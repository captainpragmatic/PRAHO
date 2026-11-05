"""Reconcile committed plan changes from current native proof, outside native lanes."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.provisioning.hosting_limit_selectors import hosting_limits_summary, prime_current_verification

from .plan_change_escalation import escalate_scheduled_attention
from .plan_change_financial import validate_preserved_plan_coverage
from .plan_change_lifecycle import _cancel_context
from .plan_change_models import PlanChange
from .plan_change_notices import dispatch_plan_change_notices
from .plan_change_settlement import resume_scheduled_plan_limits
from .subscription_models import Subscription

if TYPE_CHECKING:
    from apps.provisioning.models import Service


logger = logging.getLogger(__name__)


def sweep_plan_change_fulfilment(*, limit: int = 50) -> dict[str, object]:
    return {
        "operations": reconcile_plan_change_operations(limit=limit),
        "notices": dispatch_plan_change_notices(limit=limit),
    }


def reconcile_plan_change_operations(*, limit: int = 50) -> dict[str, int]:
    """Persist backoff before work so one unready or failing service cannot starve its peers."""
    now = timezone.now()
    identifiers = list(
        PlanChange.objects.filter(
            status__in={"applying_limits", "limits_attention"},
            next_reconcile_at__lte=now,
        )
        .order_by("next_reconcile_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    result: dict[str, int] = {}
    for identifier in identifiers:
        with _cancel_context(identifier) as change:
            if (
                change.status not in {"applying_limits", "limits_attention"}
                or change.next_reconcile_at is None
                or change.next_reconcile_at > now
            ):
                continue
            change.next_reconcile_at = now + timedelta(minutes=5)
            change.save(update_fields=["next_reconcile_at", "updated_at"])
        # The exact document-context claim above has committed before any
        # reconciliation exception. The next sweep can make progress elsewhere.
        try:
            status = reconcile_plan_change_operation(identifier).status
        except Exception:
            logger.exception("Plan-change operation reconciliation failed: %s", identifier)
            status = "error"
        result[status] = result.get(status, 0) + 1
    return result


def _review(change: PlanChange, reason: str) -> None:
    change.review_reason = reason[:255]
    change.require_review()
    change.save(update_fields=["review_reason", "status", "updated_at"])


def _attention(change: PlanChange, reason: str) -> None:
    if change.status == "limits_attention" and change.review_reason == reason:
        return
    change.review_reason = reason[:255]
    if change.status == "applying_limits":
        change.limits_failed()
    change.save(update_fields=["review_reason", "status", "updated_at"])


def _reconcile_native_proof(change: PlanChange, service: Service) -> None:
    """Caller holds the commercial context and already checked paid coverage."""

    from apps.provisioning.models import (  # noqa: PLC0415  # ADR-0007: runtime model.
        VirtualminAccount,
        VirtualminProvisioningJob,
    )

    application = change.limit_application
    limits = service.hosting_limits
    if (
        application is None
        or application.service_id != service.pk
        or application.revision != limits.revision
        or application.target_plan_id != change.to_plan_id
        or service.service_plan_id != change.to_plan_id
    ):
        _attention(change, _("Another resource assignment requires review of this plan's verification."))
        return
    account = VirtualminAccount.objects.filter(service_id=service.pk).select_related("server__hosting_policy").first()
    prime_current_verification([service], {service.pk: account} if account is not None else {})
    if hosting_limits_summary(service)["state"] == "verified":
        change.applied_at = limits.verified_at
        change.review_reason = ""
        change.complete()
        change.save(update_fields=["applied_at", "review_reason", "status", "updated_at"])
        return
    job = (
        VirtualminProvisioningJob.objects.filter(hosting_limit_application_id=application.pk)
        .order_by("-created_at")
        .first()
    )
    if job is not None and job.status in {"failed", "attention", "cancelled", "completed"}:
        _attention(change, _("Your agreed price is retained while the resource change needs verification."))


def reconcile_plan_change_operation(change_id: UUID | str) -> PlanChange:
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: runtime model.
    from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007: runtime model.

    with _cancel_context(change_id) as change:
        if change.status not in {"applying_limits", "limits_attention"}:
            return change
        customer = Customer.all_objects.get(pk=change.customer_id)
        subscription = Subscription.objects.get(pk=change.subscription_id)
        service = Service.objects.select_related("hosting_limits").get(pk=change.service_id)
        if (
            service.customer_id != customer.pk
            or subscription.customer_id != customer.pk
            or subscription.service_id != service.pk
            or customer.anonymized_at is not None
            or customer.deleted_at is not None
        ):
            _review(change, _("The current service owner or customer lifecycle requires review."))
            return change
        try:
            validate_preserved_plan_coverage(change)
        except ValidationError:
            _review(change, _("The accepted payment coverage requires financial review."))
            return change
        if change.limit_application_id is None:
            resume_scheduled_plan_limits(change, subscription, service)
        else:
            _reconcile_native_proof(change, service)
        escalate_scheduled_attention(change, customer, subscription, service)
        return change
