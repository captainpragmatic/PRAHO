"""Cancellation and time-bound activation of accepted hosting plan changes."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.customers.models import Customer
from apps.provisioning.models import Service
from apps.users.models import CustomerMembership, User

from .metering_models import BillingCycle
from .plan_change_models import PlanChange
from .plan_change_payment_models import PlanChangePaymentAttempt
from .plan_change_payment_service import _locked_change, cancel_plan_change_payment
from .plan_change_validation import PlanChangeConflict
from .subscription_models import Subscription


@contextmanager
def _cancel_context(change_id: UUID | str) -> Iterator[PlanChange]:
    """An existing document owns admission; unpublished quotes own no document."""
    for _retry in range(2):
        hint = PlanChange.objects.get(pk=change_id)
        if hint.proforma_id is not None:
            with _locked_change(change_id) as (change, _document):
                yield change
                return
        with transaction.atomic():
            Customer.all_objects.select_for_update(of=("self",), no_key=True).get(pk=hint.customer_id)
            Subscription.objects.select_for_update(of=("self",), no_key=True).get(pk=hint.subscription_id)
            Service.objects.select_for_update(of=("self",), no_key=True).get(pk=hint.service_id)
            change = PlanChange.objects.select_for_update(of=("self",), no_key=True).get(pk=change_id)
            if change.proforma_id is None:
                yield change
                return
            # A confirmer published a document while we waited. Release the
            # customer/subscription locks before restarting document-first.
    raise PlanChangeConflict(_("The commercial document changed. Reload this plan change."))


def _cancel_authority(change: PlanChange, *, customer_id: int, actor_id: int, expected_fingerprint: str) -> None:
    customer = Customer.all_objects.get(pk=change.customer_id)
    subscription = Subscription.objects.get(pk=change.subscription_id)
    service = Service.objects.get(pk=change.service_id)
    if (
        change.customer_id != customer_id
        or service.customer_id != customer_id
        or subscription.customer_id != customer_id
        or subscription.service_id != service.pk
        or customer.deleted_at is not None
        or customer.anonymized_at is not None
        or not User.objects.filter(pk=actor_id, is_active=True).exists()
        or not CustomerMembership.objects.filter(
            user_id=actor_id, customer_id=customer_id, is_active=True, role__in=("owner", "billing")
        ).exists()
    ):
        raise ValidationError(_("Current billing authority for this service is required to cancel its plan change."))
    if change.request_fingerprint != expected_fingerprint:
        raise PlanChangeConflict(_("The accepted quote changed. Reload its current fingerprint."))


def _refuse_committed_downgrade(change: PlanChange) -> None:
    if (
        change.status == "scheduled"
        and BillingCycle.objects.filter(
            Q(terms_frozen_at__isnull=False) | Q(proforma_id__isnull=False) | Q(invoice_id__isnull=False),
            subscription_id=change.subscription_id,
            period_start__gte=change.effective_at,
        ).exists()
    ):
        raise ValidationError(_("This downgrade already has a committed renewal document and requires staff review."))


def cancel_plan_change(
    change_id: UUID | str,
    *,
    customer_id: int,
    actor_id: int,
    expected_fingerprint: str,
) -> PlanChange:
    if connection.in_atomic_block:
        raise RuntimeError("Plan-change cancellation may contact the gateway and requires autocommit")
    with _cancel_context(change_id) as change:
        _cancel_authority(change, customer_id=customer_id, actor_id=actor_id, expected_fingerprint=expected_fingerprint)
        if change.status in {"cancelled", "expired"}:
            return change
        if change.status not in {"quoted", "awaiting_payment", "payment_in_flight", "scheduled"}:
            raise ValidationError(_("This committed plan change requires the existing billing review process."))
        _refuse_committed_downgrade(change)
        attempt = PlanChangePaymentAttempt.objects.filter(change_id=change.pk).first()
        if attempt is None:
            change.cancel()
            change.save(update_fields=["status", "updated_at"])
            return change
        attempt_id = attempt.pk
    # Unknown or running submissions retain their original ownership. This
    # service never changes a proforma's FSM to discard late received funds.
    cancel_plan_change_payment(attempt_id)
    with _cancel_context(change_id) as change:
        _cancel_authority(change, customer_id=customer_id, actor_id=actor_id, expected_fingerprint=expected_fingerprint)
        return change


def activate_scheduled_plan_change(change_id: UUID | str, *, at: datetime | None = None) -> PlanChange:
    from .plan_change_settlement import commit_scheduled_plan_change  # noqa: PLC0415 -- Shared accepted-terms writer.

    now = timezone.now() if at is None else at
    if timezone.is_naive(now):
        raise ValueError("Scheduled activation requires a timezone-aware instant")
    with _cancel_context(change_id) as change:
        if change.status != "scheduled" or now < change.effective_at:
            return change
        try:
            with transaction.atomic():
                commit_scheduled_plan_change(change, at=now)
        except ValidationError as error:
            # No money was invented. Preserve a changed owner/lifecycle for
            # explicit review instead of mutating another owner's service.
            fresh = PlanChange.objects.get(pk=change.pk)
            fresh.review_reason = str(error)[:255]
            fresh.require_review()
            fresh.save(update_fields=["review_reason", "status", "updated_at"])
            return fresh
        return change


def activate_scheduled_plan_changes(*, limit: int = 50, at: datetime | None = None) -> dict[str, int]:
    """Resume accepted due agreements even when new quote acceptance is disabled."""
    now = timezone.now() if at is None else at
    identifiers = list(
        PlanChange.objects.filter(status="scheduled", effective_at__lte=now)
        .order_by("effective_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    expired = expire_unissued_plan_changes(limit=limit, at=now)
    results: dict[str, int] = {"expired": expired} if expired else {}
    for identifier in identifiers:
        state = activate_scheduled_plan_change(identifier, at=now).status
        results[state] = results.get(state, 0) + 1
    return results


def expire_unissued_plan_change(change_id: UUID | str, *, at: datetime | None = None) -> PlanChange:
    now = timezone.now() if at is None else at
    with _cancel_context(change_id) as change:
        if (
            change.status not in {"quoted", "awaiting_payment"}
            or now < min(change.expires_at, change.authority_expires_at)
            or PlanChangePaymentAttempt.objects.filter(change_id=change.pk).exists()
        ):
            return change
        change.expire()
        change.save(update_fields=["status", "updated_at"])
        return change


def expire_unissued_plan_changes(*, limit: int = 50, at: datetime | None = None) -> int:
    """Only absent attempts prove that this worker can expire without provider recovery."""
    now = timezone.now() if at is None else at
    identifiers = list(
        PlanChange.objects.filter(
            Q(expires_at__lte=now) | Q(authority_expires_at__lte=now),
            status__in=("quoted", "awaiting_payment"),
            payment_attempt__isnull=True,
        )
        .order_by("expires_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    return sum(expire_unissued_plan_change(identifier, at=now).status == "expired" for identifier in identifiers)
