"""Explicit staff resource exceptions; recurring and frozen financial terms stay unchanged."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import router, transaction
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from .hosting_limit_assignments import request_service_plan_change
from .hosting_limit_models import HostingLimitApplication
from .service_models import Service, ServicePlan

if TYPE_CHECKING:
    from apps.billing.subscription_models import Subscription
    from apps.users.models import User


def can_override_hosting_resources(user: User) -> bool:
    return user.is_active and (user.is_superuser or user.staff_role in {"admin", "manager"})


def _financial_refusal(subscription: Subscription | None, *, using: str) -> str | None:
    from apps.billing.subscription_currency_models import SubscriptionCurrencyTransition  # noqa: PLC0415

    if subscription is None:
        return None
    if subscription.changes.using(using).filter(status="pending").exists():
        return str(_("Resolve the pending subscription change before granting a resource exception."))
    pending_currency = Q(status__in=["pending", "notified"])
    committed = Q(status="committed")
    if subscription.effective_terms_at is not None:
        committed &= Q(effective_period_start__gt=subscription.effective_terms_at) | Q(
            effective_period_start__isnull=True
        )
    if (
        SubscriptionCurrencyTransition.objects.using(using)
        .filter(pending_currency | committed, subscription=subscription)
        .exists()
    ):
        return str(_("Resolve the currency transition before granting a resource exception."))
    return None


def _validate_target_profile(service: Service, target_plan_id: int, using: str) -> None:
    plans = {
        plan.pk: plan
        for plan in ServicePlan.objects.using(using)
        .filter(
            pk__in=[target_plan_id, service.service_plan_id],
        )
        .order_by("pk")
        .select_for_update(of=("self",), no_key=True)
    }
    if target_plan_id not in plans:
        raise ValidationError(_("Select an existing resource plan."))
    plan, current_plan = plans[target_plan_id], plans[service.service_plan_id]
    profile = ("plan_type", "features", "email_accounts", "databases", "domains", "cpu_cores", "ram_gb")
    if any(getattr(plan, field) != getattr(current_plan, field) for field in profile):
        raise ValidationError(_("A resource-only exception cannot change the hosting template or other features."))


def grant_resource_override(  # noqa: PLR0913 -- Explicit human authority, revision and replay identity.
    *,
    user: User,
    service: Service,
    target_plan_id: int,
    ticket_id: int,
    reason: str,
    expected_revision: int,
    submission_id: UUID,
    billing_unchanged: bool,
    adopt_existing_native_limits: bool = False,
) -> HostingLimitApplication:
    """Customer→Subscription→Service; no native Account/Server locks or native I/O.

    This named exception grants resources only. It never rewrites Subscription
    prices, frozen BillingCycle tariffs, issued documents or Service.price.
    """
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.tickets.models import Ticket  # noqa: PLC0415
    from apps.users.models import User  # noqa: PLC0415

    using = router.db_for_write(Service, instance=service)
    if billing_unchanged is not True:
        raise ValidationError(_("Acknowledge that billing and frozen tariffs stay unchanged."))
    if type(adopt_existing_native_limits) is not bool:
        raise ValidationError(_("Explicitly choose whether to adopt native enforcement for this account."))
    if not reason.strip():
        raise ValidationError(_("Give a reason for this resource-only exception."))
    expected_customer = service.customer_id
    with transaction.atomic(using=using):
        actor = User.objects.using(using).get(pk=user.pk)
        if not can_override_hosting_resources(actor):
            raise PermissionDenied(_("Administrator or manager authority is required for a resource-only exception."))
        customer = Customer.objects.using(using).select_for_update(of=("self",)).get(pk=expected_customer)
        subscription = (
            Subscription.objects.using(using)
            .select_for_update(of=("self",), no_key=True)
            .filter(service=service)
            .first()
        )
        locked = Service.objects.using(using).select_for_update(of=("self",), no_key=True).get(pk=service.pk)
        if locked.customer_id != expected_customer or not actor.can_access_customer(customer):
            raise ValidationError(_("The service's owner changed. Reload and authorize the current owner."))
        if customer.anonymized_at is not None or customer.status != "active":
            raise ValidationError(_("Resource exceptions require an active customer."))
        ticket = Ticket.objects.using(using).select_for_update(of=("self",), no_key=True).filter(pk=ticket_id).first()
        if ticket is None or ticket.customer_id != customer.pk:
            raise ValidationError(_("Select a support ticket belonging to this service's customer."))
        if subscription is not None and subscription.customer_id != customer.pk:
            raise ValidationError(_("The subscription owner does not match this service."))
        if refusal := _financial_refusal(subscription, using=using):
            raise ValidationError(refusal)
        previous = (
            HostingLimitApplication.objects.using(using).filter(service=locked, submission_id=submission_id).first()
        )
        if previous is None:
            _validate_target_profile(locked, target_plan_id, using)
        authority = {
            "kind": "staff_resource_override",
            "staff_user_id": str(actor.pk),
            "ticket_id": str(ticket.pk),
            "billing_unchanged": "acknowledged",
        }
        if adopt_existing_native_limits:
            authority["adopt_existing_native_limits"] = "acknowledged"
        return request_service_plan_change(
            service=locked,
            target_plan_id=target_plan_id,
            expected_revision=expected_revision,
            submission_id=submission_id,
            reason=reason,
            authority=authority,
        )
