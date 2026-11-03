"""Revalidate commercial and native authority before reserving a first charge."""

from __future__ import annotations

from datetime import datetime

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.customers.models import Customer
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms
from apps.provisioning.models import Service, VirtualminAccount
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User

from .metering_models import BillingCycle
from .payment_models import Payment
from .plan_change_coverage import load_plan_coverage
from .plan_change_models import PlanChange
from .subscription_currency_models import SubscriptionCurrencyTransition
from .subscription_models import Subscription


class PlanChangeConflict(ValidationError):  # noqa: N818 -- Stable API conflict alongside ValidationError.
    """The caller must reload immutable quote/revision authority (HTTP409)."""


def require_plan_change_acceptance() -> None:
    """Read current stored authority; accepted money/recovery never consults this switch."""
    if SettingsService.get_stored_setting("billing.hosting_plan_changes_enabled") is not True:
        raise ValidationError(_("New hosting plan changes are temporarily disabled."))


def _validate_native_claim(service: Service) -> None:
    account = VirtualminAccount.objects.filter(service=service).first()
    if account is None or not getattr(account, "quota_managed", False) or account.status != "active":
        raise ValidationError(_("This service has no current managed quota capability."))
    # These selectors read local, identity-bound facts. A financial transaction
    # never takes Account/Server locks or performs SSH/native I/O.
    from apps.infrastructure.node_maintenance_gate import maintenance_refusal  # noqa: PLC0415
    from apps.provisioning.hosting_limit_selectors import hosting_limits_summary  # noqa: PLC0415
    from apps.provisioning.hosting_node_policy import managed_quota_refusal  # noqa: PLC0415
    from apps.provisioning.virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415
    from apps.provisioning.virtualmin_usage_service import prime_service_usage, public_usage  # noqa: PLC0415

    if refusal := managed_quota_refusal(account.server):
        raise ValidationError(refusal)
    if refusal := maintenance_refusal(account.server_id):
        raise ValidationError(refusal)
    if (
        account.restore_hold
        or VirtualminProvisioningJob.objects.filter(account=account, status__in=["pending", "running", "attention"])
        .exclude(operation="observe_hosting_limits")
        .exists()
        or VirtualminMigration.objects.filter(account=account)
        .exclude(status__in=["completed", "failed", "rolled_back"])
        .exists()
    ):
        raise ValidationError(_("Resolve the current hosting operation before reserving a plan-change charge."))
    prime_service_usage([service])
    if hosting_limits_summary(service)["state"] != "verified" or public_usage(service)["usage_state"] != "fresh":
        raise ValidationError(_("Fresh usage and current managed quota verification are required before payment."))


def _validate_collection_boundary(subscription: Subscription) -> None:
    transitions = SubscriptionCurrencyTransition.objects.filter(subscription=subscription)
    unresolved = Q(status__in=["pending", "notified"])
    committed = Q(status="committed")
    if subscription.effective_terms_at is not None:
        committed &= Q(effective_period_start__gt=subscription.effective_terms_at) | Q(
            effective_period_start__isnull=True
        )
    if transitions.filter(unresolved | committed).exists():
        raise ValidationError(_("Resolve the currency transition before reserving a plan-change charge."))
    if subscription.changes.filter(status="pending").exists():
        raise ValidationError(_("Resolve the pending subscription change before reserving another charge."))
    cycles = BillingCycle.objects.filter(subscription=subscription)
    documents = Q(proforma_id__in=cycles.values("proforma_id")) | Q(invoice_id__in=cycles.values("invoice_id"))
    if (
        cycles.filter(collection_status="processing").exists()
        or Payment.objects.filter(documents, status="pending").exists()
    ):
        raise ValidationError(_("Resolve the in-flight renewal charge before accepting another commercial change."))


def validate_customer_actor(customer_id: int, actor_id: int) -> Customer:
    actor = User.objects.get(pk=actor_id)
    if (
        not actor.is_active
        or not CustomerMembership.objects.filter(
            user=actor, customer_id=customer_id, is_active=True, role__in=["owner", "billing"]
        ).exists()
    ):
        raise ValidationError(_("The requester no longer has billing authority for this customer."))
    customer = Customer.all_objects.get(pk=customer_id)
    if customer.deleted_at is not None or customer.anonymized_at is not None or customer.status != "active":
        raise ValidationError(_("This customer no longer permits a new plan-change charge."))
    return customer


def _validate_charge_actor(change: PlanChange) -> None:
    validate_customer_actor(change.customer_id, change.requested_by_id)


def _validate_payable_document(change: PlanChange) -> None:
    if change.proforma_id is None:
        raise ValidationError(_("The accepted plan change has no bound payable document."))
    proforma = change.proforma
    if (
        proforma is None
        or proforma.status not in {"sent", "accepted"}
        or proforma.customer_id != change.customer_id
        or proforma.currency_id != change.currency_id
        or (proforma.subtotal_cents, proforma.tax_cents, proforma.total_cents)
        != (change.net_cents, change.tax_cents, change.total_cents)
        or proforma.payments.exists()
        or proforma.gift_card_reservations.filter(status="reserved").exists()
    ):
        raise ValidationError(_("The payable plan-change document changed or already owns a payment attempt."))


def validate_payment_claim(change: PlanChange, *, at: datetime | None = None) -> None:
    """Called inside document→Customer→Subscription→Service→PlanChange locks.

    A replay of an already durable provider attempt must use its frozen payload,
    rather than reprice or reserve again through this first-claim validator.
    """
    if not transaction.get_connection(change._state.db).in_atomic_block:
        raise RuntimeError("The first payment claim requires its document-context transaction")
    require_plan_change_acceptance()
    now = timezone.now() if at is None else at
    if timezone.is_naive(now):
        raise ValueError("A payment authority instant must be timezone-aware")
    if now >= min(change.expires_at, change.authority_expires_at, change.current_period_end):
        raise ValidationError(_("This plan-change quote or its payment authority expired. Request a fresh quote."))
    if (
        change.direction != "upgrade"
        or change.status != "awaiting_payment"
        or change.confirmed_at is None
        or change.total_cents <= 0
    ):
        raise ValidationError(_("Explicitly confirm a payable upgrade before reserving its first charge."))
    _validate_charge_actor(change)
    subscription = Subscription.objects.get(pk=change.subscription_id)
    service = Service.objects.get(pk=change.service_id)
    if (
        subscription.service_id != service.pk
        or subscription.customer_id != change.customer_id
        or service.customer_id != change.customer_id
        or subscription.product_id != change.from_product_id
        or service.service_plan_id != change.from_plan_id
        or subscription.currency_id != change.currency_id
        or service.currency_id != change.currency_id
        or subscription.quantity != 1
        or subscription.billing_cycle != change.quote_snapshot.get("billing_cycle")
        or subscription.cancel_at_period_end
        or subscription.status != "active"
        or service.status != "active"
    ):
        raise ValidationError(_("The service's owner or commercial terms changed. Request a fresh quote."))
    limits = ServiceHostingLimits.objects.get(service_id=service.pk)
    if limits.revision != change.expected_limit_revision:
        raise PlanChangeConflict(_("Another resource assignment superseded this quote."))
    terms = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    if terms.plan_id != change.to_plan_id:
        raise ValidationError(_("The accepted resource terms belong to another plan."))
    if limits.disk_allowance_mib and terms.disk_allowance_mib == 0:
        raise ValidationError(
            _("Unlimited native disk capacity requires an explicit staff capacity review before payment.")
        )
    _validate_payable_document(change)
    coverage = load_plan_coverage(subscription, at=change.quoted_at)
    if coverage.evidence != change.quote_snapshot.get("coverage"):
        raise ValidationError(_("The accepted period coverage changed. Request a fresh quote."))
    if sum(part.net_cents for part in change.intervals.all()) != change.net_cents:
        raise ValidationError(_("The accepted interval amounts do not match this quote."))
    _validate_collection_boundary(subscription)
    _validate_native_claim(service)
    from .plan_change_quote_service import (  # noqa: PLC0415 -- Quote/claim import cycle.
        validate_frozen_catalog,
    )

    validate_frozen_catalog(change, subscription)
