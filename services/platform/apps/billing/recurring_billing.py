"""PRAHO-owned recurring billing primitives and orchestration."""

from __future__ import annotations

import calendar
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict

from dateutil.relativedelta import relativedelta
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.billing.efactura.settings import ro_local_date
from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

from .config import FIXED_RENEWAL_COLLECTION_LEAD_DAYS, get_invoice_generation_lead_days
from .fiscal_identity import billing_country_code, get_customer_fiscal_identity

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from apps.customers.models import CustomerPaymentMethod

    from .invoice_models import Invoice
    from .metering_models import BillingCycle
    from .proforma_models import ProformaInvoice
    from .subscription_models import Subscription

_CYCLE_MONTHS: dict[str, int] = {
    "monthly": 1,
    "quarterly": 3,
    "semi_annual": 6,
    "annual": 12,
    "yearly": 12,
}
_MAX_BILLING_ANCHOR_DAY = 31


def unmanaged_auto_renew_service_count() -> int:
    """Count live services that would be skipped by PRAHO subscription billing."""
    from apps.provisioning.models import Service  # noqa: PLC0415

    return Service.objects.filter(
        auto_renew=True,
        status__in=("active", "suspended"),
        subscription__isnull=True,
    ).count()


def next_billing_period_end(
    current_period_end: datetime,
    billing_cycle: str,
    *,
    anchor_day: int | None = None,
    custom_cycle_days: int | None = None,
) -> datetime:
    """Advance a period with calendar arithmetic while preserving its original anchor."""
    if billing_cycle == "custom":
        if custom_cycle_days is None or custom_cycle_days < 1:
            raise ValueError("custom_cycle_days must be positive for a custom billing cycle")
        return current_period_end + timedelta(days=custom_cycle_days)

    months = _CYCLE_MONTHS.get(billing_cycle)
    if months is None:
        raise ValueError(f"Unsupported billing cycle: {billing_cycle}")

    resolved_anchor = anchor_day or current_period_end.day
    if not 1 <= resolved_anchor <= _MAX_BILLING_ANCHOR_DAY:
        raise ValueError("anchor_day must be between 1 and 31")

    target_month = current_period_end.replace(day=1) + relativedelta(months=months)
    last_day = calendar.monthrange(target_month.year, target_month.month)[1]
    return target_month.replace(day=min(resolved_anchor, last_day))


def fixed_renewal_schedule(period_end: datetime) -> tuple[datetime, datetime]:
    """Return the proforma-notice and automatic-charge times for a fixed renewal."""
    invoice_lead_days = get_invoice_generation_lead_days()
    return (
        period_end - timedelta(days=invoice_lead_days),
        period_end - timedelta(days=FIXED_RENEWAL_COLLECTION_LEAD_DAYS),
    )


def usage_collection_schedule(period_end: datetime) -> tuple[datetime, datetime]:
    """Return postpaid usage notice and charge times after the measured period closes."""
    return period_end, period_end + timedelta(days=7)


class RecurringCollectionGate:
    """Single fail-closed policy gate for every automatic recurring charge."""

    # "paused" here is a SYSTEM dunning state only: _pause_now()'s sole caller is
    # grace-period expiration (payment_overdue), so collecting from a paused subscription
    # and resuming it on success IS the intended dunning-recovery path. If a customer-facing
    # pause is ever wired to Subscription.pause(), it must NOT reuse this status — a
    # customer pause in the T-14..T-7 window would otherwise be charged and silently
    # resumed against their intent.
    _FIXED_RENEWAL_STATUSES = frozenset({"active", "trialing", "past_due", "paused"})
    _RENEWABLE_SERVICE_STATUSES = frozenset({"active", "suspended"})

    @staticmethod
    def _collection_enabled() -> bool:
        try:
            return SettingsService.get_boolean_setting(
                "billing.recurring_auto_collection_enabled",
                False,
            )
        except Exception:
            return False

    @staticmethod
    def _validate_mandate(subscription: Any, customer_id: object, payment_method: Any) -> str | None:
        if not subscription.auto_payment_enabled:
            return f"Subscription {subscription.subscription_number} is not enrolled in automatic payment"
        if subscription.saved_payment_method_id != payment_method.id:
            return f"Subscription {subscription.subscription_number} does not use the selected saved payment method"

        authorization = subscription.payment_authorization
        if authorization is None or not authorization.is_active:
            return f"Subscription {subscription.subscription_number} has no active recurring-payment authorization"
        if authorization.customer_id != customer_id:
            return "Recurring-payment authorization customer does not match the document customer"
        if authorization.payment_method_id != payment_method.id:
            return "Recurring-payment authorization does not cover the selected saved payment method"
        return None

    @staticmethod
    def _validate_fixed_renewal_lifecycle(subscription: Any) -> str | None:
        if subscription.status not in RecurringCollectionGate._FIXED_RENEWAL_STATUSES:
            return (
                f"Subscription {subscription.subscription_number} status "
                f"{subscription.status} does not allow renewal collection"
            )
        if subscription.cancel_at_period_end:
            return f"Subscription {subscription.subscription_number} is scheduled for cancellation"
        service = subscription.service
        if service is None:
            return f"Subscription {subscription.subscription_number} has no linked service"
        if service.status not in RecurringCollectionGate._RENEWABLE_SERVICE_STATUSES:
            return (
                f"Subscription {subscription.subscription_number} linked service status "
                f"{service.status} does not allow renewal collection"
            )
        if not service.auto_renew:
            return f"Subscription {subscription.subscription_number} has automatic renewal disabled"
        return None

    @staticmethod
    def authorize_invoice(  # noqa: PLR0911  # Preserve distinct fail-closed rejection reasons
        invoice: Invoice,
        payment_method: CustomerPaymentMethod,
    ) -> Result[list[BillingCycle], str]:
        if not RecurringCollectionGate._collection_enabled():
            return Err("Recurring automatic collection is disabled")

        from .metering_models import BillingCycle  # noqa: PLC0415

        cycles = list(
            BillingCycle.objects.filter(Q(invoice=invoice) | Q(usage_invoice=invoice))
            .select_related(
                "subscription__service",
                "subscription__saved_payment_method",
                "subscription__payment_authorization__payment_method",
            )
            .defer(
                "subscription__saved_payment_method__bank_details",
                "subscription__payment_authorization__payment_method__bank_details",
            )
        )
        if not cycles:
            return Err("Recurring invoice has no billing cycles to authorize")

        for cycle in cycles:
            subscription = cycle.subscription
            if subscription.customer_id != invoice.customer_id:
                return Err("Billing cycle customer does not match the invoice customer")
            is_usage_invoice = cycle.usage_invoice_id == invoice.id
            if is_usage_invoice and cycle.status != "invoiced":
                return Err(f"Usage billing cycle {cycle.id} is not invoiced (status: {cycle.status})")
            if not is_usage_invoice and cycle.status != "upcoming":
                return Err(f"Renewal billing cycle {cycle.id} is not upcoming (status: {cycle.status})")
            if not is_usage_invoice and cycle.collection_status not in {"scheduled", "past_due"}:
                return Err(
                    f"Billing cycle {cycle.id} is not scheduled for collection (status: {cycle.collection_status})"
                )
            if is_usage_invoice:
                # Usage bills CONSUMED service, so a cancelled subscription's final usage
                # cycle remains legitimately collectible — but that is the ONLY divergence
                # from the renewal lifecycle. Anything else (expired, incomplete, unpaid
                # teardown states) must not produce an off-session charge: skipping the
                # lifecycle check entirely left long-terminated services chargeable forever.
                if subscription.status not in (RecurringCollectionGate._FIXED_RENEWAL_STATUSES | {"cancelled"}):
                    return Err(
                        f"Subscription {subscription.id} status '{subscription.status}' does not "
                        f"permit automatic usage collection"
                    )
            else:
                lifecycle_error = RecurringCollectionGate._validate_fixed_renewal_lifecycle(subscription)
                if lifecycle_error:
                    return Err(lifecycle_error)
            mandate_error = RecurringCollectionGate._validate_mandate(subscription, invoice.customer_id, payment_method)
            if mandate_error:
                return Err(mandate_error)

        return Ok(cycles)

    @staticmethod
    def authorize_proforma(  # noqa: PLR0911  # Preserve distinct fail-closed rejection reasons
        proforma: ProformaInvoice,
        payment_method: CustomerPaymentMethod,
    ) -> Result[list[BillingCycle], str]:
        """Authorize a grouped recurring proforma before creating a gateway charge."""
        if not RecurringCollectionGate._collection_enabled():
            return Err("Recurring automatic collection is disabled")

        from .metering_models import BillingCycle  # noqa: PLC0415

        cycles = list(
            BillingCycle.objects.filter(proforma=proforma)
            .select_related(
                "subscription__service",
                "subscription__saved_payment_method",
                "subscription__payment_authorization__payment_method",
            )
            .defer(
                "subscription__saved_payment_method__bank_details",
                "subscription__payment_authorization__payment_method__bank_details",
            )
        )
        if not cycles:
            return Err("Recurring proforma has no billing cycles to authorize")

        proforma_customer_id = getattr(proforma, "customer_id", None)
        for cycle in cycles:
            subscription = cycle.subscription
            if subscription.customer_id != proforma_customer_id:
                return Err("Billing cycle customer does not match the proforma customer")
            if cycle.status != "upcoming":
                return Err(f"Renewal billing cycle {cycle.id} is not upcoming (status: {cycle.status})")
            if cycle.collection_status not in {"prepared", "past_due"}:
                return Err(
                    f"Billing cycle {cycle.id} is not prepared for collection (status: {cycle.collection_status})"
                )
            lifecycle_error = RecurringCollectionGate._validate_fixed_renewal_lifecycle(subscription)
            if lifecycle_error:
                return Err(lifecycle_error)
            mandate_error = RecurringCollectionGate._validate_mandate(
                subscription, proforma_customer_id, payment_method
            )
            if mandate_error:
                return Err(mandate_error)

        return Ok(cycles)


class RecurringPreparationResult(TypedDict):
    subscriptions_checked: int
    unmanaged_services: int
    cycles_prepared: int
    proformas_created: int
    errors: list[str]


class RecurringCollectionResult(TypedDict):
    proformas_checked: int
    payments_created: int
    payments_failed: int
    errors: list[str]


def _resolve_due_unprepared_cycle(
    subscription: Subscription,
    *,
    run_at: datetime,
    invoice_lead_days: int,
    errors: list[str],
) -> tuple[BillingCycle, datetime] | None:
    """Reconcile one fixed-renewal schedule and return its due unprepared cycle."""
    from .metering_models import BillingCycle  # noqa: PLC0415

    expected_proforma_at = subscription.current_period_end - timedelta(days=invoice_lead_days)
    period_start = subscription.current_period_end
    period_end = next_billing_period_end(
        period_start,
        subscription.billing_cycle,
        anchor_day=subscription.billing_anchor_day,
        custom_cycle_days=subscription.custom_cycle_days,
    )
    cycle = (
        BillingCycle.objects.select_for_update(of=("self",))
        .filter(subscription=subscription, period_start=period_start)
        .first()
    )
    if cycle and cycle.period_end != period_end:
        errors.append(f"Cycle {cycle.id} period does not match subscription {subscription.subscription_number}")
        return None
    if cycle and (cycle.proforma_id or cycle.invoice_id or cycle.collection_status != "unbilled"):
        return None

    if subscription.next_proforma_at != expected_proforma_at:
        subscription.next_proforma_at = expected_proforma_at
        subscription.next_billing_date = expected_proforma_at
        subscription.save(update_fields=["next_proforma_at", "next_billing_date", "updated_at"])
    if expected_proforma_at > run_at:
        return None

    if cycle is None:
        cycle, _created = BillingCycle.objects.get_or_create(
            subscription=subscription,
            period_start=period_start,
            defaults={
                "period_end": period_end,
                "status": "upcoming",
                "collection_status": "unbilled",
                "base_charge_cents": subscription.total_price_cents,
                "charge_scheduled_at": subscription.next_charge_at,
            },
        )
    if cycle.period_end != period_end:
        errors.append(f"Cycle {cycle.id} period does not match subscription {subscription.subscription_number}")
        return None
    if cycle.proforma_id or cycle.invoice_id or cycle.collection_status != "unbilled":
        return None
    return cycle, period_end


class RecurringBillingOrchestrator:
    """PRAHO-owned preparation and collection of recurring service charges."""

    @staticmethod
    def prepare_due_proformas(  # noqa: PLR0915  # One transaction creates the document and all cycle-linked lines
        as_of: datetime | None = None,
    ) -> RecurringPreparationResult:
        """Create one proforma per compatible customer collection group.

        Services that share a customer, currency, collection authorization, saved
        method, and charge time are consolidated. Each independently cancellable
        service still owns its own Subscription and BillingCycle.
        """
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        from .proforma_models import ProformaInvoice, ProformaLine, ProformaSequence  # noqa: PLC0415
        from .proforma_service import _derive_tax_category  # noqa: PLC0415
        from .services import _build_customer_vat_info  # noqa: PLC0415
        from .subscription_models import Subscription  # noqa: PLC0415

        run_at = as_of or timezone.now()
        result = RecurringPreparationResult(
            subscriptions_checked=0,
            unmanaged_services=unmanaged_auto_renew_service_count(),
            cycles_prepared=0,
            proformas_created=0,
            errors=[],
        )
        if result["unmanaged_services"]:
            result["errors"].append(
                f"{result['unmanaged_services']} active auto-renew services have no PRAHO subscription; "
                "link or migrate them before retiring the legacy renewal engine"
            )

        try:
            invoice_lead_days = get_invoice_generation_lead_days()
            preparation_cutoff = run_at + timedelta(days=invoice_lead_days)
            with transaction.atomic():
                candidate_subscriptions = list(
                    Subscription.objects.select_for_update(of=("self",))
                    .select_related(
                        "customer",
                        "currency",
                        "product",
                        "service",
                        "saved_payment_method",
                        "payment_authorization",
                        "payment_authorization__payment_method",
                    )
                    .defer(
                        "saved_payment_method__bank_details",
                        "payment_authorization__payment_method__bank_details",
                    )
                    .filter(
                        status__in=["active", "trialing"],
                        cancel_at_period_end=False,
                        next_proforma_at__isnull=False,
                        service__isnull=False,
                        service__auto_renew=True,
                        service__status__in=["active", "suspended"],
                    )
                    .filter(Q(next_proforma_at__lte=run_at) | Q(current_period_end__lte=preparation_cutoff))
                    .order_by("customer_id", "currency_id", "next_charge_at", "id")
                )
                result["subscriptions_checked"] = len(candidate_subscriptions)

                groups: dict[tuple[object, ...], list[tuple[Subscription, BillingCycle, datetime]]] = {}
                for subscription in candidate_subscriptions:
                    due_cycle = _resolve_due_unprepared_cycle(
                        subscription,
                        run_at=run_at,
                        invoice_lead_days=invoice_lead_days,
                        errors=result["errors"],
                    )
                    if due_cycle is None:
                        continue
                    cycle, period_end = due_cycle

                    collection_key = (
                        subscription.customer_id,
                        subscription.currency_id,
                        subscription.auto_payment_enabled,
                        subscription.saved_payment_method_id if subscription.auto_payment_enabled else None,
                        subscription.payment_authorization_id if subscription.auto_payment_enabled else None,
                        subscription.next_charge_at,
                    )
                    groups.setdefault(collection_key, []).append((subscription, cycle, period_end))

                for grouped_items in groups.values():
                    group_cycles_prepared = 0
                    try:
                        with transaction.atomic():
                            first_subscription = grouped_items[0][0]
                            customer = first_subscription.customer
                            billing_address = customer.get_billing_address()
                            bill_to_country = billing_country_code(getattr(billing_address, "country", ""))
                            vat_result = TaxService.calculate_vat_for_document(
                                subtotal_cents=sum(item[0].total_price_cents for item in grouped_items),
                                customer_info=_build_customer_vat_info(customer, country=bill_to_country),
                            )
                            vat_rate = (vat_result.vat_rate / Decimal("100")).quantize(Decimal("0.0001"))
                            tax_category = _derive_tax_category(vat_result)

                            sequence, _ = ProformaSequence.objects.get_or_create(scope="default")
                            sequence = ProformaSequence.objects.select_for_update(of=("self",)).get(pk=sequence.pk)
                            try:
                                tax_profile = customer.tax_profile
                            except Exception:
                                tax_profile = None
                            fiscal_identity = get_customer_fiscal_identity(customer)

                            valid_until = max(
                                run_at + timedelta(days=30),
                                max(item[1].period_start for item in grouped_items) + timedelta(days=1),
                            )
                            proforma = ProformaInvoice.objects.create(
                                customer=customer,
                                number=sequence.get_next_number("PRO"),
                                currency=first_subscription.currency,
                                valid_until=valid_until,
                                bill_to_name=customer.company_name or customer.name or "",
                                bill_to_email=customer.primary_email or "",
                                bill_to_tax_id=fiscal_identity.business_tax_id,
                                bill_to_cnp=fiscal_identity.cnp,
                                bill_to_registration_number=getattr(tax_profile, "registration_number", "") or "",
                                bill_to_address1=getattr(billing_address, "address_line1", "") or "",
                                bill_to_address2=getattr(billing_address, "address_line2", "") or "",
                                bill_to_city=getattr(billing_address, "city", "") or "",
                                bill_to_region=getattr(billing_address, "county", "") or "",
                                bill_to_postal=getattr(billing_address, "postal_code", "") or "",
                                bill_to_country=bill_to_country,
                                meta={
                                    "type": "recurring",
                                    "source": "recurring_billing",
                                    "collection_mode": "automatic"
                                    if first_subscription.auto_payment_enabled
                                    else "manual",
                                    "cycle_ids": [str(item[1].id) for item in grouped_items],
                                },
                            )

                            for sort_order, (subscription, cycle, _period_end) in enumerate(grouped_items, start=1):
                                line = ProformaLine(
                                    proforma=proforma,
                                    kind="service",
                                    service=subscription.service,
                                    billing_cycle=cycle,
                                    description=(
                                        f"{subscription.product.name} - {subscription.billing_cycle.replace('_', ' ').title()} "
                                        f"({ro_local_date(cycle.period_start)} to {ro_local_date(cycle.period_end)})"
                                    ),
                                    quantity=Decimal(subscription.quantity),
                                    unit_price_cents=subscription.effective_price_cents,
                                    tax_rate=vat_rate,
                                    domain_name=getattr(subscription.service, "domain", "") or "",
                                    # Romanian calendar days: these are DateFields emitted verbatim into
                                    # the e-Factura InvoicePeriod (#220/#286); raw .date() is the UTC day.
                                    period_start=ro_local_date(cycle.period_start),
                                    period_end=ro_local_date(cycle.period_end),
                                    unit_code="C62",
                                    tax_category_code=tax_category,
                                    seller_item_id=subscription.product.slug,
                                    sort_order=sort_order,
                                )
                                line.calculate_totals()
                                line.save()
                                cycle.proforma = proforma
                                cycle.collection_status = "prepared"
                                cycle.tax_cents = line.tax_cents
                                cycle.total_cents = line.line_total_cents
                                cycle.save(
                                    update_fields=[
                                        "proforma",
                                        "collection_status",
                                        "tax_cents",
                                        "total_cents",
                                        "updated_at",
                                    ]
                                )
                                group_cycles_prepared += 1

                            proforma.recalculate_totals()
                            proforma.send_proforma()
                            proforma.save(update_fields=["subtotal_cents", "tax_cents", "total_cents", "status"])
                    except Exception as exc:
                        result["errors"].append(str(exc))
                        logger.exception(
                            "Recurring proforma preparation failed for customer %s",
                            grouped_items[0][0].customer_id,
                        )
                    else:
                        result["cycles_prepared"] += group_cycles_prepared
                        result["proformas_created"] += 1
        except Exception as exc:
            result["errors"].append(str(exc))
            logger.exception("Recurring proforma preparation failed")

        return result

    @staticmethod
    def collect_due_proformas(as_of: datetime | None = None) -> RecurringCollectionResult:
        """Create one off-session PaymentIntent for every due automatic proforma."""
        from .metering_models import BillingCycle  # noqa: PLC0415
        from .payment_models import Payment  # noqa: PLC0415
        from .payment_service import PaymentService  # noqa: PLC0415
        from .proforma_models import ProformaInvoice  # noqa: PLC0415

        run_at = as_of or timezone.now()
        result = RecurringCollectionResult(
            proformas_checked=0,
            payments_created=0,
            payments_failed=0,
            errors=[],
        )
        proforma_ids = list(
            BillingCycle.objects.filter(
                collection_status="prepared",
                charge_scheduled_at__isnull=False,
                charge_scheduled_at__lte=run_at,
                proforma__status__in=["sent", "accepted"],
                subscription__auto_payment_enabled=True,
            )
            .order_by()
            .values_list("proforma_id", flat=True)
            .distinct()
        )
        result["proformas_checked"] = len(proforma_ids)

        for proforma_id in proforma_ids:
            try:
                with transaction.atomic():
                    proforma = ProformaInvoice.objects.select_for_update(of=("self",)).get(id=proforma_id)
                    cycles = list(
                        BillingCycle.objects.select_for_update(of=("self",))
                        .select_related("subscription__saved_payment_method")
                        .defer("subscription__saved_payment_method__bank_details")
                        .filter(proforma=proforma)
                        .order_by("subscription_id", "id")
                    )
                    existing = (
                        Payment.objects.filter(
                            proforma=proforma,
                            payment_method="stripe",
                            status__in=["pending", "succeeded"],
                        )
                        .order_by("-created_at")
                        .first()
                    )
                    if existing is not None and (existing.gateway_txn_id or existing.status == "succeeded"):
                        continue
                    if not cycles:
                        result["errors"].append(f"Proforma {proforma.number} has no recurring cycles")
                        continue

                    saved_method = cycles[0].subscription.saved_payment_method
                    if saved_method is None or not saved_method.stripe_payment_method_id:
                        result["errors"].append(f"Proforma {proforma.number} has no saved Stripe payment method")
                        continue

                    payment_method_id = saved_method.stripe_payment_method_id
                    proforma_number = proforma.number

                # Network I/O must never hold document or cycle row locks. PaymentService
                # owns attempt idempotency and revalidates the mandate immediately before
                # asking the gateway to collect the proforma.
                intent = PaymentService.create_payment_intent_for_proforma(
                    proforma_id=proforma_id,
                    payment_method_id=payment_method_id,
                )
                if not intent.get("success", False):
                    result["payments_failed"] += 1
                    result["errors"].append(
                        f"Proforma {proforma_number}: {intent.get('error') or 'payment creation failed'}"
                    )
                    continue

                with transaction.atomic():
                    cycles = list(
                        BillingCycle.objects.select_for_update(of=("self",))
                        .filter(
                            proforma_id=proforma_id,
                            # NOT past_due: an early failure webhook may have already converged
                            # this attempt — overwriting its verdict back to "processing" hides
                            # the definitive failure from mark_overdue_renewals and corrupts
                            # the attempt state. The webhook's word is final.
                            collection_status__in=["prepared", "processing"],
                        )
                        .order_by("subscription_id", "id")
                    )
                    for cycle in cycles:
                        if cycle.collection_status == "processing":
                            continue
                        cycle.collection_status = "processing"
                        cycle.collection_started_at = cycle.collection_started_at or run_at
                        cycle.collection_attempt_count += 1
                        cycle.save(
                            update_fields=[
                                "collection_status",
                                "collection_started_at",
                                "collection_attempt_count",
                                "updated_at",
                            ]
                        )
                result["payments_created"] += 1
            except Exception as exc:
                logger.exception("Recurring collection failed for proforma %s", proforma_id)
                result["errors"].append(f"Proforma {proforma_id}: {exc}")

        return result

    @staticmethod
    def mark_overdue_renewals(as_of: datetime | None = None) -> int:
        """Start grace when a prepared fixed renewal reaches its paid-through boundary.

        Automatic attempts run before this step. A pending or successful payment is
        deliberately excluded so an uncertain gateway outcome cannot race dunning.
        Manual renewals and fail-closed automatic renewals then share the same grace
        and service-suspension lifecycle without fabricating a failed payment attempt.
        """
        from .metering_models import BillingCycle  # noqa: PLC0415
        from .subscription_models import Subscription  # noqa: PLC0415

        run_at = as_of or timezone.now()
        overdue_cycle_ids = list(
            BillingCycle.objects.filter(
                collection_status__in=["prepared", "past_due"],
                period_start__lte=run_at,
                proforma__status__in=["sent", "accepted"],
                subscription__status="active",
            )
            .exclude(proforma__payments__status__in=["pending", "succeeded"])
            .order_by()
            .values_list("id", flat=True)
            .distinct()
        )
        if not overdue_cycle_ids:
            return 0

        marked = 0
        with transaction.atomic():
            cycles = list(
                BillingCycle.objects.select_for_update(of=("self",))
                .filter(
                    id__in=overdue_cycle_ids,
                    collection_status__in=["prepared", "past_due"],
                    subscription__status="active",
                )
                .order_by("subscription_id", "id")
            )
            subscriptions = {
                subscription.id: subscription
                for subscription in Subscription.objects.select_for_update(of=("self",))
                .filter(id__in={cycle.subscription_id for cycle in cycles}, status="active")
                .order_by("id")
            }
            for cycle in cycles:
                subscription = subscriptions.get(cycle.subscription_id)
                if subscription is None:
                    continue
                # Recheck payment state under the document relationship immediately
                # before changing lifecycle state.
                if cycle.proforma_id:
                    proforma = cycle.proforma
                    if proforma is None or proforma.payments.filter(status__in=["pending", "succeeded"]).exists():
                        continue
                if subscription.status == "active":
                    subscription._go_past_due()
                    subscription.grace_period_ends_at = run_at + timedelta(days=subscription.grace_period_days)
                    subscription.save(update_fields=["status", "grace_period_ends_at", "updated_at"])
                elif subscription.status != "past_due":
                    continue
                cycle.collection_status = "past_due"
                cycle.save(update_fields=["collection_status", "updated_at"])
                marked += 1

        return marked
