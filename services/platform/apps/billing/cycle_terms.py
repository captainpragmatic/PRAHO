"""Freeze the currency, quantities and metering contract of a billing period."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from .currency_models import Currency
from .metering_models import BillingCycle, UsageAggregation, UsageMeter
from .subscription_models import Subscription

SNAPSHOT_VERSION = 1
FROZEN_FIELDS = (
    "currency",
    "quantity",
    "unit_price_cents",
    "pricing_snapshot",
    "terms_frozen_at",
    "terms_hold_reason",
)


@dataclass(frozen=True)
class CycleTerms:
    currency: Currency
    quantity: int
    unit_price_cents: int
    snapshot: dict[str, Any]

    @property
    def subtotal_cents(self) -> int:
        return self.quantity * self.unit_price_cents


def _meter_snapshot(subscription: Subscription, meter: UsageMeter, currency_code: str, at: datetime) -> dict[str, Any]:
    from .metering_service import (  # noqa: PLC0415  # Rating engine and snapshot builder share validation.
        RatingEngine,
        _get_allowance_from_service_plan,
        _get_allowance_from_subscription_item,
        _get_subscription_item_for_meter,
    )

    item = _get_subscription_item_for_meter(subscription, meter)
    included = _get_allowance_from_subscription_item(item)
    if included <= 0:
        included = _get_allowance_from_service_plan(meter, getattr(subscription.product, "default_service_plan", None))
    snapshot: dict[str, Any] = {
        "meter_id": str(meter.pk),
        "name": meter.name,
        "currency": currency_code,
        "is_billable": meter.is_billable,
        "rounding_mode": meter.rounding_mode,
        "rounding_increment": str(meter.rounding_increment),
        "included_allowance": str(included),
        "subscription_item_id": str(item.pk) if item else None,
    }
    tiers = list(
        meter.pricing_tiers.filter(
            Q(valid_from__isnull=True) | Q(valid_from__lte=at),
            Q(valid_until__isnull=True) | Q(valid_until__gt=at),
            currency_id=currency_code,
            is_default=True,
            is_active=True,
        ).order_by("id")[:2]
    )
    engine = RatingEngine()
    if len(tiers) > 1:
        snapshot["hold_reason"] = f"Ambiguous active {currency_code} pricing for meter {meter.name}"
    elif tiers:
        error = engine._validate_pricing_configuration(tiers[0])  # Shared rating validation.
        if error:
            snapshot["hold_reason"] = f"Invalid pricing for meter {meter.name}: {error}"
        else:
            snapshot.update(engine._pricing_snapshot(tiers[0]))  # Shared tariff serialization.
    elif item and item.currency_id == currency_code and not item.currency_hold_reason:
        snapshot.update(source="subscription_item", unit_price_cents=item.effective_price_cents)
    elif meter.is_billable:
        snapshot["hold_reason"] = f"No active {currency_code} pricing configured for meter {meter.name}"
    return snapshot


def build_terms_snapshot(
    subscription: Subscription,
    *,
    effective_at: datetime,
    currency_code: str | None = None,
    unit_price_cents: int | None = None,
) -> dict[str, Any]:
    """Read current configured terms only when making a new period or offer."""
    currency_code = currency_code or subscription.currency_id
    if unit_price_cents is None:
        protected = subscription.locked_price_cents is not None and (
            subscription.locked_price_expires_at is None or effective_at < subscription.locked_price_expires_at
        )
        unit_price_cents = subscription.locked_price_cents if protected else subscription.unit_price_cents
    return {
        "version": SNAPSHOT_VERSION,
        "currency": currency_code,
        "quantity": subscription.quantity,
        "unit_price_cents": unit_price_cents,
        "billing_cycle": subscription.billing_cycle,
        "custom_cycle_days": subscription.custom_cycle_days,
        "meters": {
            str(meter.pk): _meter_snapshot(subscription, meter, currency_code, effective_at)
            for meter in UsageMeter.objects.filter(is_active=True).order_by("id")
        },
    }


def transition_price_blockers(subscription: Subscription, target_currency_code: str) -> list[str]:
    """Check the meter tariffs this subscription actually uses, using the freezing validator."""
    from .cycle_provenance import inspect_cycle_provenance  # noqa: PLC0415

    used_meters = {
        str(value)
        for value in UsageAggregation.objects.filter(
            subscription=subscription,
        )
        .values_list("meter_id", flat=True)
        .distinct()
    }
    snapshot = build_terms_snapshot(
        subscription,
        effective_at=subscription.current_period_end,
        currency_code=target_currency_code,
    )
    blockers = [
        str(meter["hold_reason"])
        for meter_id, meter in snapshot["meters"].items()
        if meter.get("hold_reason") and (meter_id in used_meters or meter.get("subscription_item_id"))
    ]
    for cycle in subscription.billing_cycles.filter(
        terms_frozen_at__isnull=True,
        status__in=["upcoming", "active", "closing", "closed"],
    ):
        if cycle.status == "upcoming" and not (cycle.proforma_id or cycle.invoice_id):
            continue
        evidence = inspect_cycle_provenance(cycle)
        if not evidence.currency_code:
            blockers.append(f"Historical cycle {cycle.pk}: {evidence.hold_reason}")
        elif (
            cycle.status in {"upcoming", "active"}
            or UsageAggregation.objects.filter(
                billing_cycle=cycle,
                status__in=["accumulating", "pending_rating"],
            ).exists()
        ):
            blockers.append(f"Historical cycle {cycle.pk} needs its original usage tariff snapshot reviewed")
    return blockers


def freeze_cycle_terms(cycle: BillingCycle, snapshot: dict[str, Any] | None = None) -> CycleTerms:
    """Capture a new contract. Callers save inside the transaction preparing the cycle."""
    if cycle.terms_frozen_at:
        return get_cycle_terms(cycle)
    if cycle.terms_hold_reason:
        raise ValidationError(_("Billing cycle terms require review: %(reason)s") % {"reason": cycle.terms_hold_reason})
    snapshot = deepcopy(snapshot or build_terms_snapshot(cycle.subscription, effective_at=cycle.period_start))
    cycle.currency_id = snapshot["currency"]
    cycle.quantity = snapshot["quantity"]
    cycle.unit_price_cents = snapshot["unit_price_cents"]
    cycle.pricing_snapshot = snapshot
    cycle.terms_frozen_at = timezone.now()
    return get_cycle_terms(cycle)


def get_cycle_terms(cycle: BillingCycle) -> CycleTerms:
    """Read proven frozen terms; historical billing must never fall back to live prices."""
    snapshot = cycle.pricing_snapshot
    if (
        cycle.terms_hold_reason
        or not cycle.terms_frozen_at
        or not cycle.currency_id
        or cycle.quantity is None
        or cycle.quantity < 1
        or cycle.unit_price_cents is None
        or cycle.unit_price_cents < 0
        or not isinstance(snapshot, dict)
        or snapshot.get("version") != SNAPSHOT_VERSION
        or snapshot.get("currency") != cycle.currency_id
        or snapshot.get("quantity") != cycle.quantity
        or snapshot.get("unit_price_cents") != cycle.unit_price_cents
    ):
        raise ValidationError(
            _("Billing cycle %(cycle)s has unproven pricing terms; review is required") % {"cycle": cycle.pk}
        )
    currency = get_cycle_currency(cycle)
    return CycleTerms(currency, cycle.quantity, cycle.unit_price_cents, snapshot)


def get_cycle_currency(cycle: BillingCycle) -> Currency:
    """Already rated historical usage only needs proven currency, not unknown base prices."""
    from .cycle_provenance import inspect_cycle_provenance  # noqa: PLC0415

    currency = cycle.currency
    if currency is None:
        evidence = inspect_cycle_provenance(cycle)
        if evidence.currency_code is None:
            raise ValidationError(
                _("Billing cycle %(cycle)s: %(reason)s") % {"cycle": cycle.pk, "reason": evidence.hold_reason}
            )
        currency = Currency.objects.filter(code=evidence.currency_code).first()
        if currency is None:
            raise ValidationError(
                _("Original currency %(currency)s is unavailable; review is required")
                % {"currency": evidence.currency_code}
            )
    for document in (cycle.proforma, cycle.invoice, cycle.usage_invoice):
        if document and document.currency_id != currency.code:
            raise ValidationError(_("Billing cycle currency conflicts with its original document"))
    return currency


def get_usage_cycle_currency(cycle: BillingCycle) -> Currency:
    """Use original evidence; retain unreviewed legacy behavior only before a policy change."""
    from .currency_policy import get_selling_currency_policy  # noqa: PLC0415
    from .cycle_provenance import inspect_cycle_provenance  # noqa: PLC0415

    if cycle.currency_id:
        return get_cycle_currency(cycle)
    evidence = inspect_cycle_provenance(cycle)
    if evidence.currency_code:
        return get_cycle_currency(cycle)
    if evidence.hold_reason != "No immutable source identifies the original currency":
        raise ValidationError(evidence.hold_reason)
    if get_selling_currency_policy().revision > 1:
        raise ValidationError(_("Unreviewed historical usage cannot be billed after a currency policy change"))
    return cycle.subscription.currency


def frozen_pricing_tier(snapshot: dict[str, Any]) -> SimpleNamespace:
    """Adapt a saved tariff to the existing rating arithmetic without fetching live rows."""
    return SimpleNamespace(
        id=snapshot["pricing_tier_id"],
        name=snapshot["pricing_tier_name"],
        pricing_model=snapshot["pricing_model"],
        currency=SimpleNamespace(code=snapshot["currency"]),
        unit_price_cents=snapshot["unit_price_cents"],
        minimum_charge_cents=snapshot["minimum_charge_cents"],
        frozen_brackets=[
            SimpleNamespace(
                from_quantity=Decimal(bracket["from_quantity"]),
                to_quantity=Decimal(bracket["to_quantity"]) if bracket["to_quantity"] is not None else None,
                unit_price_cents=bracket["unit_price_cents"],
                flat_fee_cents=bracket["flat_fee_cents"],
            )
            for bracket in snapshot["brackets"]
        ],
    )
