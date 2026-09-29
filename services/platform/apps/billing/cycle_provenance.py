"""Read-only recovery of historical cycle identity from original financial evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from .invoice_models import InvoiceLine
from .metering_models import BillingCycle, UsageAggregation
from .proforma_models import ProformaLine


@dataclass(frozen=True)
class CycleProvenance:
    currency_code: str | None
    quantity: int | None = None
    unit_price_cents: int | None = None
    hold_reason: str = ""


def _initial_order_terms(cycle: BillingCycle) -> tuple[str, int, int] | None:
    from apps.orders.models import OrderItem  # noqa: PLC0415  # Cross-app immutable order evidence.

    if (cycle.meta or {}).get("source") != "initial_subscription_entitlement":
        return None
    meta = cycle.subscription.meta or {}
    try:
        item_id = UUID(str(meta.get("initial_order_item_id")))
        order_id = UUID(str(meta.get("initial_order_id")))
    except (ValueError, TypeError, AttributeError):
        return None
    if not cycle.subscription.service_id:
        return None
    item = (
        OrderItem.objects.filter(
            pk=item_id,
            order_id=order_id,
            service_id=cycle.subscription.service_id,
            product_id=cycle.subscription.product_id,
            order__customer_id=cycle.subscription.customer_id,
            order__status__in=["paid", "in_review", "provisioning", "completed"],
        )
        .select_related("order")
        .first()
    )
    return (item.order.currency_id, item.quantity, item.unit_price_cents) if item else None


def inspect_cycle_provenance(cycle: BillingCycle) -> CycleProvenance:  # noqa: C901, PLR0911, PLR0912  # Explicit provenance rejection reasons.
    """No writes, current-price lookup, selling setting or guessed conversion."""
    known: set[str] = set()
    linked: set[str] = set()
    terms: set[tuple[str, int, int]] = set()
    hold_reason = ""
    if cycle.currency_id:
        known.add(cycle.currency_id)
    if cycle.terms_frozen_at and cycle.currency_id and cycle.quantity and cycle.unit_price_cents is not None:
        terms.add((cycle.currency_id, cycle.quantity, cycle.unit_price_cents))
    sources: tuple[tuple[str, Any], ...] = (("invoice", InvoiceLine), ("proforma", ProformaLine))
    for source_name, line_model in sources:
        source = getattr(cycle, source_name)
        if not source:
            continue
        if source.customer_id != cycle.subscription.customer_id:
            return CycleProvenance(None, hold_reason="Original document belongs to another customer")
        linked.add(source.currency_id)
        if source.status == "draft" and not getattr(source, "locked_at", None):
            continue
        known.add(source.currency_id)
        lines = list(line_model.objects.filter(**{source_name: source.pk}, billing_cycle_id=cycle.pk)[:2])
        if len(lines) != 1:
            hold_reason = "Original document does not have exactly one matching fixed line"
            continue
        line = lines[0]
        if line.quantity <= 0 or line.quantity != int(line.quantity) or line.unit_price_cents < 0:
            hold_reason = "Original fixed line has unsupported quantity or price"
            continue
        terms.add((source.currency_id, int(line.quantity), line.unit_price_cents))
    invoice = cycle.usage_invoice
    if invoice is not None:
        if invoice.customer_id != cycle.subscription.customer_id:
            return CycleProvenance(None, hold_reason="Original usage invoice belongs to another customer")
        linked.add(invoice.currency_id)
        if invoice.status != "draft" or invoice.locked_at:
            known.add(invoice.currency_id)
    for aggregation in UsageAggregation.objects.filter(
        billing_cycle=cycle,
        status__in=["rated", "invoiced", "finalized"],
    ):
        if aggregation.customer_id != cycle.subscription.customer_id:
            return CycleProvenance(None, hold_reason="Rated usage belongs to another customer")
        currency = (aggregation.meta or {}).get("rating", {}).get("currency")
        if isinstance(currency, str):
            known.add(currency)
    original = _initial_order_terms(cycle)
    if original:
        known.add(original[0])
        terms.add(original)
    if len(known | linked) > 1:
        return CycleProvenance(None, hold_reason="Conflicting original currencies require review")
    currency_code = next(iter(known), None)
    if not currency_code:
        return CycleProvenance(None, hold_reason="No immutable source identifies the original currency")
    if len(terms) == 1 and not hold_reason:
        _, quantity, unit_price = next(iter(terms))
        return CycleProvenance(currency_code, quantity, unit_price)
    return CycleProvenance(
        currency_code,
        hold_reason=hold_reason or "No unambiguous original fixed terms; preserve already-rated usage",
    )
