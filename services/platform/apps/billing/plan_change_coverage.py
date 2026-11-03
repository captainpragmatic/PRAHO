"""Recover paid service intervals and frozen future obligations without repricing them."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db.models import Q

from .invoice_models import Invoice, InvoiceLine
from .metering_models import BillingCycle
from .plan_change_models import PlanChange
from .plan_change_pricing import CoveredInterval
from .proforma_models import ProformaInvoice, ProformaLine
from .refund_models import refunds_for_invoice
from .subscription_models import Subscription

if TYPE_CHECKING:
    from apps.orders.models import OrderItem
    from apps.promotions.models import PromotionApplication

PROMOTION_QUOTE_VERSION = 2


@dataclass(frozen=True)
class PlanCoverage:
    intervals: tuple[CoveredInterval, ...]
    current_period_price_cents: int
    evidence: dict[str, dict[str, Any]]


def _refuse(reason: str) -> ValidationError:
    return ValidationError(f"Plan-change coverage requires review: {reason}")


def invoice_has_paid_coverage(invoice: Invoice) -> bool:
    # A dispute writes Payment facts before document-first review can run. Refuse
    # immediately, including when an old invoice projection still says 'paid'.
    if invoice.payments.filter(status__in=["disputed", "refunded", "partially_refunded"]).exists():
        raise _refuse("disputed or refunded payment evidence")
    if refunds_for_invoice(invoice).exclude(status__in=["cancelled", "rejected", "failed"]).exists():
        raise _refuse("a refund requires an explicit interval allocation")
    return invoice.status == "paid" and invoice.get_remaining_amount() == 0


def _document_net(
    cycle: BillingCycle,
    document: Invoice | ProformaInvoice,
    line: InvoiceLine | ProformaLine,
) -> int:
    discount = 0
    if document.discount_cents:
        allocations = (document.meta or {}).get("promotion_cycle_discounts")
        if not isinstance(allocations, dict) or str(cycle.pk) not in allocations:
            raise _refuse("the document discount has no proven fixed-line allocation")
        discount = allocations[str(cycle.pk)]
        if type(discount) is not int or discount < 0:
            raise _refuse("invalid fixed-line discount allocation")
    net = line.subtotal_cents - discount - line.discount_amount_cents
    if net < 0:
        raise _refuse("a fixed obligation cannot be negative")
    return net


def _fixed_evidence(cycle: BillingCycle, subscription: Subscription) -> tuple[int, bool, dict[str, Any]]:
    # A renewal payment changes the invoice projection, not the original frozen
    # obligation. Retain the proforma's identity across its real conversion.
    invoice = cycle.invoice
    document: Invoice | ProformaInvoice | None = cycle.proforma or invoice
    if document is None:
        return _initial_order_evidence(cycle, subscription)
    if document.customer_id != subscription.customer_id or document.currency_id != subscription.currency_id:
        raise _refuse("document owner or currency changed")
    if document.status not in {"issued", "overdue", "paid", "sent", "accepted", "converted"} or (
        isinstance(document, Invoice) and not document.locked_at
    ):
        raise _refuse("the base obligation is not an immutable issued document")
    lines = list(document.lines.filter(billing_cycle_id=cycle.pk)[:2])
    if len(lines) != 1:
        raise _refuse("the document does not have exactly one fixed line")
    line = lines[0]
    if line.kind != "service" or line.service_id != subscription.service_id or line.quantity != 1:
        raise _refuse("the fixed line does not belong to this quantity-one service")
    if (
        cycle.currency_id != document.currency_id
        or cycle.quantity != 1
        or cycle.unit_price_cents != line.unit_price_cents
    ):
        raise _refuse("the frozen interval and fixed line disagree")
    net = _document_net(cycle, document, line)
    if cycle.proforma_id and invoice is not None:
        if (
            invoice.converted_from_proforma_id != cycle.proforma_id
            or invoice.customer_id != document.customer_id
            or invoice.currency_id != document.currency_id
            or (invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents)
            != (document.subtotal_cents, document.tax_cents, document.total_cents)
        ):
            raise _refuse("the converted invoice no longer matches the original fixed obligation")
        converted = list(invoice.lines.filter(billing_cycle_id=cycle.pk)[:2])
        if len(converted) != 1 or any(
            getattr(converted[0], field) != getattr(line, field)
            for field in (
                "service_id",
                "quantity",
                "unit_price_cents",
                "discount_amount_cents",
                "period_start",
                "period_end",
            )
        ):
            raise _refuse("the converted fixed line no longer matches the original obligation")
    paid = invoice_has_paid_coverage(invoice) if invoice is not None else False
    evidence = {
        "cycle_id": str(cycle.pk),
        "document_kind": "invoice" if isinstance(document, Invoice) else "proforma",
        "document_id": str(document.pk),
        "fixed_line_id": line.pk,
        "currency": document.currency_id,
        "period_start": cycle.period_start.isoformat(),
        "period_end": cycle.period_end.isoformat(),
        "quantity": 1,
        "fixed_unit_price_cents": line.unit_price_cents,
        "base_net_cents": net,
    }
    return net, paid, evidence


def _initial_order_evidence(cycle: BillingCycle, subscription: Subscription) -> tuple[int, bool, dict[str, Any]]:
    from apps.orders.models import OrderItem  # noqa: PLC0415  # Original paid-order entitlement evidence.

    if (cycle.meta or {}).get("source") != "initial_subscription_entitlement":
        raise _refuse("the interval has no immutable base document")
    meta = subscription.meta or {}
    if subscription.service_id is None:
        raise _refuse("the initial entitlement has no owned service")
    try:
        item_id, order_id = UUID(str(meta.get("initial_order_item_id"))), UUID(str(meta.get("initial_order_id")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise _refuse("the initial order identifiers are unproven") from exc
    item = (
        OrderItem.objects.select_related("order__invoice")
        .filter(
            pk=item_id,
            order_id=order_id,
            service_id=subscription.service_id,
            order__customer_id=subscription.customer_id,
            order__status__in=["paid", "in_review", "provisioning", "completed"],
        )
        .first()
    )
    if item is None or item.quantity != 1 or item.order.currency_id != subscription.currency_id:
        raise _refuse("the initial entitlement has no matching paid order item")
    invoice = item.order.invoice
    if invoice is None or invoice.customer_id != subscription.customer_id or not invoice_has_paid_coverage(invoice):
        raise _refuse("the initial order's payment coverage is unproven")
    net = _initial_period_net(item)
    return (
        net,
        True,
        {
            "cycle_id": str(cycle.pk),
            "document_kind": "initial_order",
            "document_id": str(invoice.pk),
            "order_id": str(item.order_id),
            "order_item_id": str(item.pk),
            "currency": invoice.currency_id,
            "period_start": cycle.period_start.isoformat(),
            "period_end": cycle.period_end.isoformat(),
            "quantity": 1,
            "fixed_unit_price_cents": net,
            "base_net_cents": net,
        },
    )


def _initial_period_net(item: OrderItem) -> int:
    """Reuse the checkout allocator with its stored, ordered application facts."""
    from apps.promotions.pricing import allocate  # noqa: PLC0415  # Same service/setup split as checkout.

    service, setup = item.unit_price_cents, item.setup_cents
    if not item.order.discount_cents:
        return int(service)
    applications = _ordered_initial_applications(item)
    if sum(app.discount_cents for app in applications) != item.order.discount_cents:
        raise _refuse("the initial discount has no complete allocation evidence")
    for application in applications:
        discount = application.allocations.get(str(item.pk), 0)
        if type(discount) is not int or not 0 <= discount <= service + setup:
            raise _refuse("invalid initial item allocation")
        kind = application.snapshot.get("kind")
        if kind == "free_setup":
            if discount > setup:
                raise _refuse("invalid setup-only discount")
            setup -= discount
        elif kind in {"bogo", "free_months"}:
            if discount > service:
                raise _refuse("invalid service-only discount")
            service -= discount
        elif isinstance(kind, str) and kind in {"percent", "fixed", "tiered", "tiered_percent", "tiered_fixed"}:
            parts = allocate(discount, {"service": service, "setup": setup})
            service -= parts.get("service", 0)
            setup -= parts.get("setup", 0)
        else:
            raise _refuse("unknown historical promotion allocation")
    return int(service)


def _ordered_initial_applications(item: OrderItem) -> list[PromotionApplication]:
    """Only the accepted checkout payload establishes the order of its offers."""
    quote = (item.order.meta or {}).get("promotion_quote")
    if (
        not isinstance(quote, dict)
        or quote.get("version") != PROMOTION_QUOTE_VERSION
        or not isinstance(quote.get("offers"), list)
    ):
        raise _refuse("the initial discount has no frozen offer order")
    applications = list(item.order.promotion_applications.all())
    indexed = {
        ("coupon" if app.coupon_id is not None else "rule", str(app.coupon_id or app.rule_id)): app
        for app in applications
    }
    ordered = []
    seen = set()
    for offer in quote["offers"]:
        if (
            not isinstance(offer, dict)
            or not isinstance(offer.get("source"), str)
            or not isinstance(offer.get("key"), str)
        ):
            raise _refuse("the initial discount's ordered offer is malformed")
        key = (offer["source"], offer["key"])
        application = indexed.get(key)
        if key in seen or application is None or application.snapshot != offer:
            raise _refuse("the initial discount's ordered application is unproven")
        seen.add(key)
        ordered.append(application)
    if len(ordered) != len(applications):
        raise _refuse("the initial discount's ordered applications are incomplete")
    return ordered


def _committed_supplements(subscription: Subscription) -> list[PlanChange]:
    return list(
        PlanChange.objects.filter(subscription=subscription, committed_at__isnull=False)
        .select_related("invoice")
        .prefetch_related("intervals")
        .order_by("committed_at", "pk")
    )


def load_plan_coverage(subscription: Subscription, *, at: datetime) -> PlanCoverage:
    """Read committed evidence; callers serialize acceptance under Customer/Subscription.

    This function takes no document locks after the customer boundary. Claim and
    settlement must revalidate the fingerprint under their own document-first context.
    """
    if subscription.quantity != 1 or not subscription.service_id:
        raise _refuse("only an independently billed quantity-one service is supported")
    cycles = list(
        BillingCycle.objects.filter(subscription=subscription, period_end__gt=at)
        .filter(
            Q(period_start__lte=at)
            | Q(terms_frozen_at__isnull=False)
            | Q(invoice__isnull=False)
            | Q(proforma__isnull=False)
        )
        .select_related("invoice", "proforma")
        .order_by("period_start", "pk")
    )
    current = [cycle for cycle in cycles if cycle.period_start <= at < cycle.period_end]
    if len(current) != 1:
        raise _refuse("there is no single proven current interval")
    values: dict[str, tuple[int, bool, dict[str, Any]]] = {}
    for cycle in cycles:
        # A frozen unbilled placeholder is not a committed financial obligation.
        if cycle.period_start > at and not cycle.invoice_id and not cycle.proforma_id:
            continue
        values[str(cycle.pk)] = _fixed_evidence(cycle, subscription)
    current_key = str(current[0].pk)
    if not values[current_key][1]:
        raise _refuse("the current interval has no paid coverage")
    current_price = values[current_key][0]
    sums, current_price = _supplement_coverage(subscription, values, current_key, current_price, at)
    intervals: list[CoveredInterval] = []
    evidence: dict[str, dict[str, Any]] = {}
    for cycle in cycles:
        key = str(cycle.pk)
        if key not in values:
            continue
        base, paid, source = values[key]
        source["prior_supplement_cents"] = sums.get(key, 0)
        source["fingerprint"] = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        evidence[key] = source
        intervals.append(CoveredInterval(key, cycle.period_start, cycle.period_end, base, sums.get(key, 0), paid))
    return PlanCoverage(tuple(intervals), current_price, evidence)


def _supplement_coverage(
    subscription: Subscription,
    values: dict[str, tuple[int, bool, dict[str, Any]]],
    current_key: str,
    current_price: int,
    at: datetime,
) -> tuple[dict[str, int], int]:
    return _apply_supplement_coverage(
        subscription, values, current_key, current_price, at, changes=_committed_supplements(subscription)
    )


def _apply_supplement_coverage(  # noqa: C901, PLR0913 -- Shared fixed evidence and prior/own allocation context.
    subscription: Subscription,
    values: dict[str, tuple[int, bool, dict[str, Any]]],
    current_key: str,
    current_price: int,
    at: datetime,
    *,
    changes: Iterable[PlanChange],
) -> tuple[dict[str, int], int]:
    sums: dict[str, int] = {}
    for change in changes:
        if change.customer_id != subscription.customer_id or change.service_id != subscription.service_id:
            raise _refuse("a settled supplement belongs to another owner or service")
        if change.currency_id != subscription.currency_id or change.status == "paid_review":
            raise _refuse("a settled supplement has invalidated currency or payment coverage")
        if change.total_cents:
            if change.invoice is None or not invoice_has_paid_coverage(change.invoice):
                raise _refuse("a committed supplement is no longer settled")
            if (
                change.invoice.customer_id != subscription.customer_id
                or change.invoice.currency_id != change.currency_id
            ):
                raise _refuse("a supplement document belongs to another owner or currency")
            if change.invoice.total_cents != change.total_cents or change.invoice.subtotal_cents != change.net_cents:
                raise _refuse("a supplement document does not match the accepted price")
        parts = list(change.intervals.all())
        if sum(part.net_cents for part in parts) != change.net_cents:
            raise _refuse("supplement allocations do not match the accepted net amount")
        for part in parts:
            key = str(part.evidence.get("cycle_id", ""))
            if key not in values:
                continue
            source = values[key][2]
            if (
                source["period_start"] != part.period_start.isoformat()
                or source["period_end"] != part.period_end.isoformat()
            ):
                raise _refuse("a supplement interval was retargeted")
            sums[key] = sums.get(key, 0) + part.net_cents
            if key == current_key and change.effective_at <= at:
                current_price = change.target_period_price_cents
    return sums, current_price
