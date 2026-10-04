"""Shared fixtures for the fiscal-correction obligation tests."""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from apps.billing.invoice_models import ISSUER_BUILTIN, Invoice, InvoiceLine
from apps.billing.models import Currency, Payment, Refund
from apps.customers.models import Customer


def ron() -> Currency:
    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
    return currency


def customer(name: str = "Fiscal Correction SRL") -> Customer:
    return Customer.objects.create(name=name, customer_type="company", company_name=name, status="active")


def issued_invoice(
    owner: Customer,
    *,
    lines: tuple[tuple[int, str], ...] = ((10000, "0.21"),),
    issuer: str = ISSUER_BUILTIN,
    number: str | None = None,
    issue: bool = True,
) -> Invoice:
    """An invoice whose lines carry the given (net cents, rate) pairs, issued and numbered."""
    subtotal = sum(net for net, _rate in lines)
    taxes = [int((Decimal(net) * Decimal(rate)).quantize(Decimal("1"))) for net, rate in lines]
    invoice = Invoice.objects.create(
        customer=owner,
        currency=ron(),
        number=(number or f"INV-{uuid.uuid4().hex[:8]}") if issue else None,
        status="draft",
        subtotal_cents=subtotal,
        tax_cents=sum(taxes),
        total_cents=subtotal + sum(taxes),
        bill_to_name=owner.company_name,
        bill_to_country="RO",
        issuer_provider=issuer,
    )
    for index, ((net, rate), tax) in enumerate(zip(lines, taxes, strict=True)):
        InvoiceLine.objects.create(
            invoice=invoice,
            description=f"Service {index}",
            quantity=Decimal("1"),
            unit_price_cents=net,
            tax_rate=Decimal(rate),
            tax_cents=tax,
            line_total_cents=net + tax,
            sort_order=index,
        )
    if issue:
        invoice.issue()
        invoice.save()
    return invoice


def paid(invoice: Invoice, *, method: str = "stripe", amount_cents: int | None = None, **extra: Any) -> Payment:
    payment = Payment.objects.create(
        customer=invoice.customer,
        invoice=invoice,
        currency=invoice.currency,
        status="succeeded",
        payment_method=method,
        amount_cents=invoice.total_cents if amount_cents is None else amount_cents,
        gateway_txn_id=f"pi_{uuid.uuid4().hex[:12]}",
        **extra,
    )
    invoice.mark_as_paid()
    invoice.save()
    return payment


def pending_refund(**fields: Any) -> Refund:
    """A refund intent as the service reserves it: pending, linked, not yet settled."""
    document = fields.get("invoice") or fields["order"]
    defaults: dict[str, Any] = {
        "customer": document.customer,
        "currency": document.currency,
        "refund_type": "full",
        "amount_cents": document.total_cents,
        "original_amount_cents": document.total_cents,
        "reference_number": f"REF-{uuid.uuid4().hex[:12]}",
    }
    defaults.update(fields)
    return Refund.objects.create(**defaults)


def complete(refund: Refund) -> Refund:
    """Settle a refund through the same FSM path the gateway convergence uses."""
    from apps.billing.refund_service import RefundService  # noqa: PLC0415

    result = RefundService._advance_refund_status(refund, "succeeded")
    assert result.is_ok(), result
    return result.unwrap()


def gateway(amount_cents: int) -> Any:
    """A payment gateway double that settles a refund of exactly `amount_cents`."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    double = MagicMock()
    double.refund_payment.return_value = {
        "success": True,
        "refund_id": f"re_{uuid.uuid4().hex[:10]}",
        "amount_refunded_cents": amount_cents,
        "status": "succeeded",
        "error": None,
    }
    return double


def order_for(invoice: Invoice | None, owner: Customer | None = None, **fields: Any) -> Any:
    """An order linked to `invoice` (or to none), priced like it."""
    from apps.orders.models import Order  # noqa: PLC0415

    if owner is None:
        assert invoice is not None, "an order with no invoice needs an explicit owner"
        owner = invoice.customer
    defaults: dict[str, Any] = {
        "order_number": f"ORD-{uuid.uuid4().hex[:8]}",
        "customer": owner,
        "currency": ron(),
        "invoice": invoice,
        "status": "completed",
        "subtotal_cents": 10000,
        "tax_cents": 2100,
        "total_cents": 12100,
        "customer_email": "billing@example.test",
        "customer_name": "Fiscal Correction SRL",
    }
    defaults.update(fields)
    return Order.objects.create(**defaults)


def allocated(correction: Any, *, base_cents: int, tax_cents: int, discount_cents: int = 0) -> Any:
    """Freeze an allocation of these magnitudes on `correction`, as the worker's allocation step does."""
    from django.utils import timezone  # noqa: PLC0415

    correction.allocate(base_cents=base_cents, tax_cents=tax_cents, discount_cents=discount_cents, at=timezone.now())
    correction.save()
    return correction


def whole_correction(refund: Refund) -> Any:
    """The correction a completed refund records, allocated the whole original, as a full refund is."""
    from apps.billing.fiscal_correction_service import record_obligation  # noqa: PLC0415

    correction = record_obligation(refund)
    assert correction is not None and correction.original is not None, "the refund owes no correction"
    original = correction.original
    return allocated(
        correction,
        base_cents=original.subtotal_cents,
        tax_cents=original.tax_cents,
        discount_cents=original.discount_cents,
    )


def run_queued_now(func_path: str, *args: Any, **kwargs: Any) -> str:
    """Django-Q's `async_task`, run synchronously: patch it in to run a queued worker right away."""
    from importlib import import_module  # noqa: PLC0415

    module, name = func_path.rsplit(".", 1)
    getattr(import_module(module), name)(*args)
    return "inline"


def correction_of(original: Invoice, *, whole: bool = False) -> Any:
    """The fiscal correction a provider storno of `original` is issued for, created once per original.

    Recorded straight onto a completed refund, without the fiscal-document check the completion hook
    applies, so tests of the reversal document itself need not issue and pay the original first.
    `whole` allocates it the whole original, which is what makes a whole-document storno eligible.
    """
    from apps.billing.fiscal_correction_models import FiscalCorrection  # noqa: PLC0415

    correction = FiscalCorrection.objects.filter(original=original).first()
    if correction is None:
        refund = pending_refund(invoice=original, status="completed", amount_cents=abs(original.total_cents))
        correction = FiscalCorrection.objects.create(original=original, source_refund=refund)
    if whole and not correction.is_allocated:
        allocated(
            correction,
            base_cents=original.subtotal_cents,
            tax_cents=original.tax_cents,
            discount_cents=original.discount_cents,
        )
    return correction
