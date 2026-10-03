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
