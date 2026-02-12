# ===============================================================================
# TEST FACTORIES FOR BILLING
# ===============================================================================

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.billing.models import Currency, Invoice, InvoiceLine, Payment
from apps.customers.models import Customer

User = get_user_model()


# ===============================================================================
# PAYMENT FACTORY PARAMETER OBJECTS
# ===============================================================================

@dataclass
class PaymentCreationRequest:
    """Parameter object for payment creation"""
    customer: Customer
    invoice: Invoice | None = None
    currency: Currency | None = None
    amount_cents: int = 1000
    payment_method: str = 'stripe'
    status: str = 'succeeded'


def create_currency(code: str = 'RON') -> Currency:
    """Create a simple currency for tests."""
    return Currency.objects.create(code=code, symbol='€' if code == 'EUR' else 'L', decimals=2)


def create_customer(company_name: str = 'Test Co') -> Customer:
    """Create a minimal company customer for tests."""
    return Customer.objects.create(
        name=company_name,
        customer_type='company',
        company_name=company_name,
        status='active',
    )


def create_invoice(customer: Customer, currency: Currency | None = None, number: str = 'INV-TEST-001', total_cents: int = 10000) -> Invoice:
    """Create an Invoice with sensible defaults."""
    if currency is None:
        currency = create_currency()

    return Invoice.objects.create(
        customer=customer,
        currency=currency,
        number=number,
        total_cents=total_cents,
        subtotal_cents=total_cents,
        status='issued',
        due_at=timezone.now() + timedelta(days=14)  # Default 14 day payment terms
    )


def create_invoice_line(
    invoice: Invoice,
    description: str = "Service",
    quantity: int | Decimal = 1,
    unit_price_cents: int = 1000,
    kind: str = "service",
    tax_rate: Decimal = Decimal("0.2100"),
) -> InvoiceLine:
    """Create an InvoiceLine with sensible defaults."""
    return InvoiceLine.objects.create(
        invoice=invoice,
        kind=kind,
        description=description,
        quantity=Decimal(str(quantity)),
        unit_price_cents=unit_price_cents,
        tax_rate=tax_rate,
    )


def CurrencyFactory(**kwargs: object) -> Currency:  # noqa: N802
    code = str(kwargs.pop("code", "RON"))
    symbol = str(kwargs.pop("symbol", "€" if code == "EUR" else "L"))
    decimals = int(kwargs.pop("decimals", 2))
    kwargs["code"] = code
    kwargs["symbol"] = symbol
    kwargs["decimals"] = decimals
    return Currency.objects.create(**kwargs)


def CustomerFactory(**kwargs: object) -> Customer:  # noqa: N802
    company_name = str(kwargs.pop("company_name", "Test Company SRL"))
    kwargs.setdefault("name", company_name)
    kwargs.setdefault("customer_type", "company")
    kwargs.setdefault("company_name", company_name)
    kwargs.setdefault("status", "active")
    return Customer.objects.create(**kwargs)


def InvoiceFactory(**kwargs: object) -> Invoice:  # noqa: N802
    customer = kwargs.pop("customer", None)
    currency = kwargs.pop("currency", None)

    if customer is None:
        customer = create_customer()
    if currency is None:
        currency = create_currency()

    if "bill_to_street" in kwargs and "bill_to_address1" not in kwargs:
        kwargs["bill_to_address1"] = kwargs.pop("bill_to_street")
    if "bill_to_postal_code" in kwargs and "bill_to_postal" not in kwargs:
        kwargs["bill_to_postal"] = kwargs.pop("bill_to_postal_code")
    if "tax_total_cents" in kwargs and "tax_cents" not in kwargs:
        kwargs["tax_cents"] = kwargs.pop("tax_total_cents")

    kwargs.setdefault("number", "INV-TEST-001")
    kwargs.setdefault("status", "issued")
    kwargs.setdefault("subtotal_cents", kwargs.get("total_cents", 10000))
    kwargs.setdefault("total_cents", kwargs.get("subtotal_cents", 10000))
    kwargs.setdefault("due_at", timezone.now() + timedelta(days=14))
    kwargs.setdefault("bill_to_name", "Test Company SRL")

    return Invoice.objects.create(customer=customer, currency=currency, **kwargs)


def InvoiceLineFactory(**kwargs: object) -> InvoiceLine:  # noqa: N802
    invoice = kwargs.pop("invoice", None)
    if invoice is None:
        invoice = create_invoice(customer=create_customer())
    kwargs.setdefault("description", "Service")
    kwargs.setdefault("quantity", Decimal("1"))
    kwargs.setdefault("unit_price_cents", 1000)
    kwargs.setdefault("kind", "service")
    kwargs.setdefault("tax_rate", Decimal("0.2100"))
    kwargs["quantity"] = Decimal(str(kwargs["quantity"]))
    return InvoiceLine.objects.create(invoice=invoice, **kwargs)


def create_payment(request: PaymentCreationRequest) -> Payment:
    """Create a Payment linked to an invoice optionally."""
    if request.currency is None:
        request.currency = create_currency()

    return Payment.objects.create(
        customer=request.customer,
        invoice=request.invoice,
        currency=request.currency,
        amount_cents=request.amount_cents,
        payment_method=request.payment_method,
        status=request.status
    )


# Legacy wrapper for backward compatibility
def create_payment_legacy(  # noqa: PLR0913
    customer: Customer,
    invoice: Invoice | None = None,
    currency: Currency | None = None,
    amount_cents: int = 1000,
    payment_method: str = 'stripe',
    status: str = 'succeeded'
) -> Payment:
    """Legacy wrapper for backward compatibility"""
    request = PaymentCreationRequest(
        customer=customer,
        invoice=invoice,
        currency=currency,
        amount_cents=amount_cents,
        payment_method=payment_method,
        status=status
    )
    return create_payment(request)
