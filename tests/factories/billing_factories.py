# ===============================================================================
# TEST FACTORIES FOR BILLING
# ===============================================================================

from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment
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
    method: str = 'stripe'
    status: str = 'succeeded'


def create_currency(code: str = 'RON') -> Currency:
    """Create a simple currency for tests."""
    return Currency.objects.create(code=code, symbol='€' if code == 'EUR' else 'L', decimals=2)


def create_customer(company_name: str = 'Test Co') -> Customer:
    """Create a minimal company customer for tests."""
    return Customer.objects.create(customer_type='company', company_name=company_name, status='active')


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
        due_at=timezone.now() + timedelta(days=30)  # Default 30 day payment terms
    )


def create_payment(request: PaymentCreationRequest) -> Payment:
    """Create a Payment linked to an invoice optionally."""
    if request.currency is None:
        request.currency = create_currency()

    return Payment.objects.create(
        customer=request.customer,
        invoice=request.invoice,
        currency=request.currency,
        amount_cents=request.amount_cents,
        method=request.method,
        status=request.status
    )


# Legacy wrapper for backward compatibility
def create_payment_legacy(  # noqa: PLR0913
    customer: Customer,
    invoice: Invoice | None = None,
    currency: Currency | None = None,
    amount_cents: int = 1000,
    method: str = 'stripe',
    status: str = 'succeeded'
) -> Payment:
    """Legacy wrapper for backward compatibility"""
    request = PaymentCreationRequest(
        customer=customer,
        invoice=invoice,
        currency=currency,
        amount_cents=amount_cents,
        method=method,
        status=status
    )
    return create_payment(request)
