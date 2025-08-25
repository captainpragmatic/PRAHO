# ===============================================================================
# TEST FACTORIES FOR BILLING
# ===============================================================================
from typing import Optional

from django.contrib.auth import get_user_model

from apps.billing.models import Currency, Invoice, Payment
from apps.customers.models import Customer

User = get_user_model()


def create_currency(code: str = 'RON') -> Currency:
    """Create a simple currency for tests."""
    return Currency.objects.create(code=code, symbol='€' if code == 'EUR' else 'L', decimals=2)


def create_customer(company_name: str = 'Test Co') -> Customer:
    """Create a minimal company customer for tests."""
    return Customer.objects.create(customer_type='company', company_name=company_name, status='active')


def create_invoice(customer: Customer, currency: Optional[Currency] = None, number: str = 'INV-TEST-001', total_cents: int = 10000) -> Invoice:
    """Create an Invoice with sensible defaults."""
    if currency is None:
        currency = create_currency()

    return Invoice.objects.create(
        customer=customer,
        currency=currency,
        number=number,
        total_cents=total_cents,
        subtotal_cents=total_cents,
        status='issued'
    )


def create_payment(customer: Customer, invoice: Optional[Invoice] = None, currency: Optional[Currency] = None, amount_cents: int = 1000, method: str = 'stripe', status: str = 'succeeded') -> Payment:
    """Create a Payment linked to an invoice optionally."""
    if currency is None:
        currency = create_currency()

    return Payment.objects.create(
        customer=customer,
        invoice=invoice,
        currency=currency,
        amount_cents=amount_cents,
        method=method,
        status=status
    )
