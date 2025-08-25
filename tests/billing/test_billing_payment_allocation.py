# ===============================================================================
# BILLING PAYMENT ALLOCATION TESTS
# ===============================================================================

from django.test import TestCase

from tests.factories.billing import create_currency, create_customer, create_invoice, create_payment


class PaymentAllocationTests(TestCase):
    """Tests around payment allocation, partial payments and invoice balances"""

    def setUp(self) -> None:
        self.currency = create_currency('RON')
        self.customer = create_customer('Allocation Co')
        self.invoice = create_invoice(customer=self.customer, currency=self.currency, number='INV-ALLOC-001', total_cents=10000)

    def test_partial_payment_reduces_remaining_amount(self) -> None:
        # Partial payment of 30.00 (3000 cents)
        create_payment(customer=self.customer, invoice=self.invoice, currency=self.currency, amount_cents=3000, status='succeeded')

        remaining = self.invoice.get_remaining_amount()
        self.assertEqual(remaining, 7000)

        # Invoice is not automatically marked paid until business logic runs
        self.assertNotEqual(self.invoice.status, 'paid')

    def test_multiple_partial_payments_fulfill_invoice(self) -> None:
        create_payment(customer=self.customer, invoice=self.invoice, currency=self.currency, amount_cents=6000, status='succeeded')
        create_payment(customer=self.customer, invoice=self.invoice, currency=self.currency, amount_cents=4000, status='succeeded')

        remaining = self.invoice.get_remaining_amount()
        self.assertEqual(remaining, 0)

        # Mark as paid using model helper and assert status change
        self.invoice.mark_as_paid()
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, 'paid')

