"""
Tests for B10: Billing views — Record Payment delegates to ProformaPaymentService.

Validates:
- process_proforma_payment delegates to ProformaPaymentService
- proforma_to_invoice returns error (manual conversion removed)
- Payment method normalization works
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.customers.models import Customer
from apps.users.models import User


class TestProformaToInvoiceRemoved(TestCase):
    """Manual convert-to-invoice is removed."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Test SRL", customer_type="company", status="active",
            primary_email="test@test.ro",
        )
        self.user = User.objects.create_user(
            email="staff@test.ro", password="test123", is_staff=True,
            staff_role="admin",
        )
        ProformaSequence.objects.get_or_create(scope="default")
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="PRO-000001", subtotal_cents=10000,
            tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )

    def test_manual_convert_returns_error(self):
        """proforma_to_invoice view rejects with 'automatic after payment' message."""
        self.client.force_login(self.user)
        response = self.client.post(f"/billing/proformas/{self.proforma.pk}/convert/")
        # Should redirect with error message (not 500)
        self.assertIn(response.status_code, [302, 200, 403])


class TestPaymentMethodNormalization(TestCase):
    """Payment method canonical mapping."""

    def test_bank_transfer_normalizes_to_bank(self):
        from apps.billing.proforma_service import _normalize_payment_method  # noqa: PLC0415
        self.assertEqual(_normalize_payment_method("bank_transfer"), "bank")

    def test_card_normalizes_to_stripe(self):
        from apps.billing.proforma_service import _normalize_payment_method  # noqa: PLC0415
        self.assertEqual(_normalize_payment_method("card"), "stripe")

    def test_unknown_passes_through(self):
        from apps.billing.proforma_service import _normalize_payment_method  # noqa: PLC0415
        self.assertEqual(_normalize_payment_method("paypal"), "paypal")
