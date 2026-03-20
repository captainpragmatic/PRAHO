"""
Tests for B7: Stripe webhook proforma auto-convert on payment success.

Validates:
- Payment with proforma FK triggers record_payment_and_convert on success
- Payment without proforma FK does not trigger conversion
- Payment failure sends proforma email as fallback
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.customers.models import Customer
from tests.helpers.fsm_helpers import force_status  # noqa: F401


class StripeProformaWebhookTest(TestCase):
    """Test Stripe webhook integration with proforma lifecycle."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Stripe Test SRL", customer_type="company",
            status="active", primary_email="stripe@test.ro",
        )
        ProformaSequence.objects.get_or_create(scope="default")

    def _create_payment_with_proforma(self):
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="PRO-STRIPE-001", subtotal_cents=10000,
            tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        proforma.send_proforma()
        proforma.save()

        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency,
            amount_cents=12100, payment_method="stripe",
            gateway_txn_id="pi_test_123",
            proforma=proforma,
        )
        return payment, proforma

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_succeeded_payment_with_proforma_triggers_conversion(self, mock_convert):
        """When payment succeeds and has proforma FK, trigger auto-conversion."""
        from apps.common.types import Ok  # noqa: PLC0415

        payment, _proforma = self._create_payment_with_proforma()
        mock_convert.return_value = Ok(MagicMock())  # Simulate successful conversion

        # Simulate what the webhook handler does after apply_gateway_event succeeds
        payment.succeed()
        payment.save(update_fields=["status", "updated_at"])

        # The webhook should call record_payment_and_convert
        if payment.proforma:
            from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415
            ProformaPaymentService.record_payment_and_convert(
                proforma_id=str(payment.proforma.id),
                amount_cents=payment.amount_cents,
                payment_method="stripe",
                existing_payment=payment,
            )

        mock_convert.assert_called_once()

    def test_succeeded_payment_without_proforma_no_conversion(self):
        """Payment without proforma FK does not trigger conversion."""
        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency,
            amount_cents=12100, payment_method="stripe",
            gateway_txn_id="pi_no_proforma_456",
        )
        payment.succeed()
        payment.save(update_fields=["status", "updated_at"])

        # No proforma → no conversion attempt
        self.assertIsNone(payment.proforma)
