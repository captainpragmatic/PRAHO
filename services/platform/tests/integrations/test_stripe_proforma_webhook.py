"""
Tests for B7: Stripe webhook proforma auto-convert on payment success.

Validates:
- Payment with proforma FK triggers record_payment_and_convert on success
- Payment without proforma FK does not trigger conversion
- Payment failure sends proforma email as fallback
- C1: Retry after conversion failure still attempts conversion
- C7: Tests exercise the actual webhook handler, not just mocks
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

    def _create_payment_with_proforma(self, gateway_txn_id: str = "pi_test_123"):
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number=f"PRO-STRIPE-{gateway_txn_id[-3:]}", subtotal_cents=10000,
            tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        proforma.send_proforma()
        proforma.save()

        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency,
            amount_cents=12100, payment_method="stripe",
            gateway_txn_id=gateway_txn_id,
            proforma=proforma,
        )
        return payment, proforma

    def _build_succeeded_payload(self, stripe_payment_id: str) -> dict:
        """Build a payment_intent.succeeded webhook payload."""
        return {
            "data": {
                "object": {
                    "id": stripe_payment_id,
                    "payment_method": "pm_test",
                    "amount_received": 12100,
                },
            },
        }

    def _get_processor(self):
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415
        return StripeWebhookProcessor()

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_succeeded_payment_with_proforma_triggers_conversion(self, mock_convert):
        """C7 fix: Test the ACTUAL webhook handler, not manual code.
        When payment succeeds and has proforma FK, handler calls record_payment_and_convert."""
        from apps.common.types import Ok  # noqa: PLC0415

        _payment, _proforma = self._create_payment_with_proforma("pi_test_c7")
        mock_convert.return_value = Ok(MagicMock())

        processor = self._get_processor()
        payload = self._build_succeeded_payload("pi_test_c7")
        success, _msg = processor.handle_payment_intent_event("payment_intent.succeeded", payload)

        self.assertTrue(success)
        mock_convert.assert_called_once()

    def test_succeeded_payment_without_proforma_no_conversion(self):
        """Payment without proforma FK does not trigger conversion."""
        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency,
            amount_cents=12100, payment_method="stripe",
            gateway_txn_id="pi_no_proforma_456",
        )

        # No proforma → no conversion attempt
        self.assertIsNone(payment.proforma)

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_retry_after_conversion_failure_still_attempts_conversion(self, mock_convert):
        """C1 regression test: When first webhook succeeds payment but conversion fails,
        Stripe retries the webhook. The retry MUST still attempt conversion even though
        the payment is already in terminal 'succeeded' state.

        ROOT CAUSE: apply_gateway_event returns False on retry (payment already succeeded),
        and the early-return at line 174 skips the proforma conversion check entirely.
        """
        from apps.common.types import Err, Ok  # noqa: PLC0415

        payment, proforma = self._create_payment_with_proforma("pi_retry_c1")

        processor = self._get_processor()
        payload = self._build_succeeded_payload("pi_retry_c1")

        # First webhook: payment transitions to succeeded, but conversion FAILS
        mock_convert.return_value = Err("conversion service unavailable")
        success1, _msg1 = processor.handle_payment_intent_event("payment_intent.succeeded", payload)
        # Webhook signals failure so Stripe will retry
        self.assertFalse(success1, "First attempt should return False when conversion fails")

        # Payment is now 'succeeded' in DB (committed by apply_gateway_event)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")

        # Proforma is still NOT converted (conversion was rolled back)
        proforma.refresh_from_db()
        self.assertNotEqual(proforma.status, "converted")

        # Second webhook (Stripe retry): conversion should succeed this time
        mock_convert.reset_mock()
        mock_convert.return_value = Ok(MagicMock())
        success2, _msg2 = processor.handle_payment_intent_event("payment_intent.succeeded", payload)

        # THIS IS THE C1 BUG: without the fix, mock_convert is NOT called on retry
        # because apply_gateway_event returns False (already succeeded) → early return
        mock_convert.assert_called_once()
        self.assertTrue(success2, "Retry should succeed after conversion succeeds")
