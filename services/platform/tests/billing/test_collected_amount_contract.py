"""Requested amounts cannot replace exact integer collected amounts at settlement."""

from django.test import TestCase

from apps.billing.models import Payment
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from tests.billing.test_payment_settlement_isolation import prepare_case


class CollectedAmountContractTests(TestCase):
    def setUp(self) -> None:
        customer, currency, self.invoice, _ = prepare_case(self)
        self.payment = Payment.objects.create(
            customer=customer,
            invoice=self.invoice,
            currency=currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_collected",
        )

    def test_partial_capture_cannot_credit_the_requested_total(self) -> None:
        self.assert_rejected(self.payment.amount_cents - 1)

    def test_missing_collected_amount_cannot_fall_back_to_requested_amount(self) -> None:
        self.assert_rejected(None)

    def test_noninteger_collected_amounts_are_rejected(self) -> None:
        for value in (True, str(self.payment.amount_cents), float(self.payment.amount_cents)):
            with self.subTest(value=value):
                self.assert_rejected(value)

    def assert_rejected(self, received: object) -> None:
        facts = {
            "id": self.payment.gateway_txn_id,
            "status": "succeeded",
            "amount": self.payment.amount_cents,
            "amount_received": received,
            "currency": self.payment.currency.code.lower(),
        }
        success, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded", {"data": {"object": facts}}
        )
        self.assertTrue(success, "acknowledged: no redelivery can fix a collected-amount mismatch")
        self.assertIn("amount mismatch", message)
        self.payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual((self.payment.status, self.invoice.status), ("pending", "issued"))
        self.assertIsNone(self.invoice.paid_at)
