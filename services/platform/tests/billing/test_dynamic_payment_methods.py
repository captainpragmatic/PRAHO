"""Payment Element methods remain dynamic; only confirmed success settles a document."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from tests.billing.test_payment_settlement_isolation import prepare_case


class DynamicGatewayContractTests(SimpleTestCase):
    def test_checkout_retains_automatic_payment_methods(self) -> None:
        with (
            patch("apps.settings.services.SettingsService.get_setting", return_value="local-test-key"),
            patch(
                "stripe.PaymentIntent.create", return_value=SimpleNamespace(id="pi_dynamic", client_secret="test")
            ) as create,
        ):
            result = StripeGateway().create_payment_intent("order", 10000, "RON")
        self.assertTrue(result["success"])
        self.assertEqual(create.call_args.kwargs["automatic_payment_methods"], {"enabled": True})
        self.assertNotIn("payment_method_types", create.call_args.kwargs)


class DelayedPaymentContractTests(TestCase):
    def test_delayed_method_settles_only_after_success_and_remains_idempotent(self) -> None:
        customer, currency, invoice, _ = prepare_case(self)
        payment = Payment.objects.create(
            customer=customer,
            invoice=invoice,
            currency=currency,
            amount_cents=invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_delayed",
        )
        processor = StripeWebhookProcessor()
        facts = {
            "id": payment.gateway_txn_id,
            "amount": payment.amount_cents,
            "amount_received": payment.amount_cents,
            "currency": currency.code.lower(),
            "payment_method_types": ["sepa_debit"],
            "latest_charge": None,
        }
        for event, status in (
            ("payment_intent.requires_action", "requires_action"),
            ("payment_intent.amount_capturable_updated", "requires_capture"),
            ("payment_intent.processing", "processing"),
        ):
            with self.subTest(status=status):
                success, message = processor.handle_payment_intent_event(
                    event, {"data": {"object": {**facts, "status": status}}}
                )
                self.assertTrue(success, message)
                payment.refresh_from_db()
                invoice.refresh_from_db()
                self.assertEqual((payment.status, invoice.status), ("pending", "issued"))
                self.assertIsNone(invoice.paid_at)
        for _ in range(2):
            success, message = processor.handle_payment_intent_event(
                "payment_intent.succeeded", {"data": {"object": {**facts, "status": "succeeded"}}}
            )
            self.assertTrue(success, message)
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual((payment.status, invoice.status), ("succeeded", "paid"))
        self.assertEqual(Payment.objects.filter(invoice=invoice).count(), 1)
