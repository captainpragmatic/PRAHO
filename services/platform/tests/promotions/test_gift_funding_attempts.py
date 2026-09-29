"""Uncertain funding, early callbacks and declines converge into one voucher."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, FXRate, PaymentRetryAttempt
from apps.customers.models import Customer
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.promotions.gift_cards import create_purchase, start_funding
from apps.promotions.gift_funding import refresh_funding
from apps.promotions.models import GiftCardTransaction
from apps.settings.services import SettingsService
from apps.users.models import User


class GiftFundingAttemptTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        self.customer = Customer.objects.create(
            name="Funding buyer", customer_type="individual", primary_email="buyer@example.test"
        )
        self.actor = User.objects.create_user(email="buyer@example.test")
        self.purchase = create_purchase(self.customer, self.currency, 5000, "funding", actor=self.actor)

    def _facts(self, status="succeeded", **changes):
        attempt = apps.get_model("promotions", "GiftCardFundingAttempt").objects.get(purchase=self.purchase)
        return {
            "success": True, "status": status, "amount": 5000, "amount_received": 5000,
            "currency": self.purchase.gift_card.currency_id.lower(), "metadata": attempt.request_metadata, **changes,
        }

    def _remote_result(self):
        return {"success": True, "payment_intent_id": "pi_gift_attempt", "client_secret": "secret", "error": None}

    def test_request_identity_is_durable_before_gateway_io(self) -> None:
        def create_remote(**kwargs):
            attempt = apps.get_model("promotions", "GiftCardFundingAttempt").objects.get(purchase=self.purchase)
            self.assertIsNotNone(attempt.first_submitted_at)
            self.assertEqual(attempt.amount_cents, 5000)
            self.assertEqual(attempt.currency_id, "RON")
            self.assertEqual(kwargs["idempotency_key"], attempt.idempotency_key)
            self.assertEqual(kwargs["metadata"]["gift_funding_attempt_id"], str(attempt.pk))
            return self._remote_result()

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.side_effect = create_remote
            result = start_funding(self.purchase)

        self.assertTrue(result["success"])

    def test_refresh_before_payment_start_returns_a_controlled_validation_error(self) -> None:
        with self.assertRaisesMessage(ValidationError, "Start the payment"):
            refresh_funding(self.purchase.pk)

    def test_unbound_uncertain_retry_reuses_identity_then_stops_before_key_expiry(self) -> None:
        first_time = timezone.now()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = {
                "success": False, "payment_intent_id": "", "client_secret": None, "error": "Response unavailable"
            }
            with patch("django.utils.timezone.now", return_value=first_time):
                start_funding(self.purchase)
            with patch("django.utils.timezone.now", return_value=first_time + timedelta(hours=22)):
                start_funding(self.purchase)
            first, second = factory.return_value.create_payment_intent.call_args_list
            self.assertEqual(first.kwargs, second.kwargs)
            with (
                patch("django.utils.timezone.now", return_value=first_time + timedelta(hours=23)),
                self.assertRaises(ValidationError),
            ):
                start_funding(self.purchase)
            self.assertEqual(factory.return_value.create_payment_intent.call_count, 2)

    def test_bound_intent_is_retrieved_after_idempotency_window(self) -> None:
        first_time = timezone.now()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = self._remote_result()
            start_funding(self.purchase)
            factory.return_value.confirm_payment.return_value = self._facts()
            with patch("django.utils.timezone.now", return_value=first_time + timedelta(days=5)):
                result = start_funding(self.purchase)
            factory.return_value.create_payment_intent.assert_called_once()
            factory.return_value.confirm_payment.assert_called_once_with("pi_gift_attempt")
        self.assertTrue(result["success"])
        self.purchase.refresh_from_db()
        self.assertEqual(self.purchase.status, "funded")

    def test_early_decline_can_retry_the_same_intent_without_recurring_dunning(self) -> None:
        processor = StripeWebhookProcessor()

        def create_remote(**kwargs):
            succeeded, _message = processor.handle_payment_intent_event("payment_intent.payment_failed", {
                "data": {"object": {
                    "id": "pi_gift_attempt", "amount": 5000, "amount_received": 0, "currency": "ron",
                    "status": "requires_payment_method", "metadata": kwargs["metadata"],
                    "last_payment_error": {"message": "Declined"},
                }}
            })
            self.assertTrue(succeeded)
            return self._remote_result()

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.side_effect = create_remote
            start_funding(self.purchase)
        self.purchase.funding_payment.refresh_from_db()
        self.assertEqual(self.purchase.funding_payment.status, "pending")
        self.assertFalse(PaymentRetryAttempt.objects.exists())

        for _ in range(2):
            success, _message = processor.handle_payment_intent_event("payment_intent.succeeded", {
                "data": {"object": {"id": "pi_gift_attempt", **self._facts()}}
            })
            self.assertTrue(success)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.current_balance_cents, 5000)
        self.assertEqual(GiftCardTransaction.objects.filter(transaction_type="activation").count(), 1)

    def test_provider_amount_currency_and_attempt_identity_must_match(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = self._remote_result()
            start_funding(self.purchase)
        processor = StripeWebhookProcessor()
        for changed in ({"amount_received": 4999}, {"currency": "eur"}, {"metadata": {}}):
            with self.subTest(changed=changed):
                success, _message = processor.handle_payment_intent_event("payment_intent.succeeded", {
                    "data": {"object": {"id": "pi_gift_attempt", **self._facts(**changed)}}
                })
                self.assertFalse(success)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.current_balance_cents, 0)

    def test_all_original_currencies_fund_after_default_switch_without_conversion(self) -> None:
        purchases = [self.purchase]
        for code in ("EUR", "USD"):
            currency = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            FXRate.objects.create(
                base_code=currency, quote_code=self.currency, as_of=timezone.localdate(), rate=Decimal("5"),
                source="bnr", source_reference="https://bnr.ro/rate", fetched_at=timezone.now(),
            )
            purchases.append(create_purchase(self.customer, currency, 5000, code, actor=self.actor))
        SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertEqual(get_selling_currency_policy().currency_code, "EUR")
        for purchase in purchases:
            self.purchase = purchase
            code = purchase.gift_card.currency_id
            with self.subTest(currency=code), patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
                factory.return_value.create_payment_intent.return_value = {
                    "success": True, "payment_intent_id": f"pi_{code}", "client_secret": "test_secret", "error": None,
                }
                start_funding(purchase)
                self.assertEqual(factory.return_value.create_payment_intent.call_args.kwargs["currency"], code)
                self.assertEqual(factory.return_value.create_payment_intent.call_args.kwargs["amount_cents"], 5000)
                factory.return_value.confirm_payment.return_value = self._facts()
                self.assertTrue(refresh_funding(purchase.pk)["success"])
                purchase.gift_card.refresh_from_db()
                self.assertEqual((purchase.gift_card.currency_id, purchase.gift_card.current_balance_cents), (code, 5000))
