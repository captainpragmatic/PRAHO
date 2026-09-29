"""Durable gift funding recovery uses existing, immutable payment attempts."""

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.gift_cards import create_purchase, start_funding
from apps.promotions.models import GiftCardFundingAttempt, GiftCardTransaction
from apps.promotions.tasks import reconcile_gift_funding, setup_gift_scheduled_tasks


class GiftFundingTaskTests(TestCase):
    def setUp(self) -> None:
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        customer = Customer.objects.create(name="Recovery buyer", customer_type="individual")
        self.purchase = create_purchase(customer, currency, 5000, "recovery")

    def _prepare(self, *, bound=True, at=None):
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = {
                "success": bound, "payment_intent_id": "pi_recovery" if bound else "", "client_secret": None,
            }
            with patch("django.utils.timezone.now", return_value=at or timezone.now()):
                start_funding(self.purchase)
        return GiftCardFundingAttempt.objects.get(purchase=self.purchase)

    def test_bound_success_is_recovered_and_activated_only_once(self) -> None:
        attempt = self._prepare()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.confirm_payment.return_value = {
                "success": True, "status": "succeeded", "amount": 5000, "amount_received": 5000,
                "currency": "ron", "metadata": attempt.request_metadata,
            }
            first = reconcile_gift_funding()
            second = reconcile_gift_funding()
            factory.return_value.create_payment_intent.assert_not_called()
            factory.return_value.confirm_payment.assert_called_once_with("pi_recovery")
        self.assertEqual((first["checked"], first["funded"], second["checked"]), (1, 1, 0))
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.current_balance_cents, 5000)
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=self.purchase.gift_card, transaction_type="activation").count(), 1)

    def test_uncertain_unbound_request_recovers_with_original_key_and_metadata(self) -> None:
        attempt = self._prepare(bound=False)
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = {
                "success": True, "payment_intent_id": "pi_recovered", "client_secret": "test_secret",
            }
            result = reconcile_gift_funding()
            self.assertEqual(factory.return_value.create_payment_intent.call_args.kwargs, {
                "order_id": str(self.purchase.pk), "amount_cents": 5000, "currency": "RON",
                "metadata": attempt.request_metadata, "idempotency_key": attempt.idempotency_key,
            })
        self.assertEqual(result["checked"], 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.gateway_intent_id, "pi_recovered")

    def test_expired_uncertain_request_is_held_for_review_without_provider_io(self) -> None:
        attempt = self._prepare(bound=False, at=timezone.now() - timedelta(hours=24))
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            result = reconcile_gift_funding()
            factory.assert_not_called()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, "needs_review")
        self.assertEqual(result["needs_review"], 1)

    def test_unavailable_provider_is_retained_and_not_immediately_repolled(self) -> None:
        self._prepare()
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.confirm_payment.return_value = {"success": False}
            first = reconcile_gift_funding()
            second = reconcile_gift_funding()
            factory.return_value.confirm_payment.assert_called_once()
        self.assertEqual((first["checked"], second["checked"]), (1, 0))
        self.assertEqual(len(first["errors"]), 1)
        self.purchase.refresh_from_db()
        self.assertIsNone(self.purchase.funded_at)

    def test_schedule_registration_is_idempotent(self) -> None:
        setup_gift_scheduled_tasks()
        setup_gift_scheduled_tasks()
        schedule = Schedule.objects.get(name="gift-funding-reconciliation")
        self.assertEqual(schedule.func, "apps.promotions.tasks.reconcile_gift_funding")
        self.assertEqual(schedule.cron, "*/10 * * * *")

    def test_billing_setup_registers_gift_recovery_even_if_renewal_guard_fails(self) -> None:
        with (
            patch("apps.common.management.commands.setup_scheduled_tasks.setup_billing_scheduled_tasks",
                  side_effect=RuntimeError("Unmanaged renewal fixture")),
            self.assertRaises(CommandError),
        ):
            call_command("setup_scheduled_tasks", "--billing-only", stdout=StringIO(), stderr=StringIO())
        self.assertTrue(Schedule.objects.filter(name="gift-funding-reconciliation").exists())
