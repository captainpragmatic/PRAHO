"""Real PostgreSQL threads cannot reserve the same gift value twice."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase, start_funding
from apps.promotions.gift_funding import converge_gift_funding
from apps.promotions.gift_refunds import reserve_funding_refund
from apps.promotions.models import GiftCardFundingAttempt, GiftCardFundingRefund, GiftCardTransaction
from apps.users.models import User


@skipUnless(connection.vendor == "postgresql", "Gift financial row-lock verification requires PostgreSQL")
class GiftRefundConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        customer = Customer.objects.create(name="Concurrent gift buyer", customer_type="individual")
        self.staff = User.objects.create_user(email="concurrent-staff@example.test", staff_role="billing")
        self.purchase = create_purchase(customer, currency, 5000, "concurrent")
        payment = self.purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_concurrent_gift"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        activate_verified_purchase(self.purchase.pk)

    def _run_competitors(self, keys, amount):
        barrier = Barrier(2)

        def reserve(key):
            close_old_connections()
            try:
                staff = User.objects.get(pk=self.staff.pk)
                barrier.wait(timeout=5)
                try:
                    refund = reserve_funding_refund(self.purchase.pk, amount, key, actor=staff)
                except ValidationError:
                    return "rejected"
                return str(refund.pk)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, keys))
        self.purchase.gift_card.refresh_from_db()
        return results

    def test_competing_refunds_cannot_overreserve_the_balance(self) -> None:
        results = self._run_competitors(["first", "second"], 3000)
        self.assertEqual(results.count("rejected"), 1)
        self.assertEqual(GiftCardFundingRefund.objects.count(), 1)
        self.assertEqual(self.purchase.gift_card.refund_held_cents, 3000)

    def test_concurrent_exact_replay_reuses_the_same_full_balance_hold(self) -> None:
        results = self._run_competitors(["same", "same"], 5000)
        self.assertNotIn("rejected", results)
        self.assertEqual(results[0], results[1])
        self.assertEqual(GiftCardFundingRefund.objects.count(), 1)
        self.assertEqual(self.purchase.gift_card.refund_held_cents, 5000)

    def test_concurrent_funding_commits_one_identity_before_io_and_activates_once(self) -> None:
        purchase = create_purchase(self.purchase.customer, self.purchase.gift_card.currency, 5000, "funding-race")
        requests = []
        remote_barrier = Barrier(2)

        def remote_create(**kwargs):
            self.assertFalse(connection.in_atomic_block)
            attempt = GiftCardFundingAttempt.objects.get(purchase=purchase)
            self.assertEqual(kwargs["metadata"]["gift_funding_attempt_id"], str(attempt.pk))
            self.assertIsNotNone(attempt.first_submitted_at)
            requests.append(kwargs)
            remote_barrier.wait(timeout=5)
            return {"success": True, "payment_intent_id": "pi_race", "client_secret": "test_secret", "error": None}

        def fund(_index):
            close_old_connections()
            try:
                return start_funding(purchase)
            finally:
                close_old_connections()

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.side_effect = remote_create
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(fund, [1, 2]))
        self.assertTrue(all(result["success"] for result in results))
        self.assertEqual(requests[0], requests[1])
        self.assertEqual(GiftCardFundingAttempt.objects.filter(purchase=purchase).count(), 1)
        facts = {"status": "succeeded", "amount": 5000, "amount_received": 5000,
                 "currency": "ron", "metadata": requests[0]["metadata"]}
        settle_barrier = Barrier(2)

        def settle(_index):
            close_old_connections()
            try:
                settle_barrier.wait(timeout=5)
                return converge_gift_funding("pi_race", facts).is_ok()
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(settle, [1, 2])), [True, True])
        purchase.gift_card.refresh_from_db()
        self.assertEqual(purchase.gift_card.current_balance_cents, 5000)
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=purchase.gift_card, transaction_type="activation").count(), 1)
