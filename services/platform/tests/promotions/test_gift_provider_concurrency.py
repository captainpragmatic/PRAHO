"""Real PostgreSQL workers commit claims/holds before mocked external I/O."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch

from django.core import mail
from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase
from apps.promotions.gift_delivery import _message, deliver_gift_card
from apps.promotions.gift_refunds import converge_gift_refund, refund_purchase
from apps.promotions.models import GiftCardFundingRefund, GiftCardTransaction
from apps.users.models import User


@skipUnless(connection.vendor == "postgresql", "Gift provider concurrency requires real PostgreSQL row locks")
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class GiftProviderConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        queue = patch("django_q.tasks.async_task")
        queue.start()
        self.addCleanup(queue.stop)
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        customer = Customer.objects.create(name="Concurrent buyer", primary_email="buyer@example.test")
        self.staff = User.objects.create_user(email="staff@example.test", staff_role="billing")
        self.purchase = create_purchase(customer, currency, 5000, "concurrent-provider", buyer_email="buyer@example.test")
        payment = self.purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_concurrent_provider"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        self.purchase = activate_verified_purchase(self.purchase.pk)

    def _facts(self, refund, status="succeeded"):
        return {
            "success": True, "refund_id": "re_concurrent_provider", "payment_intent_id": "pi_concurrent_provider",
            "amount_cents": 3000, "currency": "ron", "status": status,
            "metadata": {"gift_refund_id": str(refund.pk)},
        }

    def test_two_refund_requests_commit_one_hold_and_exact_provider_identity_before_io(self) -> None:
        barrier = Barrier(2)
        requests = []

        def remote(*args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
            self.assertIsNotNone(refund.first_submitted_at)
            self.assertEqual(refund.funding_intent_id, "pi_concurrent_provider")
            self.assertEqual(kwargs["metadata"], {"gift_refund_id": str(refund.pk)})
            self.purchase.gift_card.refresh_from_db()
            self.assertEqual(self.purchase.gift_card.refund_held_cents, 3000)
            requests.append((args, kwargs))
            barrier.wait(timeout=10)
            return {"success": True, "refund_id": "re_concurrent_provider"}

        def run(_index):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.staff.pk)
                return refund_purchase(self.purchase.pk, 3000, "same-request", actor=actor).pk
            finally:
                close_old_connections()

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = remote
            factory.return_value.retrieve_refund.side_effect = lambda _: self._facts(
                GiftCardFundingRefund.objects.get(purchase=self.purchase)
            )
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(run, [1, 2]))
        self.assertEqual(results[0], results[1])
        self.assertEqual(requests[0], requests[1])
        self.assertEqual(GiftCardFundingRefund.objects.count(), 1)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual((self.purchase.gift_card.current_balance_cents, self.purchase.gift_card.refund_held_cents), (2000, 0))
        self.assertEqual(GiftCardTransaction.objects.filter(operation_key=f"funding-refund:{results[0]}").count(), 1)

    def test_concurrent_delivery_workers_send_once_and_do_not_hold_database_locks(self) -> None:
        voucher = self.purchase.deliveries.get(purpose="voucher")
        sending, release = Event(), Event()

        def remote(*args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            sending.set()
            self.assertTrue(release.wait(timeout=10))
            return 1

        def run():
            close_old_connections()
            try:
                return deliver_gift_card(voucher.pk)
            finally:
                close_old_connections()

        with patch("django.core.mail.EmailMessage.send", side_effect=remote) as send, ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run)
            try:
                self.assertTrue(sending.wait(timeout=10))
                self.assertFalse(pool.submit(run).result(timeout=10))
            finally:
                release.set()
            self.assertTrue(first.result(timeout=10))
        self.assertEqual(send.call_count, 1)
        voucher.refresh_from_db()
        self.assertEqual((voucher.status, voucher.attempt_count), ("sent", 1))

    def test_worker_crash_after_acceptance_recovers_same_code_without_new_value(self) -> None:
        voucher = self.purchase.deliveries.get(purpose="voucher")

        def accepted_then_crashed(delivery, purchase):
            _message(delivery, purchase).send()
            raise SystemExit("simulated worker stop")

        with patch("apps.promotions.gift_delivery._send", side_effect=accepted_then_crashed), self.assertRaises(SystemExit):
            deliver_gift_card(voucher.pk)
        self.assertEqual(len(mail.outbox), 1)
        self.assertFalse(deliver_gift_card(voucher.pk))
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(minutes=11)):
            self.assertTrue(deliver_gift_card(voucher.pk))
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[0].body, mail.outbox[1].body)
        self.assertIn(self.purchase.gift_card.code, mail.outbox[1].body)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.current_balance_cents, 5000)

    def test_success_callback_wins_over_a_stale_pending_retrieval(self) -> None:
        def retrieve(_identity):
            refund = GiftCardFundingRefund.objects.get(purchase=self.purchase)
            self.assertTrue(converge_gift_refund(self._facts(refund)).is_ok())
            return self._facts(refund, "pending")

        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {"success": True, "refund_id": "re_concurrent_provider"}
            factory.return_value.retrieve_refund.side_effect = retrieve
            refund = refund_purchase(self.purchase.pk, 3000, "callback-wins", actor=self.staff)
        self.assertEqual((refund.status, refund.applied_cents, refund.held_cents), ("succeeded", 3000, 0))
