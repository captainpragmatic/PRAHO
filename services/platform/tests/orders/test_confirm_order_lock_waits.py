"""Protected confirmation controls stay identical after real waits in either API phase."""

from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings

from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Invoice, InvoiceSequence
from apps.orders.models import Order
from apps.users.models import CustomerMembership, User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin
from tests.orders import test_confirm_order_concurrency as fixtures


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL confirmation lock waits")
@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ConfirmOrderLockWaitTests(BoundSessionMixin, HMACTestMixin, TransactionTestCase):
    _create_order_with_proforma = fixtures.TestC2ConfirmOrderIdempotency._create_order_with_proforma

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("django_q.tasks.async_task", return_value="queued-confirmation"))
        fixtures.TestC2ConfirmOrderIdempotency.setUp(self)
        InvoiceSequence.objects.get_or_create(scope="subscription", defaults={"prefix": "SUB"})
        self.owner = User.objects.create_user(email="confirmation-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)

    def _waited_confirmation(self, phase: int) -> None:
        order, proforma = self._create_order_with_proforma()
        start, reached = Event(), Event()
        network_transactions = []

        def gateway(_intent):
            network_transactions.append(connection.in_atomic_block)
            return PaymentConfirmResult(success=True, status="succeeded", error=None,
                                        amount_received=order.total_cents, currency="ron")

        def confirm():
            lock_count = 0

            def pause(execute, sql, params, many, context):
                nonlocal lock_count
                if sql.startswith(f'SELECT "{Order._meta.db_table}"."id" AS "pk"') and "FOR UPDATE" in sql:
                    lock_count += 1
                    if lock_count == phase:
                        reached.set()
                        assert start.wait(15)
                return execute(sql, params, many, context)

            with connection.execute_wrapper(pause):
                return self.portal_post(f"/api/orders/{order.pk}/confirm/", {
                    "customer_id": self.customer.pk, "user_id": self.owner.pk,
                    "payment_intent_id": order.payment_intent_id,
                })

        owner_pid = backend_pid()
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.confirm_payment.side_effect = gateway
            with database_worker(confirm) as (pid, pending):
                try:
                    self.assertTrue(reached.wait(15), "Confirmation did not reach its audited API phase")
                    with transaction.atomic():
                        Order.objects.select_for_update(of=("self",)).get(pk=order.pk)
                        start.set()
                        wait_for_blocker(pid, owner_pid, pending, table=Order._meta.db_table)
                finally:
                    start.set()
                waited = pending.result(timeout=30)
            replay = self.portal_post(f"/api/orders/{order.pk}/confirm/", {
                "customer_id": self.customer.pk, "user_id": self.owner.pk,
                "payment_intent_id": order.payment_intent_id,
            })
        self.assertEqual(waited.status_code, 200, waited.content)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(waited.json()["status"], replay.json()["status"])
        self.assertEqual(network_transactions, [False])
        issued = Invoice.objects.get(converted_from_proforma=proforma)
        self.assertEqual((issued.total_cents, issued.currency_id), (12100, "RON"))

    def test_confirmation_waiting_in_phase_one_matches_uncontended_replay(self) -> None:
        self._waited_confirmation(1)

    def test_confirmation_waiting_in_phase_three_matches_uncontended_replay(self) -> None:
        self._waited_confirmation(2)
