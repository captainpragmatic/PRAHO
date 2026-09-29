"""Real PostgreSQL interleavings across signed checkout, price writes, and currency settings."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal
from threading import Event
from time import monotonic
from typing import Any
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.products.models import Product, ProductPrice
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@skipUnless(connection.vendor == "postgresql", "PostgreSQL lock visibility is required")
@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class SellingCurrencyConcurrencyTests(HMACTestMixin, TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Currency lock customer", primary_email="currency-lock@example.test", status="active"
        )
        self.user = User.objects.create_user(email="currency-lock@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.user, role="owner", is_primary=True)
        self.product = Product.objects.create(name="Currency lock hosting", slug="currency-lock-hosting")
        for code, cents in (("RON", 5000), ("EUR", 1000)):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            ProductPrice.objects.create(product=self.product, currency_id=code, monthly_price_cents=cents)
        FXRate.objects.create(
            base_code_id="EUR", quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
            source=FXRate.Source.BNR, source_reference="currency-lock-test", fetched_at=timezone.now(),
        )
        self.initial_policy = get_selling_currency_policy()

    def _create_order(self, key: str | None = None):
        return self.portal_post(
            "/api/orders/create/",
            {
                "customer_id": self.customer.pk,
                "user_id": self.user.pk,
                "currency": self.initial_policy.currency_code,
                "currency_revision": self.initial_policy.revision,
                "items": [{"product_id": str(self.product.pk), "quantity": 1, "billing_period": "monthly"}],
            },
            HTTP_IDEMPOTENCY_KEY=key or uuid4().hex,
        )

    @staticmethod
    def _switch():
        return SettingsService.update_setting("billing.default_currency", "EUR")

    def _assert_policy_wait(self, worker_pid: int, owner_pid: int, pending: Future[Any]) -> None:
        """Observe a real setting-row wait, rather than inferring one from elapsed time."""
        deadline = monotonic() + 8
        poll = Event()
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                # The observer is inside the primary transaction; refresh PostgreSQL's
                # statistics snapshot so query text cannot describe an earlier statement.
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [worker_pid]
                )
                row = cursor.fetchone()
            if row and owner_pid in row[0]:
                self.assertIn("setting_entries", row[1])
                self.assertIn("FOR UPDATE", row[1])
                return
            if pending.done():
                result = pending.result()
                self.fail(f"Competing operation completed without waiting for the selling-policy lock: {result}")
            poll.wait(0.01)
        self.fail("Competing operation never reached the selling-policy row lock")

    def _interleave(
        self, primary: Callable[[], Any], competitor: Callable[[], Any], boundary: Callable[[str], bool]
    ) -> tuple[Any, Any]:
        """Pause the real primary path after its SQL boundary, until PostgreSQL observes the competing wait."""
        ready = Event()
        start_competitor = Event()
        worker_pids: list[int] = []

        def run_competitor():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '10s'")
                    cursor.execute("SET statement_timeout = '15s'")
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pids.append(cursor.fetchone()[0])
                ready.set()
                if not start_competitor.wait(10):
                    raise AssertionError("Primary operation never reached the expected SQL boundary")
                return competitor()
            finally:
                connections.close_all()

        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            owner_pid = cursor.fetchone()[0]
        reached = False
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(run_competitor)
            self.assertTrue(ready.wait(10), "Competing database connection did not start")

            def hold_at_boundary(execute, sql, params, many, context):
                nonlocal reached
                result = execute(sql, params, many, context)
                if not reached and boundary(sql):
                    reached = True
                    start_competitor.set()
                    self._assert_policy_wait(worker_pids[0], owner_pid, pending)
                return result

            try:
                with connection.execute_wrapper(hold_at_boundary):
                    primary_result = primary()
            finally:
                start_competitor.set()
            self.assertTrue(reached, "Primary operation skipped the intended business write/lock")
            competing_result = pending.result(timeout=15)
        return primary_result, competing_result

    def test_signed_order_commits_original_money_before_waiting_currency_switch(self) -> None:
        key = uuid4().hex
        response, switched = self._interleave(
            lambda: self._create_order(key), self._switch,
            lambda sql: 'INSERT INTO "orders"' in sql,
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertIsInstance(switched, Ok)
        policy = get_selling_currency_policy()
        self.assertEqual((policy.currency_code, policy.revision), ("EUR", self.initial_policy.revision + 1))
        order = Order.objects.get(pk=response.json()["order"]["id"])
        self.assertEqual((order.currency_id, order.subtotal_cents), ("RON", 5000))
        self.assertEqual(order.items.get().unit_price_cents, 5000)
        retry = self._create_order(key)
        self.assertEqual(retry.status_code, 200, retry.content)
        self.assertEqual(retry.json()["order"]["id"], str(order.pk))
        self.assertEqual(Order.objects.count(), 1)

    def test_signed_order_waiting_for_switch_rejects_original_revision(self) -> None:
        switched, response = self._interleave(
            self._switch, self._create_order,
            lambda sql: '"setting_entries"' in sql and "FOR UPDATE" in sql,
        )
        self.assertIsInstance(switched, Ok)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["code"], "currency_changed")
        self.assertEqual(response.json()["selling_currency"], "EUR")
        self.assertEqual(response.json()["currency_revision"], self.initial_policy.revision + 1)
        self.assertFalse(Order.objects.exists())

    def test_waiting_retry_recovers_the_original_order_committed_with_a_policy_switch(self) -> None:
        key = uuid4().hex

        def accept_and_switch():
            with transaction.atomic():
                accepted = self._create_order(key)
                self.assertEqual(accepted.status_code, 201, accepted.content)
                self.assertIsInstance(self._switch(), Ok)
                return accepted

        with patch("django_q.tasks.async_task"):
            accepted, retried = self._interleave(
                accept_and_switch, lambda: self._create_order(key),
                lambda sql: 'INSERT INTO "orders"' in sql,
            )

        self.assertEqual(retried.status_code, 200, retried.content)
        self.assertEqual(retried.json()["order"]["id"], accepted.json()["order"]["id"])
        self.assertEqual(Order.objects.count(), 1)
        self.assertEqual(Order.objects.get().currency_id, "RON")
        self.assertEqual(get_selling_currency_policy().currency_code, "EUR")

    def _price_availability_race(self, *, activate: bool) -> Any:
        price = ProductPrice.objects.get(product=self.product, currency_id="EUR")
        price.is_active = not activate
        price.save(update_fields=["is_active", "updated_at"])

        def write_price() -> None:
            price.is_active = activate
            price.save(update_fields=["is_active", "updated_at"])

        _written, switched = self._interleave(
            write_price, self._switch,
            lambda sql: sql.startswith('UPDATE "product_prices"'),
        )
        price.refresh_from_db()
        self.assertEqual(price.is_active, activate)
        return switched

    def test_switch_waits_for_committed_target_price_deactivation_and_refuses(self) -> None:
        switched = self._price_availability_race(activate=False)
        self.assertIsInstance(switched, Err)
        self.assertIn(self.product.name, switched.error.message)
        self.assertIn("EUR", switched.error.message)
        self.assertEqual(get_selling_currency_policy(), self.initial_policy)

    def test_switch_waits_for_committed_target_price_activation_and_succeeds(self) -> None:
        switched = self._price_availability_race(activate=True)
        self.assertIsInstance(switched, Ok)
        policy = get_selling_currency_policy()
        self.assertEqual((policy.currency_code, policy.revision), ("EUR", self.initial_policy.revision + 1))
