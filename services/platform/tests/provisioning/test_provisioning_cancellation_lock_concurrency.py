"""Public provisioning and immediate cancellation must agree on customer/service lock order."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from threading import Event
from time import monotonic
from typing import TypeVar
from unittest import skipUnless

from django.core.cache import cache
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionService
from apps.customers.models import Customer
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_tasks import provision_virtualmin_account
from apps.users.models import User

_T = TypeVar("_T")


@skipUnless(connection.vendor == "postgresql", "Real PostgreSQL row locking and deadlock detection are required")
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "provisioning-lock-order", "orm": "default", "sync": False, "timeout": 60, "retry": 120},
)
class ProvisioningCancellationLockConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.locking_queries: dict[int, str] = {}
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(name="Cancellation buyer", primary_email="cancel-lock@example.test")
        plan = ServicePlan.objects.create(
            name="Lock-order hosting", plan_type="shared_hosting", price_monthly=Decimal(9)
        )
        product = Product.objects.create(
            slug="cancellation-lock-hosting", name="Hosting", product_type="shared_hosting", default_service_plan=plan
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=currency,
            service_name="cancel-lock.example.com",
            domain="cancel-lock.example.com",
            username="cancellock",
            billing_cycle="monthly",
            price=Decimal(9),
            status="active",
            auto_renew=True,
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            service=self.service,
            currency=currency,
            subscription_number="SUB-CANCELLATION-LOCK",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=900,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )
        server = VirtualminServer.objects.create(
            name="Existing hosting", hostname="existing-node.example.test", api_username="praho-acl", status="active"
        )
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            server=server,
            domain=self.service.domain,
            virtualmin_username="cancellock",
            template_name="Default",
            status="active",
            praho_customer_id=self.customer.pk,
            praho_service_id=self.service.pk,
        )

    def _provision(self) -> dict[str, object]:
        return provision_virtualmin_account({"service_id": self.service.pk, "domain": self.service.domain})

    def test_active_existing_account_returns_its_public_result_and_idempotent_replay(self) -> None:
        result = self._provision()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["account_id"], str(self.account.pk))
        self.assertEqual(result["message"], "Account already exists")
        self.assertEqual(self._provision(), result)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)

    def test_immediate_cancellation_alone_expires_service_and_inactive_tasks_release_idempotency(self) -> None:
        result = SubscriptionService.cancel_subscription(self.subscription, at_period_end=False)
        self.assertTrue(result.is_ok(), result)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "expired")
        self.assertFalse(self.service.auto_renew)
        first = self._provision()
        self.assertFalse(first["success"], first)
        self.assertIn("not active (status: expired)", first["error"])
        self.assertEqual(self._provision(), first)

    def _worker(self, action: Callable[[], _T], ready: Event, pids: list[int]) -> _T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()

            def observe(execute, sql, params, many, context):
                if "FOR UPDATE" in sql or "FOR NO KEY UPDATE" in sql:
                    self.locking_queries[pids[0]] = sql
                return execute(sql, params, many, context)

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _wait_for_lock(self, pid: int, owner_pid: int, pending: Future[_T], table: str) -> None:
        deadline, poll = monotonic() + 10, Event()
        row = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and owner_pid in row[1]:
                # pg_stat_activity truncates queries at the server's configured
                # track_activity_query_size; observe the full real SQL before I/O.
                self.assertIn(table, self.locking_queries[pid])
                self.assertTrue(row[2].startswith("SELECT"), row)
                return
            if pending.done():
                self.fail(f"Public task finished before its genuine lock wait: {pending.result()!r}")
            poll.wait(0.01)
        self.fail(f"Public task never waited: pid={pid}, owner={owner_pid}, last_sample={row!r}")

    def test_immediate_cancellation_winning_customer_lock_prevents_provisioning_without_deadlock(self) -> None:
        locked, release = Event(), Event()
        customer_table = connection.ops.quote_name(Customer._meta.db_table)

        def cancel() -> object:
            def observe(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if "FOR NO KEY UPDATE" in sql and customer_table in sql:
                    locked.set()
                    self.assertTrue(release.wait(10), "Observer did not release the real cancellation lock")
                return result

            with connection.execute_wrapper(observe):
                return SubscriptionService.cancel_subscription(self.subscription, at_period_end=False)

        with ThreadPoolExecutor(max_workers=2) as executor:
            cancel_ready, task_ready = Event(), Event()
            cancel_pids: list[int] = []
            task_pids: list[int] = []
            cancellation = executor.submit(self._worker, cancel, cancel_ready, cancel_pids)
            try:
                self.assertTrue(cancel_ready.wait(10))
                self.assertTrue(locked.wait(10), "Cancellation never acquired its production Customer lock")
                task = executor.submit(self._worker, self._provision, task_ready, task_pids)
                self.assertTrue(task_ready.wait(10))
                self._wait_for_lock(task_pids[0], cancel_pids[0], task, self.customer._meta.db_table)
            finally:
                release.set()
            cancel_result, task_result = cancellation.result(timeout=25), task.result(timeout=25)

        self.assertTrue(cancel_result.is_ok(), f"cancel={cancel_result!r}, task={task_result!r}")
        self.assertNotIn("deadlock detected", str(task_result).lower(), task_result)
        self.assertFalse(task_result["success"], task_result)
        self.assertIn("not active (status: expired)", task_result["error"])
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "cancelled")
        self.assertEqual(self.service.status, "expired")
        self.assertFalse(self.service.auto_renew)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).pk, self.account.pk)
        # Validation refusal clears the real idempotency claim, allowing another
        # public call to revalidate rather than remaining permanently in progress.
        self.assertEqual(self._provision(), task_result)

    def test_provisioning_winning_customer_lock_returns_existing_account_before_cancellation(self) -> None:
        locked, release = Event(), Event()
        customer_table = connection.ops.quote_name(Customer._meta.db_table)

        def provision() -> dict[str, object]:
            def observe(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if "FOR UPDATE" in sql and customer_table in sql:
                    locked.set()
                    self.assertTrue(release.wait(10), "Observer did not release the real provisioning lock")
                return result

            with connection.execute_wrapper(observe):
                return self._provision()

        with ThreadPoolExecutor(max_workers=2) as executor:
            task_ready, cancel_ready = Event(), Event()
            task_pids: list[int] = []
            cancel_pids: list[int] = []
            task = executor.submit(self._worker, provision, task_ready, task_pids)
            try:
                self.assertTrue(task_ready.wait(10))
                self.assertTrue(locked.wait(10), "Provisioning never acquired its actual Customer lock")
                cancellation = executor.submit(
                    self._worker,
                    lambda: SubscriptionService.cancel_subscription(self.subscription, at_period_end=False),
                    cancel_ready,
                    cancel_pids,
                )
                self.assertTrue(cancel_ready.wait(10))
                self._wait_for_lock(cancel_pids[0], task_pids[0], cancellation, self.customer._meta.db_table)
            finally:
                release.set()
            task_result, cancel_result = task.result(timeout=25), cancellation.result(timeout=25)

        self.assertTrue(task_result["success"], task_result)
        self.assertEqual(task_result["account_id"], str(self.account.pk))
        self.assertEqual(task_result["message"], "Account already exists")
        self.assertTrue(cancel_result.is_ok(), cancel_result)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "cancelled")
        self.assertEqual(self.service.status, "expired")
        self.assertFalse(self.service.auto_renew)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)

    def test_staff_owner_change_after_routing_hint_refuses_stale_customer(self) -> None:
        new_customer = Customer.objects.create(name="Current owner", primary_email="current-owner@example.test")
        staff = User.objects.create_superuser(email="lock-editor@example.test", password="test-only")
        self.client.force_login(staff)
        hint_read, release = Event(), Event()
        table = connection.ops.quote_name(Service._meta.db_table)

        def provision() -> dict[str, object]:
            def observe(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if sql.startswith("SELECT") and table in sql and "FOR UPDATE" not in sql and not hint_read.is_set():
                    hint_read.set()
                    self.assertTrue(release.wait(10), "Observer did not release the real customer routing read")
                return result

            with connection.execute_wrapper(observe):
                return self._provision()

        with ThreadPoolExecutor(max_workers=1) as executor:
            ready, pids = Event(), []
            task = executor.submit(self._worker, provision, ready, pids)
            try:
                self.assertTrue(ready.wait(10))
                self.assertTrue(hint_read.wait(10), "Public task did not read its routing hint")
                response = self.client.post(
                    f"/provisioning/services/{self.service.pk}/edit/",
                    {
                        "customer_id": new_customer.pk,
                        "plan_id": self.service.service_plan_id,
                        "domain": self.service.domain,
                    },
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(Service.objects.get(pk=self.service.pk).customer_id, new_customer.pk)
            finally:
                release.set()
            result = task.result(timeout=25)

        self.assertEqual(result, {"success": False, "error": "Service customer changed during provisioning"})
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).service_id, self.service.pk)
        # The refusal releases idempotency; a new call can lock the current owner.
        self.assertEqual(self._provision()["account_id"], str(self.account.pk))
