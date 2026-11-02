"""The public fulfiller uses a staff plan edit committed during its actual PostgreSQL lock wait."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal
from threading import Event
from time import monotonic
from typing import TypeVar
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.cache import cache
from django.db import close_old_connections, connection, connections
from django.test import RequestFactory, TransactionTestCase, override_settings

from apps.billing.models import Currency
from apps.common.types import Result
from apps.customers.models import Customer
from apps.orders.hosting_fulfilment import complete_line_for_staff, fulfil_hosting_line
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.service_views import service_edit
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status

_T = TypeVar("_T")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL UPDATE and row-lock visibility are required")
@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class HostingPlanLockConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("django_q.tasks.async_task"))
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(name="Plan Race Buyer", primary_email="plan-race@example.test")
        self.staff = User.objects.create_superuser(email="plan-editor@example.test", password="test-only")
        self.hosting_plan = ServicePlan.objects.create(
            name="Automatic hosting", plan_type="shared_hosting", price_monthly=Decimal("9")
        )
        self.manual_plan = ServicePlan.objects.create(
            name="Staff-delivered email", plan_type="email", price_monthly=Decimal("9")
        )
        product = Product.objects.create(
            slug="plan-race", name="Hosting", product_type="shared_hosting", default_service_plan=self.hosting_plan
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address={},
            total_cents=900,
            subtotal_cents=900,
        )
        force_status(self.order, "provisioning")
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.hosting_plan,
            currency=self.currency,
            service_name="plan-race.example.test",
            domain="plan-race.example.test",
            username="planrace",
            billing_cycle="monthly",
            price=Decimal("9"),
            status="active",
        )
        self.line = OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name=product.name,
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=900,
            line_total_cents=900,
            service=self.service,
            config={"billing_period": "monthly"},
        )

    def _edit_plan(self, plan_id: int) -> int:
        # The production view's unchanged-owner save is an autocommit UPDATE.
        # Do not manufacture a surrounding application transaction for this proof.
        self.assertTrue(connection.get_autocommit())
        request = RequestFactory().post(
            "/provisioning/services/edit/",
            {"customer_id": self.customer.pk, "plan_id": plan_id, "domain": self.service.domain},
        )
        request.user = User.objects.get(pk=self.staff.pk)
        request.session = {}
        request._messages = FallbackStorage(request)
        return service_edit(request, self.service.pk).status_code

    def _worker(self, action: Callable[[], _T], ready: Event, pids: list[int]) -> _T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            return action()
        finally:
            connections.close_all()

    def _wait_for_lock(self, pid: int, owner_pid: int, pending: Future[_T], query_fragment: str) -> None:
        deadline, poll = monotonic() + 10, Event()
        row = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                row = cursor.fetchone()
            # Activity and lock-manager samples can straddle entry into the wait.
            if row and row[0] == "Lock" and owner_pid in row[1]:
                self.assertIn(query_fragment, row[2])
                return
            if pending.done():
                self.fail(f"Public operation finished before reaching its SQL lock: {pending.result()}")
            poll.wait(0.01)
        self.fail(f"Public operation did not reach its SQL lock: pid={pid}, owner={owner_pid}, last_sample={row!r}")

    def _after_plan_edit(self, plan: ServicePlan, action: Callable[[], Result[str, str]]) -> Result[str, str]:
        self.line.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "pending")
        self.assertNotEqual(self.service.service_plan_id, plan.pk)
        suffix, key = uuid4().hex, uuid4().int % 2_147_483_647
        function = connection.ops.quote_name(f"hosting_plan_wait_{suffix}")
        trigger = connection.ops.quote_name(f"hosting_plan_wait_{suffix}_row")
        table = connection.ops.quote_name(Service._meta.db_table)
        with connection.cursor() as cursor:
            cursor.execute(
                f"CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ "
                f"BEGIN IF NEW.id = {self.service.pk} THEN PERFORM pg_advisory_xact_lock({key}); "
                "END IF; RETURN NEW; END $$"
            )
            cursor.execute(
                f"CREATE TRIGGER {trigger} AFTER UPDATE OF service_plan_id ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()"
            )
            cursor.execute("SELECT pg_advisory_lock(%s), pg_backend_pid()", [key])
            observer_pid = cursor.fetchone()[1]
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                writer_ready, reader_ready = Event(), Event()
                writer_pids: list[int] = []
                reader_pids: list[int] = []
                writer = executor.submit(self._worker, lambda: self._edit_plan(plan.pk), writer_ready, writer_pids)
                try:
                    self.assertTrue(writer_ready.wait(10), "Staff edit connection did not start")
                    # This native AFTER UPDATE latch changes no data. It pauses the
                    # real view's SQL after mutation, before that statement commits.
                    self._wait_for_lock(writer_pids[0], observer_pid, writer, f"UPDATE {table}")
                    reader = executor.submit(self._worker, action, reader_ready, reader_pids)
                    self.assertTrue(reader_ready.wait(10), "Fulfilment connection did not start")
                    self._wait_for_lock(reader_pids[0], writer_pids[0], reader, table)
                finally:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_advisory_unlock(%s)", [key])
                self.assertEqual(writer.result(timeout=25), 302)
                return reader.result(timeout=25)
        finally:
            with connection.cursor() as cursor:
                cursor.execute(f"DROP TRIGGER {trigger} ON {table}")
                cursor.execute(f"DROP FUNCTION {function}()")

    def _assert_classification(self, plan: ServicePlan, expected: str) -> None:
        result = self._after_plan_edit(plan, lambda: fulfil_hosting_line(self.line.pk))
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), expected)
        self.line.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "in_progress")
        self.assertEqual(self.service.service_plan_id, plan.pk)
        self.assertEqual(self.service.customer_id, self.customer.pk)
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), expected)

    def test_hosting_changed_to_manual_during_wait_is_left_for_staff(self) -> None:
        self._assert_classification(self.manual_plan, "left_for_staff")

    def test_manual_changed_to_hosting_during_wait_uses_automatic_fulfilment(self) -> None:
        self.service.service_plan = self.manual_plan
        self.service.save(update_fields=["service_plan"])
        self._assert_classification(self.hosting_plan, "in_progress")

    def test_staff_completion_survives_a_plan_change_during_its_wait(self) -> None:
        result = self._after_plan_edit(
            self.manual_plan,
            lambda: complete_line_for_staff(self.line.pk, actor=self.staff, activate_service=False),
        )
        self.assertEqual(result.unwrap(), "completed")
        self.line.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "completed")
        self.assertIsNotNone(self.line.provisioned_at)
