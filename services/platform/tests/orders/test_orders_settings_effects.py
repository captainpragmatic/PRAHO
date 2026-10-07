"""Runtime order settings change enforcement and queued task budgets."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.core.paginator import Page
from django.db import connection, transaction
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django_q.brokers.orm import ORM
from django_q.conf import Conf
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.audit.models import AuditAlert
from apps.billing.models import Currency, Invoice, Payment
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.tasks import (
    generate_invoice_for_order_async,
    process_pending_orders,
    process_pending_orders_async,
    provision_order_item_async,
    sync_order_payment_status,
    sync_order_payment_status_async,
)
from apps.orders.views import _sanitize_search_query, order_list, order_list_htmx
from apps.products.models import Product
from apps.provisioning.models import ServicePlan
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status

PAYMENT_FAILURES_KEY = "orders.max_payment_failures_before_fail"
SEARCH_LENGTH_KEY = "orders.max_search_query_length"
TASK_LIMIT_KEY = "orders.task_time_limit"
REGISTRATION_KEY = "security.registration_rate_limit_per_ip"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "wp18-orders"}}
CONFIGURED = {PAYMENT_FAILURES_KEY: 1, SEARCH_LENGTH_KEY: 5, TASK_LIMIT_KEY: 17, REGISTRATION_KEY: 1}


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class OrdersSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Orders settings", company_name="Orders settings", primary_email="orders@example.test"
        )
        self.product = Product.objects.create(
            name="Settings item",
            slug="settings-item",
            product_type="vps",
            default_service_plan=ServicePlan.objects.create(
                name="Settings plan", plan_type="vps", price_monthly=Decimal("1.00")
            ),
        )

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def order(self, *, total: int = 100, invoice_status: str | None = None) -> Order:
        invoice = None
        if invoice_status is not None:
            invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, total_cents=total)
            force_status(invoice, invoice_status)
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total,
            total_cents=total,
            payment_method="card",
        )
        force_status(order, "awaiting_payment")
        return order

    def failed_payment(self, order: Order, *, hours_old: int = 0) -> Payment:
        payment = Payment.objects.create(
            customer=self.customer, invoice=order.invoice, currency=self.currency, amount_cents=order.total_cents
        )
        force_status(payment, "failed")
        if hours_old:
            Payment.objects.filter(pk=payment.pk).update(created_at=timezone.now() - timedelta(hours=hours_old))
        return payment

    def item(self, order: Order) -> OrderItem:
        return OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=order.total_cents,
            tax_rate=Decimal("0"),
            line_total_cents=order.total_cents,
        )

    def test_payment_failure_setting_changes_the_sync_threshold_and_keeps_the_window_and_paid_guard(self) -> None:
        self.set_value(PAYMENT_FAILURES_KEY, 1)
        unpaid = self.order(invoice_status="issued")
        stale = self.order(invoice_status="issued")
        paid = self.order(invoice_status="paid")
        force_status(paid, "paid")
        self.failed_payment(unpaid)
        self.failed_payment(stale, hours_old=25)
        self.failed_payment(paid)

        with CaptureQueriesContext(connection) as queries:
            result = sync_order_payment_status()
        self.assertTrue(result["success"])
        unpaid.refresh_from_db()
        self.assertEqual(unpaid.status, "failed")
        self.assertEqual(sum(PAYMENT_FAILURES_KEY in query["sql"] for query in queries.captured_queries), 1)
        stale.refresh_from_db()
        paid.refresh_from_db()
        self.assertEqual(stale.status, "awaiting_payment")
        self.assertEqual(paid.status, "paid")

        self.set_value(PAYMENT_FAILURES_KEY, 2)
        boundary = self.order(invoice_status="issued")
        self.failed_payment(boundary)
        sync_order_payment_status()
        boundary.refresh_from_db()
        self.assertEqual(boundary.status, "awaiting_payment")
        self.failed_payment(boundary)
        sync_order_payment_status()
        boundary.refresh_from_db()
        self.assertEqual(boundary.status, "failed")

    def test_search_setting_truncates_and_changes_both_list_filters(self) -> None:
        self.set_value(SEARCH_LENGTH_KEY, 5)
        self.assertEqual(_sanitize_search_query("abcdefgh"), "abcde")
        self.assertEqual(_sanitize_search_query("abcde"), "abcde")
        self.assertEqual(_sanitize_search_query("abcd"), "abcd")
        self.assertEqual(_sanitize_search_query("'; DROP TABLE orders; --"), "")
        matching = self.order()
        Order.objects.filter(pk=matching.pk).update(customer_company="abcde company")
        user = User.objects.create_user(
            email="search@example.test", password="password", is_staff=True, staff_role="admin"
        )
        for view in (order_list, order_list_htmx):
            request = RequestFactory().get("/orders/", {"search": "abcdefgh"})
            request.user = user
            with self.subTest(view=view.__name__), patch("apps.orders.views.render") as render:
                view(request)
                context = cast("dict[str, object]", render.call_args.args[2])
                page = cast("Page[Order]", context["orders"])
                self.assertEqual([order.pk for order in page], [matching.pk])

        self.set_value(SEARCH_LENGTH_KEY, 8)
        self.assertEqual(_sanitize_search_query("abcdefghij"), "abcdefgh")
        self.set_value(SEARCH_LENGTH_KEY, 0)
        self.assertEqual(_sanitize_search_query("abc"), "")

    def test_all_six_enqueue_sites_persist_the_current_budget_and_leave_old_tasks_unchanged(self) -> None:
        broker = ORM(list_key="wp18-orders")
        original_task = ""
        with patch("django_q.tasks.get_broker", return_value=broker), patch.object(Conf, "SYNC", False):
            for timeout in (17, 19):
                self.set_value(TASK_LIMIT_KEY, timeout)
                jobs = (
                    (process_pending_orders_async(), "apps.orders.tasks.process_pending_orders", ()),
                    (sync_order_payment_status_async(), "apps.orders.tasks.sync_order_payment_status", ()),
                    (
                        generate_invoice_for_order_async("order-id"),
                        "apps.orders.tasks.generate_invoice_for_order",
                        ("order-id",),
                    ),
                    (provision_order_item_async("item-id"), "apps.orders.tasks.provision_order_item", ("item-id",)),
                )
                free = self.order(total=0)
                settled = self.order(invoice_status="paid")
                force_status(settled, "provisioning")
                free_item = self.item(free)
                paid_item = self.item(settled)
                force_status(settled, "awaiting_payment")

                with CaptureQueriesContext(connection) as queries:
                    outcome = process_pending_orders()
                self.assertTrue(outcome["success"], outcome)
                free.refresh_from_db()
                settled.refresh_from_db()
                self.assertEqual(free.status, "provisioning")
                self.assertEqual(settled.status, "provisioning")
                tasks = {
                    task["id"]: task
                    for row in OrmQ.objects.filter(key=broker.list_key)
                    for task in (cast("dict[str, object]", SignedPackage.loads(row.payload)),)
                }
                for task_id, function, arguments in jobs:
                    with self.subTest(timeout=timeout, function=function):
                        self.assertEqual(tasks[task_id]["timeout"], timeout)
                        self.assertEqual(tasks[task_id]["func"], function)
                        self.assertEqual(tasks[task_id]["args"], arguments)
                for item in (free_item, paid_item):
                    item_tasks = [
                        task
                        for task in tasks.values()
                        if task["func"] == "apps.orders.tasks.provision_order_item" and task["args"] == (item.pk,)
                    ]
                    self.assertEqual(len(item_tasks), 1)
                    self.assertEqual(item_tasks[0]["timeout"], timeout)
                self.assertEqual(sum(TASK_LIMIT_KEY in query["sql"] for query in queries.captured_queries), 1)
                if timeout == 17:
                    original_task = jobs[0][0]
                else:
                    self.assertEqual(tasks[original_task]["timeout"], 17)

    def test_search_activation_rewrites_the_old_default_once_and_keeps_later_overrides(self) -> None:
        self.set_value(SEARCH_LENGTH_KEY, 200)
        SystemSetting.objects.filter(key=SEARCH_LENGTH_KEY).update(name="Metadata reconciled", default_value=100)
        output = StringIO()
        with (
            patch.object(sync, "CATALOG", (CATALOG_BY_KEY[SEARCH_LENGTH_KEY],)),
            self.captureOnCommitCallbacks(execute=True),
        ):
            call_command("setup_default_settings", stdout=output)
        row = SystemSetting.objects.get(key=SEARCH_LENGTH_KEY)
        self.assertEqual(row.value, 100)
        self.assertEqual(row.default_value, 100)
        self.assertIn(f"{SEARCH_LENGTH_KEY}: 200 → 100", output.getvalue())
        self.assertEqual(_sanitize_search_query("a" * 150), "a" * 100)
        self.assertTrue(SettingActivation.objects.filter(key=SEARCH_LENGTH_KEY, completed_at__isnull=False).exists())

        self.set_value(SEARCH_LENGTH_KEY, 200)
        with patch.object(sync, "CATALOG", (CATALOG_BY_KEY[SEARCH_LENGTH_KEY],)):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(SystemSetting.objects.get(key=SEARCH_LENGTH_KEY).value, 200)
        self.assertEqual(_sanitize_search_query("a" * 150), "a" * 150)

    def test_batch_activation_reports_all_retained_values_once_and_seeds_missing_rows(self) -> None:
        keys = set(CONFIGURED)
        definitions = tuple(CATALOG_BY_KEY[key] for key in CONFIGURED)
        for key, value in CONFIGURED.items():
            self.set_value(key, value)
        output = StringIO()
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=output)
        self.assertEqual(SettingActivation.objects.filter(key__in=keys, completed_at__isnull=False).count(), 4)
        alert = AuditAlert.objects.get(metadata__activation_version="wp18-v1")
        self.assertEqual(set(alert.metadata["keys"]), keys)
        self.assertEqual(alert.evidence["retained_values"], CONFIGURED)
        self.assertEqual(
            alert.evidence["previous_enforced_values"],
            {PAYMENT_FAILURES_KEY: 3, SEARCH_LENGTH_KEY: 100, TASK_LIMIT_KEY: 900, REGISTRATION_KEY: 5},
        )
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), CONFIGURED)
        for key in keys:
            self.assertIn(key, output.getvalue())
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), 1)

        SystemSetting.objects.filter(key__in=keys).delete()
        SettingActivation.objects.filter(key__in=keys).delete()
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(
            dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")),
            {PAYMENT_FAILURES_KEY: 3, SEARCH_LENGTH_KEY: 100, TASK_LIMIT_KEY: 900, REGISTRATION_KEY: 5},
        )
        self.assertEqual(_sanitize_search_query("a" * 150), "a" * 100)


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class OrdersSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @contextmanager
    def setting_mode(self, atomic: bool) -> Generator[None]:
        if atomic:
            with transaction.atomic():
                try:
                    for key, value in ((SEARCH_LENGTH_KEY, 5), (PAYMENT_FAILURES_KEY, 1), (TASK_LIMIT_KEY, 17)):
                        result = SettingsService.update_setting(key, value)
                        self.assertTrue(result.is_ok(), result)
                    yield
                finally:
                    transaction.set_rollback(True)
        else:
            self.assertTrue(connection.get_autocommit())
            for key, value in ((SEARCH_LENGTH_KEY, 5), (PAYMENT_FAILURES_KEY, 1), (TASK_LIMIT_KEY, 17)):
                cache.set(SettingsService._get_cache_key(key), value, version=SettingsService.CACHE_VERSION)
            yield

    def check_search(self, atomic: bool) -> None:
        with self.setting_mode(atomic):
            for text in ("abcdef", "a" * 1000):
                with self.subTest(length=len(text)):
                    with CaptureQueriesContext(connection) as queries:
                        sanitized = _sanitize_search_query(text)
                    self.assertEqual(len(queries), int(atomic))
                    self.assertEqual(sanitized, text[:5])
            self.check_batches(atomic)

    def check_batches(self, atomic: bool) -> None:
        operations = ((sync_order_payment_status, PAYMENT_FAILURES_KEY), (process_pending_orders, TASK_LIMIT_KEY))
        for operation, key in operations:
            with self.subTest(operation=operation.__name__):
                with CaptureQueriesContext(connection) as queries:
                    result = operation()
                self.assertTrue(result["success"], result)
                self.assertEqual(sum(key in query["sql"] for query in queries.captured_queries), int(atomic))

        broker = ORM(list_key="wp18-orders-query")
        try:
            with (
                patch("django_q.tasks.get_broker", return_value=broker),
                patch.object(Conf, "SYNC", False),
                CaptureQueriesContext(connection) as queries,
            ):
                task_id = process_pending_orders_async()
            self.assertEqual(sum(TASK_LIMIT_KEY in query["sql"] for query in queries.captured_queries), int(atomic))
            task = cast("dict[str, object]", SignedPackage.loads(OrmQ.objects.get(key=broker.list_key).payload))
            self.assertEqual(task["id"], task_id)
            self.assertEqual(task["timeout"], 17)
        finally:
            OrmQ.objects.filter(key=broker.list_key).delete()

    def test_hot_paths_use_warm_cache_without_setting_queries(self) -> None:
        self.check_search(atomic=False)

    def test_hot_paths_resolve_once_per_operation_inside_atomic(self) -> None:
        self.check_search(atomic=True)
