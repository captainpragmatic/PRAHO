"""Schedules and provisioning signals persist the current order task budget."""

from __future__ import annotations

from datetime import timedelta
from typing import cast

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django_q.brokers.orm import ORM
from django_q.conf import Conf
from django_q.models import OrmQ, Schedule
from django_q.scheduler import scheduler
from django_q.signing import SignedPackage

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.signals import _trigger_service_provisioning
from apps.orders.tasks import apply_scheduled_order_task_budget, setup_order_scheduled_tasks
from apps.products.models import Product
from apps.settings.services import SettingsService

BUDGET_KEY = "orders.task_time_limit"
SCHEDULES = {
    "order-process-pending": ("apps.orders.tasks.process_pending_orders", 5),
    "order-sync-payment-status": ("apps.orders.tasks.sync_order_payment_status", 15),
}


class OrderTaskBudgetCloseoutTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.assertFalse(Conf.SYNC)
        self.assertEqual(Conf.ORM, "default")
        Schedule.objects.filter(name__in=SCHEDULES).delete()
        self.set_budget(17)

    def set_budget(self, timeout: int) -> None:
        result = SettingsService.update_setting(BUDGET_KEY, timeout)
        self.assertTrue(result.is_ok(), result)

    def scheduled_payloads(self, timeout: int) -> None:
        for name, (function, minutes) in SCHEDULES.items():
            with self.subTest(schedule=name):
                row = Schedule.objects.get(name=name)
                self.assertEqual((row.func, row.minutes), (function, minutes))
                self.assertEqual(row.schedule_type, Schedule.MINUTES)
        Schedule.objects.filter(name__in=SCHEDULES).update(
            cluster=Conf.CLUSTER_NAME, next_run=timezone.now() - timedelta(seconds=1)
        )
        scheduler(broker=ORM(list_key="order-budget-schedules"))
        packages = [
            cast("dict[str, object]", SignedPackage.loads(row.payload))
            for row in OrmQ.objects.filter(key="order-budget-schedules")
        ]
        # Every due schedule runs; only the order schedules are under test.
        by_name = {package["group"]: package for package in packages if package["group"] in SCHEDULES}
        self.assertEqual(set(by_name), set(SCHEDULES))
        for name, (function, _minutes) in SCHEDULES.items():
            self.assertEqual(by_name[name].get("timeout"), timeout)
            self.assertEqual(by_name[name]["func"], function)
            self.assertEqual(by_name[name]["args"], ())
            self.assertEqual(by_name[name]["kwargs"], {})
        OrmQ.objects.filter(key="order-budget-schedules").delete()

    def test_new_schedules_persist_and_enqueue_the_current_timeout(self) -> None:
        result = setup_order_scheduled_tasks()
        self.assertEqual(result, {"process_pending": "created", "sync_payments": "created"})
        self.scheduled_payloads(17)

    def test_a_budget_change_reaches_the_next_scheduled_run_without_rerunning_setup(self) -> None:
        setup_order_scheduled_tasks()
        for timeout in (19, 23):
            self.set_budget(timeout)
            self.scheduled_payloads(timeout)

    def test_setup_keeps_existing_schedules_and_their_progress(self) -> None:
        next_run = timezone.now() + timedelta(hours=1)
        original_ids: dict[str, int] = {}
        for name, (function, minutes) in SCHEDULES.items():
            row = Schedule.objects.create(
                name=name,
                func=function,
                schedule_type=Schedule.MINUTES,
                minutes=minutes,
                cluster="praho-cluster",
                kwargs="{}",
                repeats=4,
                next_run=next_run,
                task="previous-task",
            )
            original_ids[name] = row.pk
        result = setup_order_scheduled_tasks()
        self.assertEqual(result, {"process_pending": "already_exists", "sync_payments": "already_exists"})
        self.assertEqual(Schedule.objects.filter(name__in=SCHEDULES).count(), 2)
        for name in SCHEDULES:
            row = Schedule.objects.get(name=name)
            self.assertEqual(
                (row.pk, row.next_run, row.repeats, row.task), (original_ids[name], next_run, 4, "previous-task")
            )
        self.scheduled_payloads(17)

    def test_an_explicit_timeout_is_not_overridden(self) -> None:
        task: dict[str, object] = {"func": "apps.orders.tasks.process_pending_orders", "timeout": 5}
        apply_scheduled_order_task_budget(sender="django_q", task=task)
        self.assertEqual(task["timeout"], 5)
        other: dict[str, object] = {"func": "apps.billing.tasks.something_else"}
        apply_scheduled_order_task_budget(sender="django_q", task=other)
        self.assertNotIn("timeout", other)

    def test_provisioning_signal_persists_one_budget_for_all_pending_items(self) -> None:
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Budget customer", primary_email="budget@example.test")
        order = Order.objects.create(
            customer=customer, currency=currency, customer_email=customer.primary_email, customer_name=customer.name
        )
        product = Product.objects.create(name="Budget product", slug="budget-product", product_type="vps")
        items = [
            OrderItem.objects.create(
                order=order,
                product=product,
                product_name=product.name,
                product_type=product.product_type,
                quantity=1,
                unit_price_cents=100,
                line_total_cents=100,
            )
            for _index in range(3)
        ]
        OrderItem.objects.filter(pk=items[-1].pk).update(provisioning_status="completed")
        original_packages = list(OrmQ.objects.values_list("pk", flat=True))
        for timeout in (17, 19):
            self.set_budget(timeout)
            with CaptureQueriesContext(connection) as queries:
                _trigger_service_provisioning(order)
            packages = [
                cast("dict[str, object]", SignedPackage.loads(row.payload))
                for row in OrmQ.objects.exclude(pk__in=original_packages)
            ]
            self.assertEqual(len(packages), 2)
            self.assertEqual({package["args"] for package in packages}, {(str(item.pk),) for item in items[:2]})
            for package in packages:
                self.assertEqual(package.get("timeout"), timeout)
                self.assertEqual(package["func"], "apps.orders.tasks.provision_order_item")
                self.assertEqual(package["kwargs"], {})
            self.assertEqual(sum(BUDGET_KEY in query["sql"] for query in queries.captured_queries), 1)
            original_packages = list(OrmQ.objects.values_list("pk", flat=True))
