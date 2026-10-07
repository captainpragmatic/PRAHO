"""Order task payloads must never expose Django-Q's zero-timeout semantics."""

from typing import cast

from django.core.cache import cache
from django.test import TestCase
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.orders.tasks import process_pending_orders_async
from tests.helpers.legacy_settings import store_legacy_integer


class NonpositiveOrderTaskBudgetTests(TestCase):
    def test_legacy_nonpositive_budgets_enqueue_with_the_default(self) -> None:
        self.addCleanup(cache.clear)
        for stored, expected in ((0, 900), (-1, 900), (1, 1), (17, 17)):
            with self.subTest(stored=stored):
                store_legacy_integer("orders.task_time_limit", stored)
                cache.clear()
                task_id = process_pending_orders_async()
                packages = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
                task = next(package for package in packages if package["id"] == task_id)
                self.assertEqual(task["timeout"], expected)
                self.assertEqual(task["func"], "apps.orders.tasks.process_pending_orders")
