"""Customer jobs retain usable hard and soft worker budgets."""

from typing import cast

from django.core.cache import cache
from django.test import TestCase
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.customers.tasks import (
    process_customer_feedback_async,
    start_customer_onboarding_async,
)
from tests.helpers.legacy_settings import store_legacy_integer


class NonpositiveCustomerTaskBudgetTests(TestCase):
    def test_legacy_nonpositive_budgets_enqueue_with_defaults(self) -> None:
        self.addCleanup(cache.clear)
        operations = (
            ("customers.task_soft_time_limit", 300, process_customer_feedback_async),
            ("customers.task_time_limit", 600, start_customer_onboarding_async),
        )
        for key, default, enqueue in operations:
            for stored in (0, -1, 1, 17):
                with self.subTest(key=key, stored=stored):
                    store_legacy_integer(key, stored)
                    cache.clear()
                    task_id = enqueue("fixture-id")
                    packages = [
                        cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()
                    ]
                    task = next(package for package in packages if package["id"] == task_id)
                    self.assertEqual(task["timeout"], default if stored <= 0 else stored)
                    self.assertEqual(task["args"], ("fixture-id",))
