"""The shared queue silencer must not leave a mock where a lazily imported module can bind it."""

from __future__ import annotations

import importlib.util
from typing import cast

import django_q.tasks
from django.conf import settings
from django.test import SimpleTestCase
from django_q.signing import SignedPackage

from tests.helpers.task_queue import quiet_task_queue


class QuietTaskQueueTests(SimpleTestCase):
    def test_a_module_imported_inside_the_window_binds_the_real_async_task(self) -> None:
        real = django_q.tasks.async_task
        broker = quiet_task_queue(self)
        self.assertIs(django_q.tasks.async_task, real)

        # Load a fresh copy of a task module, as a deferred import inside a test would.
        spec = importlib.util.spec_from_file_location(
            "quiet_probe_orders_tasks", settings.BASE_DIR / "apps" / "orders" / "tasks.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIs(module.async_task, real)

        task_id = module.async_task("apps.orders.tasks.process_pending_orders", timeout=5)
        self.assertEqual(len(broker.packages), 1)
        package = cast("dict[str, object]", SignedPackage.loads(broker.packages[0]))
        self.assertEqual((package["id"], package["func"]), (task_id, "apps.orders.tasks.process_pending_orders"))
        self.assertNotIn("sync", package)
