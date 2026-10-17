"""Two orders naming one domain cannot both become payable, however their submissions interleave."""

from __future__ import annotations

import contextlib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from apps.domains.services import DomainOrderService
from apps.orders.models import Order
from apps.orders.services import OrderService, StatusChangeData

from .test_domain_order_availability_gate import DomainAvailabilityGateFixture

ORIGINAL_REFUSAL = DomainOrderService.admission_refusal


class DomainHoldRaceTests(DomainAvailabilityGateFixture, TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock ordering between two submissions requires PostgreSQL")
        super().setUp()

    def _race(self, *orders: Order) -> list[bool]:
        """Submit both at once; the first to check its domain waits there for the other to check too.

        Without a shared lock both check before either commits and both succeed. With it, the second
        cannot reach the check until the first has committed, so the first gives up waiting.
        """
        both_checking = threading.Barrier(len(orders))

        def refusal(*args: Any, **kwargs: Any) -> str | None:
            answer = ORIGINAL_REFUSAL(*args, **kwargs)
            with contextlib.suppress(threading.BrokenBarrierError):
                both_checking.wait(timeout=3)
            return answer

        def submit(order: Order) -> bool:
            close_old_connections()
            try:
                return OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment")).is_ok()
            finally:
                connection.close()

        with (
            patch.object(DomainOrderService, "admission_refusal", side_effect=refusal),
            ThreadPoolExecutor(max_workers=len(orders)) as pool,
        ):
            return list(pool.map(submit, orders))

    def test_two_submissions_for_one_name_one_wins(self) -> None:
        first = self._create(self._line("contested.ro")).unwrap()
        second = self._create(self._line("contested.ro")).unwrap()
        self.assertEqual(sorted(self._race(first, second)), [False, True])
        statuses = sorted(Order.objects.filter(pk__in=[first.pk, second.pk]).values_list("status", flat=True))
        self.assertEqual(statuses, ["awaiting_payment", "draft"])

    def test_a_retry_and_a_submission_for_one_name_one_wins(self) -> None:
        failed = self._create(self._line("rebid.ro")).unwrap()
        Order.objects.filter(pk=failed.pk).update(status="failed")
        draft = self._create(self._line("rebid.ro")).unwrap()
        self.assertEqual(sorted(self._race(Order.objects.get(pk=failed.pk), draft)), [False, True])
        payable = Order.objects.filter(pk__in=[failed.pk, draft.pk], status="awaiting_payment").count()
        self.assertEqual(payable, 1)
