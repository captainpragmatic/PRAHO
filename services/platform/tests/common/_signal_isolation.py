"""Real failed writes shared by signal transaction regressions."""

from collections.abc import Callable
from typing import TypeVar, cast
from unittest.mock import patch

from django.db import transaction
from django.test import TestCase

from apps.billing.models import Currency
from tests.helpers.task_queue import quiet_task_queue

T = TypeVar("T")


class SignalIsolationTestCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        Currency.objects.get_or_create(code="XTS", defaults={"symbol": "test"})
        self.failed_writes: list[str] = []
        quiet_task_queue(self)

    def fail_write(self, *args: object, **kwargs: object) -> None:
        self.failed_writes.append("duplicate currency")
        Currency.objects.create(code="XTS", symbol="duplicate")

    def run_effect(self, target: str, trigger: Callable[[], T]) -> T:
        error: Exception | None = None
        result: T | None = None
        try:
            with patch(target, side_effect=self.fail_write), transaction.atomic():
                result = trigger()
        except Exception as exc:
            error = exc
        self.assertIsNone(error, "The triggering operation must not raise")
        self.assertEqual(self.failed_writes, ["duplicate currency"])
        return cast(T, result)
