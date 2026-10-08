"""Silence the task queue for a test without leaving a mock that a lazy import can capture.

Patching `django_q.tasks.async_task` itself is unsafe. A module first imported while that patch is
active - `apps.orders.tasks`, `apps.billing.tasks` and the other `from django_q.tasks import
async_task` modules, through a deferred import - binds the MagicMock for the rest of the process.
Every later test in that worker then enqueues nothing and gets the mock's return value back.

This helper leaves `async_task` alone and replaces what it looks up at call time instead: the
broker, and `Conf.SYNC`, so nothing runs inline.
"""

from __future__ import annotations

import unittest
from typing import cast
from unittest.mock import patch

from django_q.conf import Conf
from django_q.signing import SignedPackage


class DiscardingBroker:
    """Keeps the signed packages it is given, so a test can inspect them, and never delivers one."""

    list_key = "quiet-tests"

    def __init__(self) -> None:
        self.packages: list[str] = []

    def enqueue(self, package: str) -> str:
        self.packages.append(package)
        return f"quiet-{len(self.packages)}"

    def queued(self) -> list[tuple[object, ...]]:
        """Each enqueued job as `(func, *args)`, in order."""
        jobs = [cast("dict[str, object]", SignedPackage.loads(package)) for package in self.packages]
        return [(job["func"], *cast("tuple[object, ...]", job["args"])) for job in jobs]


def quiet_task_queue(case: unittest.TestCase) -> DiscardingBroker:
    broker = DiscardingBroker()
    for patcher in (patch("django_q.tasks.get_broker", return_value=broker), patch.object(Conf, "SYNC", False)):
        patcher.start()
        case.addCleanup(patcher.stop)
    return broker
