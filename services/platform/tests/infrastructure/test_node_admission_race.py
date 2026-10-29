"""Teardown's guard and account admission interleaved on one node, in both orders.

Each side holds its VirtualminServer row lock open while the other starts, so the second side must wait
and then decide on what the first committed:
- guard first: the node is closed when admission gets the lock, so no account is created;
- admission first: the new account exists when the guard gets the lock, so the guard refuses.

Row locks are real only on PostgreSQL, so this runs there (CI's PostgreSQL step) and skips on SQLite.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase

from apps.common.types import Result
from apps.infrastructure.audit_service import InfrastructureAuditContext
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.infrastructure.test_deployment_service_pipeline import _make_service
from tests.infrastructure.test_node_admission_guard import create_account, make_node, make_service

# Long enough for an unblocked second side to finish inside the hold, short enough to keep the test quick.
_HOLD_SECONDS = 2.0


class GuardAndAdmissionRaceTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.server, self.deployment = make_node("race")
        # Built before the threads start so neither side's wait includes fixture writes.
        self.admitted_service = make_service("admitted.example.com")

    def _guard(self) -> Result[bool, str]:
        return _make_service()._disable_linked_server_for_stop(self.deployment, InfrastructureAuditContext())

    def _admit(self) -> Result[VirtualminAccount, str]:
        return create_account(self.server, "admitted.example.com", self.admitted_service)

    def _race(self, first: str) -> tuple[Result[bool, str], Result[VirtualminAccount, str]]:
        first_holds_lock = threading.Event()
        second_done = threading.Event()
        guards: list[Result[bool, str]] = []
        admissions: list[Result[VirtualminAccount, str]] = []

        def run(side: str) -> None:
            if side == "guard":
                guards.append(self._guard())
            else:
                admissions.append(self._admit())

        def first_side() -> None:
            close_old_connections()
            try:
                with transaction.atomic():
                    run(first)
                    first_holds_lock.set()
                    second_done.wait(timeout=_HOLD_SECONDS)
            finally:
                connection.close()

        def second_side() -> None:
            close_old_connections()
            try:
                first_holds_lock.wait(timeout=10)
                run("admit" if first == "guard" else "guard")
            finally:
                second_done.set()
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(first_side)
            other = executor.submit(second_side)
            holder.result(timeout=30)
            other.result(timeout=30)
        return guards[0], admissions[0]

    def test_guard_first_closes_the_node_before_admission_decides(self) -> None:
        guard, admit = self._race("guard")

        self.assertTrue(guard.is_ok(), guard)
        self.assertTrue(admit.is_err(), admit)
        self.assertFalse(VirtualminAccount.objects.filter(domain="admitted.example.com").exists())
        self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).status, "disabled")

    def test_admission_first_is_seen_by_the_guard(self) -> None:
        guard, admit = self._race("admit")

        self.assertTrue(admit.is_ok(), admit)
        self.assertTrue(guard.is_err(), guard)
        self.assertTrue(VirtualminAccount.objects.filter(domain="admitted.example.com").exists())
        self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).status, "active")
