"""Both public owners contend on PostgreSQL's actual Server row mutex."""

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from unittest import skipUnless

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import record_inspection
from apps.provisioning.virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution
from tests.infrastructure.maintenance_security_fixtures import MaintenanceSecurityFixture
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.provisioning.test_node_security_policy import OPERATOR_KEY

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row locks are required")
@override_settings(Q_CLUSTER={"name": "maintenance-security-races", "orm": "default", "retry": 100000})
class NodeMaintenanceSecurityPostgresTests(MaintenanceSecurityFixture, TransactionTestCase):
    def _public_call(
        self,
        action: Callable[[], object],
        ready: Event,
        pids: list[int],
        acquired: Event | None = None,
        release: Event | None = None,
    ) -> object:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            if acquired is None or release is None:
                return action()

            def observe(
                execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
            ) -> object:
                result = execute(sql, params, many, context)
                if VirtualminServer._meta.db_table in sql and "FOR UPDATE" in sql and not acquired.is_set():
                    self.assertTrue(connection.in_atomic_block, "The public writer must own its real transaction")
                    acquired.set()
                    if not release.wait(15):
                        raise AssertionError("The public Server holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _assert_waiting(self, pid: int, holder: int, pending: Future[object]) -> None:
        deadline, poll = monotonic() + 15, Event()
        sample = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid=%s", [pid]
                )
                sample = cursor.fetchone()
            if sample and sample[0] == "Lock" and holder in sample[1]:
                self.assertTrue(sample[2].startswith("SELECT "))
                self.assertIn(VirtualminServer._meta.db_table, sample[2])
                return
            if pending.done():
                self.fail(f"The contender finished without waiting on its owner: {pending.result()}")
            poll.wait(0.01)
        self.fail(f"No actual PostgreSQL Server lock wait: pid={pid}, holder={holder}, sample={sample!r}")

    def _race(self, *, window_first: bool) -> None:
        window = self.window()
        actions: tuple[Callable[[], object], Callable[[], object]] = (
            lambda: self.start(window),
            self.harden,
        )
        if not window_first:
            actions = actions[::-1]
        acquired, release = Event(), Event()
        first_ready, second_ready = Event(), Event()
        first_pids: list[int] = []
        second_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self._public_call, actions[0], first_ready, first_pids, acquired, release)
            try:
                self.assertTrue(acquired.wait(15), "The public writer did not acquire its Server lock")
                second = pool.submit(self._public_call, actions[1], second_ready, second_pids)
                self.assertTrue(second_ready.wait(15))
                self._assert_waiting(second_pids[0], first_pids[0], second)
            finally:
                release.set()
            first_result = first.result(timeout=15)
            self.node.refresh_from_db()
            if window_first:
                self.assertIsInstance(first_result, NodeMaintenanceWindow)
                with self.assertRaisesMessage(ValidationError, "Maintenance"):
                    second.result(timeout=15)
                self.assertIsNone(self.node.security_operation)
                self.assertFalse(NodeSecurityDecision.objects.exists())
                self.assertFalse(NodeSecurityExecution.objects.exists())
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
            else:
                self.assertIsInstance(first_result, NodeSecurityExecution)
                with self.assertRaisesMessage(ValidationError, "hardening"):
                    second.result(timeout=15)
                self.assertEqual(self.node.security_operation, first_result.pk)
                self.assertEqual(NodeSecurityExecution.objects.get(pk=first_result.pk).status, "running")
                self.assertEqual(NodeSecurityDecision.objects.count(), 1)
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                self.assertFalse(window.executions.exists())

    def test_window_claim_wins_over_reviewed_hardening(self) -> None:
        self._race(window_first=True)

    def test_reviewed_hardening_wins_over_window_claim(self) -> None:
        self._race(window_first=False)

    def _bind_managed_node(self) -> None:
        deployment = _create_deployment("completed", external_node_id="managed-security-mutex-fixture")
        deployment.virtualmin_server = self.node
        deployment.ssh_host_keys = OPERATOR_KEY
        deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        self.node.refresh_from_db()
        self.evidence = self.inspect(self.node)
        self.review = record_inspection(self.node, self.evidence)

    def test_managed_window_claim_wins_over_reviewed_hardening(self) -> None:
        self._bind_managed_node()
        self._race(window_first=True)

    def test_managed_reviewed_hardening_wins_over_window_claim(self) -> None:
        self._bind_managed_node()
        self._race(window_first=False)
