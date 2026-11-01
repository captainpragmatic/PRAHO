"""Actual public admissions wait on PostgreSQL's server gate in both directions."""

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from typing import cast
from unittest import skipUnless

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.common.types import Result
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "PostgreSQL server row locks are required")
@override_settings(Q_CLUSTER={"name": "maintenance-races", "orm": "default", "retry": 100000})
class NodeMaintenancePostgresConcurrencyTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def _call(
        self,
        action: Callable[[], object],
        pid_ready: Event,
        pids: list[int],
        acquired: Event | None = None,
        release: Event | None = None,
    ) -> object:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            pid_ready.set()
            if acquired is None or release is None:
                return action()

            def observe(
                execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
            ) -> object:
                result = execute(sql, params, many, context)
                if "provisioning_virtualmin_servers" in sql and "FOR UPDATE" in sql and not acquired.is_set():
                    acquired.set()
                    if not release.wait(10):
                        raise AssertionError("The public server holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _waiting(self, pid: int, owner_pid: int, pending: Future[object]) -> None:
        deadline = monotonic() + 10
        row = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid=%s", [pid]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and owner_pid in row[1]:
                self.assertIn("provisioning_virtualmin_servers", row[2])
                self.assertTrue(row[2].startswith("SELECT "), "Wait must belong to the public server-row SELECT")
                return
            if pending.done():
                self.fail(f"The public contender completed before waiting on the server: {pending.result()}")
            Event().wait(0.01)
        self.fail(f"No actual server lock wait: contender={pid}, holder={owner_pid}, last_sample={row!r}")

    def _race(self, *, window_first: bool) -> None:
        window = self.window()
        actions: tuple[Callable[[], object], Callable[[], object]] = (
            lambda: self.start(window),
            lambda: VirtualminBackupManagementService(self.node).create_backup_job(self.account),
        )
        if not window_first:
            actions = actions[::-1]
        acquired, release = Event(), Event()
        holder_ready, contender_ready = Event(), Event()
        holder_pids: list[int] = []
        contender_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self._call, actions[0], holder_ready, holder_pids, acquired, release)
            try:
                self.assertTrue(acquired.wait(10), "The real public admission never acquired its server lock")
                second = pool.submit(self._call, actions[1], contender_ready, contender_pids)
                self.assertTrue(contender_ready.wait(10))
                self._waiting(contender_pids[0], holder_pids[0], second)
            finally:
                release.set()
            first_result = first.result(timeout=10)
            if window_first:
                self.assertIsInstance(first_result, NodeMaintenanceWindow)
                backup = cast(Result[VirtualminProvisioningJob, str], second.result(timeout=10))
                self.assertTrue(backup.is_err())
                self.assertIn("Maintenance", backup.unwrap_err())
                self.assertFalse(VirtualminProvisioningJob.objects.exists())
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
            else:
                self.assertTrue(cast(Result[VirtualminProvisioningJob, str], first_result).is_ok())
                with self.assertRaisesMessage(ValidationError, "hosting-account operation"):
                    second.result(timeout=10)
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                self.assertEqual(VirtualminProvisioningJob.objects.filter(status="pending").count(), 1)
                self.assertFalse(window.executions.exists())

    def test_window_claim_wins_over_public_backup_admission(self) -> None:
        self._race(window_first=True)

    def test_public_backup_admission_wins_over_window_claim(self) -> None:
        self._race(window_first=False)
