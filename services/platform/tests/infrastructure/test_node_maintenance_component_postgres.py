"""Public component admission and maintenance share both actual Server mutexes."""

import json
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from unittest import skipUnless
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import create_window
from apps.provisioning.component_migration_models import SourceServiceObligation
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.maintenance_component_fixtures import MaintenanceComponentFixture

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "Actual PostgreSQL row locks are required")
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-component-races", "orm": "default", "retry": 100000},
)
class NodeMaintenanceComponentPostgresTests(MaintenanceComponentFixture, TransactionTestCase):
    def _public_call(
        self,
        action: Callable[[], object],
        ready: Event,
        pids: list[int],
        *,
        node_id: UUID,
        hold: tuple[Event, Event, str] | None = None,
    ) -> object:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '25s'")
                cursor.execute("SET statement_timeout = '35s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            if hold is None:
                return action()
            acquired, release, clause = hold

            def observe(
                execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
            ) -> object:
                result = execute(sql, params, many, context)
                values = params.values() if isinstance(params, Mapping) else params or ()
                if (
                    VirtualminServer._meta.db_table in sql
                    and clause in sql
                    and str(node_id) in {str(value) for value in values}
                    and not acquired.is_set()
                ):
                    self.assertTrue(connection.in_atomic_block, "Only the public writer's own transaction may hold")
                    acquired.set()
                    self.assertTrue(release.wait(20), "The real Server holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _assert_waiting(self, pid: int, holder: int, pending: Future[object], node_id: UUID) -> None:
        deadline, poll = monotonic() + 15, Event()
        sample = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid=%s", [pid]
                )
                sample = cursor.fetchone()
            if sample and sample[0] == "Lock" and holder in sample[1]:
                self.assertTrue(sample[2].startswith("SELECT "))
                self.assertIn(VirtualminServer._meta.db_table, sample[2])
                print(
                    json.dumps(
                        {
                            "server_lock_wait": True,
                            "node_id": str(node_id),
                            "waiter_pid": pid,
                            "holder_pid": holder,
                            "blocking_pids": sample[1],
                        }
                    ),
                    flush=True,
                )
                return
            if pending.done():
                self.fail(f"The public contender did not wait on its Server owner: {pending.result()!r}")
            poll.wait(0.01)
        self.fail(f"No real Server lock wait: waiter={pid}, holder={holder}, sample={sample!r}")

    def _race(self, *, target: bool, window_first: bool) -> None:
        node = self.target if target else self.node
        # Create all ordinary schedules before component admission, which would
        # correctly veto a new schedule once it already owned either endpoint.
        source_window = self.window()
        window = (
            create_window(
                node.pk,
                actor=self.actor,
                kind=source_window.kind,
                execution_mode="manual",
                starts_at=source_window.starts_at,
                ends_at=source_window.ends_at,
                expects_downtime=True,
                expected_downtime_minutes=5,
                customer_note="Hosting maintenance",
            )
            if target
            else source_window
        )
        migrations_before = set(VirtualminMigration.objects.values_list("pk", flat=True))
        obligations_before = set(SourceServiceObligation.objects.values_list("pk", flat=True))
        http_before = self.http.call_count
        actions: tuple[Callable[[], object], Callable[[], object]] = (lambda: self.start(window), self.component_start)
        if not window_first:
            actions = actions[::-1]
        acquired, release = Event(), Event()
        first_ready, second_ready = Event(), Event()
        first_pids: list[int] = []
        second_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                self._public_call,
                actions[0],
                first_ready,
                first_pids,
                node_id=node.pk,
                hold=(acquired, release, "FOR UPDATE" if window_first else "FOR NO KEY UPDATE"),
            )
            try:
                self.assertTrue(acquired.wait(15), "The actual public holder did not acquire the selected Server")
                second = pool.submit(self._public_call, actions[1], second_ready, second_pids, node_id=node.pk)
                self.assertTrue(second_ready.wait(15))
                self._assert_waiting(second_pids[0], first_pids[0], second, node.pk)
            finally:
                release.set()
            first_result = first.result(timeout=20)
            if window_first:
                self.assertIsInstance(first_result, NodeMaintenanceWindow)
                with self.assertRaisesMessage(ValidationError, "Maintenance"):
                    second.result(timeout=20)
                self.assertEqual(set(VirtualminMigration.objects.values_list("pk", flat=True)), migrations_before)
                self.assertEqual(set(SourceServiceObligation.objects.values_list("pk", flat=True)), obligations_before)
                self.assertEqual(VirtualminMigration.active_reservations(self.target), 0)
                self.assertEqual(self.http.call_count, http_before, "The losing admission reached remote inventory")
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
                self.assertEqual(window.executions.count(), 1)
            else:
                self.assertIsInstance(first_result, VirtualminMigration)
                with self.assertRaisesMessage(ValidationError, "migration"):
                    second.result(timeout=20)
                self.assertEqual(VirtualminMigration.objects.get(pk=first_result.pk).status, "pending")
                self.assertEqual(first_result.source_server_id, self.node.pk)
                self.assertEqual(first_result.target_server_id, self.target.pk)
                self.assertEqual(first_result.component_source_obligation.source_server_id, self.node.pk)
                self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                self.assertFalse(window.executions.exists())
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.node.pk, "Admission must not publish account placement")

    def test_source_window_wins_over_public_component_admission(self) -> None:
        self._race(target=False, window_first=True)

    def test_component_admission_wins_over_source_window(self) -> None:
        self._race(target=False, window_first=False)

    def test_empty_target_window_wins_over_public_component_admission(self) -> None:
        self._race(target=True, window_first=True)

    def test_component_admission_wins_over_empty_target_window(self) -> None:
        self._race(target=True, window_first=False)
