"""Terminal artifact cleanup and manual windows serialize on their real Server mutex."""

import base64
import json
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from time import monotonic
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.provisioning.migration_artifact_cleanup import cleanup_migration_artifacts
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.maintenance_component_fixtures import MaintenanceComponentFixture

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "Actual PostgreSQL row locks are required")
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-cleanup-races", "orm": "default", "retry": 100000},
)
class NodeMaintenanceCleanupPostgresTests(MaintenanceComponentFixture, TransactionTestCase):
    def released_terminal(self) -> VirtualminMigration:
        migration = self.component_start()
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # Classify a historical controller receipt through real lease/transition
        # CAS. This proves admission, not that native compensation ran here.
        self.assertTrue(
            migration.transition(
                token,
                "pending",
                "quiescing",
                restore_issued=True,
                archive_sha256="a" * 64,
                barrier_state={
                    "component_source_hold_issued": True,
                    "component_source_released": True,
                    "component_target_removed": True,
                    "target_domain_id": "987654321",
                    "artifact_cleanup": {"done": False},
                },
            )
        )
        self.assertTrue(
            migration.transition(
                token,
                "quiescing",
                "rolled_back",
                lease_token=None,
                worker_lease_expires_at=None,
            )
        )
        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertIsNone(migration.lease_token)
        return migration

    def public_call(
        self,
        action: Callable[[], object],
        ready: Event,
        pids: list[int],
        hold: tuple[Event, Event] | None = None,
    ) -> object:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '30s'")
                cursor.execute("SET statement_timeout = '40s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            if hold is None:
                return action()
            acquired, release = hold

            def observe(
                execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
            ) -> object:
                result = execute(sql, params, many, context)
                values = params.values() if isinstance(params, Mapping) else params or ()
                if (
                    VirtualminServer._meta.db_table in sql
                    and "FOR UPDATE" in sql
                    and str(self.node.pk) in {str(value) for value in values}
                    and not acquired.is_set()
                ):
                    self.assertTrue(connection.in_atomic_block, "Only the public writer's genuine transaction holds")
                    acquired.set()
                    self.assertTrue(release.wait(20), "The real Server holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def assert_server_wait(self, pid: int, holder: int, pending: Future[object]) -> None:
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
                            "cleanup_server_lock_wait": True,
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

    def native_retirement(self, _server, _playbook, values, **_kwargs):
        self.assertFalse(connection.in_atomic_block, "Private native I/O must run after releasing row locks")
        current = VirtualminMigration.objects.get(pk=self.migration.pk)
        self.assertEqual(current.status, "rolled_back")
        self.assertIsNotNone(current.lease_token)
        self.assertGreater(current.worker_lease_expires_at, timezone.now())
        self.lease_tokens.append(current.lease_token)
        action = values["component_action"]
        self.assertIn(action, {"source_retire_artifacts", "target_retire_artifacts"})
        self.native_actions.append(action)
        self.remote_entered.set()
        self.assertTrue(self.remote_release.wait(20), "The owned external retirement boundary was not released")
        receipt = {"operation_id": str(self.migration.pk), "action": action, "phase": "artifacts_retired"}
        if action == "target_retire_artifacts":
            receipt["target_domain_id"] = "987654321"
        encoded = base64.b64encode(json.dumps(receipt).encode()).decode()
        return Ok(AnsibleResult(True, "virtualmin_component.yml", "PRAHO_COMPONENT_RESULT=" + encoded, "", 0))

    def race(self, *, cleanup_first: bool) -> None:
        self.migration = migration = self.released_terminal()
        window = self.window()
        original_state = migration.barrier_state
        sql_acquired, sql_release = Event(), Event()
        self.remote_entered, self.remote_release = Event(), Event()
        first_ready, second_ready = Event(), Event()
        first_pids: list[int] = []
        second_pids: list[int] = []
        self.lease_tokens = []
        self.native_actions = []

        first_action, second_action = (
            (lambda: cleanup_migration_artifacts(str(migration.pk)), lambda: self.start(window))
            if cleanup_first
            else (lambda: self.start(window), lambda: cleanup_migration_artifacts(str(migration.pk)))
        )
        with (
            patch(
                "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook",
                side_effect=self.native_retirement,
            ) as remote,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            first = pool.submit(self.public_call, first_action, first_ready, first_pids, (sql_acquired, sql_release))
            try:
                self.assertTrue(sql_acquired.wait(15), "The public writer never acquired its real Server row")
                second = pool.submit(self.public_call, second_action, second_ready, second_pids)
                self.assertTrue(second_ready.wait(15))
                self.assert_server_wait(second_pids[0], first_pids[0], second)
                sql_release.set()
                if cleanup_first:
                    self.assertTrue(
                        self.remote_entered.wait(15), "Cleanup did not publish its lease and reach native I/O"
                    )
                    with self.assertRaisesMessage(ValidationError, "cleanup worker"):
                        second.result(timeout=20)
                    migration.refresh_from_db()
                    self.assertEqual(migration.lease_token, self.lease_tokens[0])
                    self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                    self.assertFalse(window.executions.exists())
                else:
                    self.assertIsInstance(first.result(timeout=20), NodeMaintenanceWindow)
                    self.assertEqual(second.result(timeout=20), {"action": "waiting"})
                    remote.assert_not_called()
                    migration.refresh_from_db()
                    self.assertIsNone(migration.lease_token)
                    self.assertEqual(migration.barrier_state, original_state)
                    self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
                    self.assertEqual(window.executions.count(), 1)
            finally:
                sql_release.set()
                self.remote_release.set()
            if cleanup_first:
                outcome = first.result(timeout=20)
                migration.refresh_from_db()
                self.assertEqual(
                    outcome,
                    {"action": "cleaned"},
                    migration.barrier_state.get("artifact_cleanup", {}).get("last_error", ""),
                )
        self.assert_released_outcome(window, cleanup_first=cleanup_first)

    def assert_released_outcome(self, window: NodeMaintenanceWindow, *, cleanup_first: bool) -> None:
        self.migration.refresh_from_db()
        self.assertIsNone(self.migration.lease_token)
        self.assertIsNone(self.migration.worker_lease_expires_at)
        if cleanup_first:
            self.assertEqual(self.native_actions, ["source_retire_artifacts", "target_retire_artifacts"])
            self.assertEqual(len(set(self.lease_tokens)), 1)
            self.assertTrue(self.migration.barrier_state["artifact_cleanup"]["done"])
            self.assertEqual(self.start(window).status, "running")

    def test_cleanup_claim_wins_and_live_native_retirement_lease_refuses_window(self) -> None:
        self.race(cleanup_first=True)

    def test_window_claim_wins_and_cleanup_waits_without_lease_or_remote_dispatch(self) -> None:
        self.race(cleanup_first=False)
