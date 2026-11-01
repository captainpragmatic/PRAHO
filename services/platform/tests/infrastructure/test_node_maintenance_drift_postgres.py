"""Public drift execution and ordinary starts serialize without fabricating job states."""

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from unittest import skipUnless
from unittest.mock import DEFAULT, MagicMock, patch

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.common.types import Err, Ok, Retriability
from apps.infrastructure.cloud_gateway import ServerInfo
from apps.infrastructure.drift_remediation import DriftRemediationService
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport, DriftSnapshot
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceAudience,
    NodeMaintenanceDelivery,
    NodeMaintenanceExecution,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_service import change_window
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "Public lock ordering requires PostgreSQL")
@override_settings(Q_CLUSTER={"name": "maintenance-drift-races", "orm": "default", "retry": 100000})
class NodeMaintenanceDriftPostgresTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.deployment = _create_deployment("completed", external_node_id="owned-drift-race-resource")
        self.deployment.virtualmin_server = self.node
        self.deployment.save(update_fields=["virtualmin_server"])
        check = DriftCheck.objects.create(deployment=self.deployment, check_type="cloud", status="completed")
        report = DriftReport.objects.create(
            drift_check=check,
            deployment=self.deployment,
            severity="high",
            category="server_state",
            field_name="server_status",
            expected_value="running",
            actual_value="off",
        )
        self.request = DriftRemediationRequest.objects.create(
            report=report,
            deployment=self.deployment,
            action_type="apply_desired",
            requires_restart=True,
            action_details={"field_name": "server_status", "expected_value": "running", "actual_value": "off"},
        )
        self.service = DriftRemediationService()
        self.assertTrue(SettingsService.update_setting("infrastructure.remediation_boot_grace_seconds", 0).is_ok())
        self.gateway = MagicMock()
        self.gateway.create_snapshot.return_value = Ok("owned-drift-race-snapshot")

        def snapshot_boundary(*_args: object) -> object:
            self.assertFalse(connection.in_atomic_block)
            self.assertTrue(DriftSnapshot.objects.filter(deployment=self.deployment, status="creating").exists())
            return DEFAULT

        self.gateway.create_snapshot.side_effect = snapshot_boundary
        self.gateway.get_server.return_value = Ok(
            ServerInfo("owned-drift-race-resource", "fixture", "running", "1.2.3.4")
        )
        self.observed: list[tuple[bool, bool, bool]] = []

        def power_boundary(*_args: object) -> Ok[bool]:
            self.observed.append(
                (
                    connection.in_atomic_block,
                    NodeMaintenanceWindow.objects.filter(node=self.node, kind="emergency", status="running").exists(),
                    NodeMaintenanceExecution.objects.filter(
                        deployment=self.deployment,
                        existing_job_type="drift",
                        existing_job_id=str(self.request.pk),
                        phase="issued",
                    ).exists(),
                )
            )
            return Ok(True)

        self.gateway.power_on.side_effect = power_boundary
        for seam in (
            patch("apps.infrastructure.drift_remediation.get_provider_token", return_value=Ok("fixture-only")),
            patch("apps.infrastructure.drift_remediation.get_cloud_gateway", return_value=self.gateway),
            patch("apps.infrastructure.drift_remediation.socket.create_connection"),
        ):
            seam.start()
            self.addCleanup(seam.stop)

    def _approve(self) -> None:
        result = self.service.approve_remediation(self.request.pk, self.actor, restart_approved=True)
        self.assertTrue(result.is_ok(), result)
        self.request = result.unwrap()

    def _execute(self) -> object:
        return self.service.execute_remediation(DriftRemediationRequest.objects.get(pk=self.request.pk))

    def _call(
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
                    self.assertTrue(connection.in_atomic_block)
                    acquired.set()
                    if not release.wait(15):
                        raise AssertionError("The actual public server-lock holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _waiting(self, pid: int, owner: int, pending: Future[object]) -> None:
        deadline = monotonic() + 15
        row = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid=%s", [pid]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and owner in row[1]:
                self.assertTrue(row[2].startswith("SELECT "))
                self.assertIn(VirtualminServer._meta.db_table, row[2])
                return
            if pending.done():
                self.fail(f"The public contender did not wait: {pending.result()!r}")
            Event().wait(0.01)
        self.fail(f"No exact PostgreSQL lock wait: contender={pid}, holder={owner}, sample={row!r}")

    def _future_start_race(self, *, ordinary_first: bool) -> None:
        ordinary = self.window(future=True)
        self._approve()

        def ordinary_start() -> ValidationError:
            try:
                self.start(ordinary)
            except ValidationError as exc:
                return exc
            raise AssertionError("A future ordinary window started despite its approved drift owner")

        actions: tuple[Callable[[], object], Callable[[], object]] = (ordinary_start, self._execute)
        if not ordinary_first:
            actions = actions[::-1]
        acquired, release = Event(), Event()
        first_ready, second_ready = Event(), Event()
        first_pids: list[int] = []
        second_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            holder = pool.submit(self._call, actions[0], first_ready, first_pids, acquired, release)
            try:
                self.assertTrue(acquired.wait(15))
                contender = pool.submit(self._call, actions[1], second_ready, second_pids)
                self.assertTrue(second_ready.wait(15))
                self._waiting(second_pids[0], first_pids[0], contender)
            finally:
                release.set()
            first, second = holder.result(timeout=15), contender.result(timeout=15)
        refusal, executed = (first, second) if ordinary_first else (second, first)
        self.assertIsInstance(refusal, ValidationError)
        expected_refusal = "permitted latest-start" if ordinary_first else "window changed"
        self.assertIn(expected_refusal, str(refusal))
        self.assertTrue(executed.is_ok(), executed)
        ordinary.refresh_from_db()
        self.assertEqual((ordinary.status, ordinary.revision), ("cancelled", 2))
        self.assertIsNone(ordinary.current_execution_id)
        emergency = NodeMaintenanceWindow.objects.exclude(pk=ordinary.pk).get()
        self.assertEqual(
            (emergency.kind, emergency.status, emergency.completion_source), ("emergency", "completed", "job")
        )
        self.assertEqual(ordinary.internal_outcome["superseded_by"], str(emergency.pk))
        execution = NodeMaintenanceExecution.objects.get()
        self.assertEqual(
            (execution.window_id, execution.phase, execution.existing_job_id),
            (emergency.pk, "verified", str(self.request.pk)),
        )
        self.request.refresh_from_db()
        self.assertEqual(self.request.status, "completed")
        self.assertEqual(self.observed, [(False, True, True)])
        self.gateway.create_snapshot.assert_called_once()
        self.gateway.power_on.assert_called_once()
        self.gateway.restore_snapshot.assert_not_called()

    def test_future_ordinary_start_holds_server_first_then_drift_supersedes_it(self) -> None:
        self._future_start_race(ordinary_first=True)

    def test_drift_holds_server_first_then_future_ordinary_start_is_refused(self) -> None:
        self._future_start_race(ordinary_first=False)

    def test_a_due_unclaimed_ordinary_window_and_approved_drift_both_refuse_native_work(self) -> None:
        ordinary = self.window()
        self._approve()

        with self.assertRaisesMessage(ValidationError, "drift operation"):
            self.start(ordinary)
        result = self._execute()

        self.assertTrue(result.is_err(), result)
        self.assertIn("cannot preempt", result.unwrap_err())
        ordinary.refresh_from_db()
        self.assertEqual((ordinary.status, ordinary.revision), ("scheduled", 1))
        self.assertEqual(NodeMaintenanceWindow.objects.count(), 1)
        self.assertFalse(NodeMaintenanceExecution.objects.exists())
        self.request.refresh_from_db()
        self.assertEqual(self.request.status, "approved")
        self.gateway.create_snapshot.assert_not_called()
        self.gateway.power_on.assert_not_called()

        change_window(
            ordinary.pk,
            actor=self.actor,
            revision=ordinary.revision,
            action="cancel",
            reason="Explicitly release the due ordinary window for the approved server recovery",
        )
        recovered = self._execute()

        self.assertTrue(recovered.is_ok(), recovered)
        ordinary.refresh_from_db()
        self.assertEqual(ordinary.status, "cancelled")
        self.request.refresh_from_db()
        self.assertEqual(self.request.status, "completed")
        self.assertEqual(self.observed, [(False, True, True)])
        self.gateway.power_on.assert_called_once()

    def test_a_failed_public_execution_replay_rolls_back_its_lost_cas_emergency_publication(self) -> None:
        self._approve()
        self.gateway.create_snapshot.return_value = Err(
            "Provider refused snapshot", retriability=Retriability.NOT_RETRIABLE
        )
        first = self._execute()
        self.assertTrue(first.is_err(), first)
        self.request.refresh_from_db()
        self.assertEqual(self.request.status, "failed")
        self.assertFalse(DriftReport.objects.get(pk=self.request.report_id).resolved)
        models = (
            NodeMaintenanceWindow,
            NodeMaintenanceExecution,
            NodeMaintenanceAudience,
            NodeMaintenanceDelivery,
            DriftSnapshot,
        )
        before = tuple(set(model.objects.values_list("pk", flat=True)) for model in models)

        replay = self._execute()

        self.assertTrue(replay.is_err(), replay)
        self.assertIn("Cannot execute remediation in status 'failed'", replay.unwrap_err())
        self.assertEqual(tuple(set(model.objects.values_list("pk", flat=True)) for model in models), before)
        self.gateway.create_snapshot.assert_called_once()
        self.gateway.power_on.assert_not_called()
