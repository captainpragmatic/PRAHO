"""Public deployment/drift/registration writers serialize on actual PostgreSQL ownership."""

import secrets
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from typing import cast
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings
from django_q.models import OrmQ

from apps.common.credential_vault import EncryptedCredential
from apps.common.types import Ok, Result
from apps.infrastructure.deployment_lifecycle import reserve_operation
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.drift_remediation import DriftRemediationService
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport, NodeDeployment
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution, NodeMaintenanceWindow
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@skipUnless(connection.vendor == "postgresql", "Public row-lock races require PostgreSQL")
@override_settings(Q_CLUSTER={"name": "maintenance-deployment-races", "orm": "default", "retry": 100000})
class NodeMaintenanceDeploymentPostgresTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def _deployment(self, *, bound: bool = True) -> NodeDeployment:
        deployment = _create_deployment("completed", external_node_id="owned-fixture-resource")
        if bound:
            deployment.virtualmin_server = self.node
            deployment.save(update_fields=["virtualmin_server", "updated_at"])
        return deployment

    def _call(  # noqa: PLR0913 -- each public-writer observation has separate PID and after-SQL latch controls
        self,
        action: Callable[[], object],
        ready: Event,
        pids: list[int],
        *,
        statement: Callable[[str], bool] | None = None,
        acquired: Event | None = None,
        release: Event | None = None,
    ) -> object:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            if statement is None or acquired is None or release is None:
                return action()

            def observe(
                execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
            ) -> object:
                result = execute(sql, params, many, context)
                if statement(sql) and not acquired.is_set():
                    self.assertTrue(connection.in_atomic_block, "Only the public writer's real transaction is held")
                    acquired.set()
                    if not release.wait(15):
                        raise AssertionError("The public SQL holder was not released")
                return result

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _waiting(self, pid: int, owner: int, pending: Future[object], table: str) -> None:
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
                self.assertIn(table, row[2])  # pg_stat_activity may truncate before the FOR UPDATE suffix.
                return
            if pending.done():
                self.fail(f"Public contender did not wait: {pending.result()!r}")
            Event().wait(0.01)
        self.fail(f"No genuine PostgreSQL wait: contender={pid}, holder={owner}, sample={row!r}")

    def _request(self, deployment: NodeDeployment) -> DriftRemediationRequest:
        check = DriftCheck.objects.create(deployment=deployment, check_type="cloud", status="completed")
        report = DriftReport.objects.create(
            drift_check=check,
            deployment=deployment,
            severity="high",
            category="server_state",
            field_name="server_type",
            expected_value="cx11",
            actual_value="cx21",
        )
        return DriftRemediationRequest.objects.create(
            report=report,
            deployment=deployment,
            action_type="apply_desired",
            requires_approval=True,
            requires_restart=False,
        )

    def _window_race(self, *, drift: bool, window_first: bool) -> None:  # noqa: PLR0915 -- both real public winners and their persisted outcomes form one lock experiment
        deployment = self._deployment()
        window = self.window()
        request = self._request(deployment) if drift else None

        def competing() -> object:
            if request is None:
                return reserve_operation(deployment.pk, from_states=("completed",), kind="destroy")
            return DriftRemediationService().approve_remediation(request.pk, self.actor)

        actions: tuple[Callable[[], object], Callable[[], object]] = (lambda: self.start(window), competing)
        if not window_first:
            actions = actions[::-1]
        acquired, release = Event(), Event()
        holder_ready, contender_ready = Event(), Event()
        holder_pids: list[int] = []
        contender_pids: list[int] = []
        queued_before = set(OrmQ.objects.values_list("pk", flat=True))
        server_table = VirtualminServer._meta.db_table
        with ThreadPoolExecutor(max_workers=2) as pool:
            holder = pool.submit(
                self._call,
                actions[0],
                holder_ready,
                holder_pids,
                statement=lambda sql: server_table in sql and "FOR UPDATE" in sql,
                acquired=acquired,
                release=release,
            )
            try:
                self.assertTrue(acquired.wait(15), "The real public writer did not acquire its server lock")
                contender = pool.submit(self._call, actions[1], contender_ready, contender_pids)
                self.assertTrue(contender_ready.wait(15))
                self._waiting(contender_pids[0], holder_pids[0], contender, server_table)
            finally:
                release.set()
            first = holder.result(timeout=15)
            if window_first:
                self.assertIsInstance(first, NodeMaintenanceWindow)
                refused = cast(Result[object, str], contender.result(timeout=15))
                self.assertTrue(refused.is_err())
                self.assertIn("Maintenance", refused.unwrap_err())
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
                self.assertIsNone(NodeDeployment.objects.get(pk=deployment.pk).operation_reserved_at)
                if request is not None:
                    request.refresh_from_db()
                    self.assertEqual(request.status, "pending_approval")
                self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), queued_before)
            else:
                self.assertTrue(cast(Result[object, str], first).is_ok())
                reason = "drift operation" if drift else "deployment operation"
                with self.assertRaisesMessage(ValidationError, reason):
                    contender.result(timeout=15)
                self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
                self.assertFalse(window.executions.exists())
                if request is None:
                    self.assertIsNotNone(NodeDeployment.objects.get(pk=deployment.pk).operation_reserved_at)
                else:
                    request.refresh_from_db()
                    self.assertEqual(request.status, "approved")
                    queued = OrmQ.objects.exclude(pk__in=queued_before)
                    self.assertEqual(queued.count(), 1)
                    self.assertEqual(queued.get().task["func"], "apps.infrastructure.tasks.execute_remediation_task")
                    self.assertEqual(tuple(queued.get().task["args"]), (request.pk,))

    def test_window_claim_wins_over_public_deployment_reservation(self) -> None:
        self._window_race(drift=False, window_first=True)

    def test_public_deployment_reservation_wins_over_window_claim(self) -> None:
        self._window_race(drift=False, window_first=False)

    def test_window_claim_wins_over_public_drift_approval(self) -> None:
        self._window_race(drift=True, window_first=True)

    def test_public_drift_approval_wins_over_window_claim(self) -> None:
        self._window_race(drift=True, window_first=False)

    def _register(self, deployment_id: int) -> Result[VirtualminServer, str]:
        return NodeRegistrationService().register_node(
            NodeDeployment.objects.get(pk=deployment_id), admin_password=secrets.token_urlsafe(32), user=self.actor
        )

    def _reboot(self, deployment_id: int) -> Result[bool, str]:
        return NodeDeploymentService().reboot_node(
            NodeDeployment.objects.get(pk=deployment_id), {"hcloud_token": "fixture-only"}, user=self.actor
        )

    def test_public_registration_wins_then_stale_unbound_native_attempt_refuses(self) -> None:
        deployment = self._deployment(bound=False)
        acquired, release = Event(), Event()
        holder_ready, contender_ready = Event(), Event()
        holder_pids: list[int] = []
        contender_pids: list[int] = []
        deployment_table = NodeDeployment._meta.db_table
        with (
            patch("apps.infrastructure.validation_service.get_validation_service") as validation,
            patch("apps.infrastructure.deployment_service.run_provider_command") as provider,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok("ab" * 32)
            holder = pool.submit(
                self._call,
                lambda: self._register(deployment.pk),
                holder_ready,
                holder_pids,
                statement=lambda sql: (
                    sql.startswith("UPDATE ") and deployment_table in sql and "virtualmin_server_id" in sql
                ),
                acquired=acquired,
                release=release,
            )
            try:
                self.assertTrue(acquired.wait(15), "Registration never completed its real FK UPDATE")
                contender = pool.submit(
                    self._call, lambda: self._reboot(deployment.pk), contender_ready, contender_pids
                )
                self.assertTrue(contender_ready.wait(15))
                self._waiting(contender_pids[0], holder_pids[0], contender, deployment_table)
            finally:
                release.set()
            registered = cast(Result[VirtualminServer, str], holder.result(timeout=15))
            self.assertTrue(registered.is_ok(), registered)
            native = cast(Result[bool, str], contender.result(timeout=15))
            self.assertTrue(native.is_err(), native)
            self.assertIn("binding changed", native.unwrap_err())
            provider.assert_not_called()
            self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).virtualmin_server_id, registered.unwrap().pk)
            self.assertFalse(NodeMaintenanceExecution.objects.filter(deployment=deployment).exists())
            self.assertTrue(EncryptedCredential.objects.filter(service_identifier=deployment.fqdn).exists())

    def test_issued_unbound_native_owner_refuses_registration_before_server_or_vault_writes(self) -> None:
        deployment = self._deployment(bound=False)
        acquired, release, ready = Event(), Event(), Event()
        native_pids: list[int] = []
        boundaries: list[tuple[bool, bool]] = []
        server_ids = set(VirtualminServer.objects.values_list("pk", flat=True))
        credential_ids = set(EncryptedCredential.objects.values_list("pk", flat=True))

        def provider_boundary(**_kwargs: object) -> Ok[ProviderCommandResult]:
            boundaries.append(
                (
                    connection.in_atomic_block,
                    NodeMaintenanceExecution.objects.filter(
                        deployment_id=deployment.pk, node__isnull=True, phase="issued", action="reboot"
                    ).exists(),
                )
            )
            acquired.set()
            if not release.wait(15):
                raise AssertionError("The owned external provider boundary was not released")
            return Ok(ProviderCommandResult(True, "", "", 0, "owned-fixture-provider"))

        with (
            patch("apps.infrastructure.validation_service.get_validation_service") as validation,
            patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=provider_boundary),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok("ab" * 32)
            native = pool.submit(self._call, lambda: self._reboot(deployment.pk), ready, native_pids)
            try:
                self.assertTrue(acquired.wait(15), "Public reboot never reached its external provider boundary")
                self.assertEqual(boundaries, [(False, True)])
                registered = self._register(deployment.pk)
                new_servers = set(VirtualminServer.objects.values_list("pk", flat=True)) - server_ids
                new_credentials = set(EncryptedCredential.objects.values_list("pk", flat=True)) - credential_ids
                self.assertTrue(
                    registered.is_err(),
                    f"Registration crossed issued ownership: created_servers={len(new_servers)}, created_credentials={len(new_credentials)}",
                )
                self.assertIn("operation", registered.unwrap_err().lower())
                self.assertFalse(new_servers)
                self.assertFalse(new_credentials)
                self.assertIsNone(NodeDeployment.objects.get(pk=deployment.pk).virtualmin_server_id)
            finally:
                release.set()
            self.assertTrue(cast(Result[bool, str], native.result(timeout=15)).is_ok())
            execution = NodeMaintenanceExecution.objects.get(deployment=deployment)
            self.assertEqual(execution.phase, "awaiting_recovery")
            self.assertIsNone(execution.node_id)
