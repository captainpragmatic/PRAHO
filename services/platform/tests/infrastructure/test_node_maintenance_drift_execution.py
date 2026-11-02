"""Real approved power recovery publishes customer maintenance before native commands."""

from collections.abc import Callable
from unittest.mock import MagicMock, patch

from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.common.types import Ok
from apps.infrastructure.cloud_gateway import ServerInfo
from apps.infrastructure.drift_remediation import DriftRemediationService
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_service import change_window
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-drift-execution", "orm": "default", "retry": 100000})
class NodeMaintenanceDriftExecutionTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.deployment = _create_deployment("completed", external_node_id="drift-power-fixture")
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

    def execute(
        self, *, on_power: Callable[[], None] | None = None, expect_success: bool = True
    ) -> tuple[object, list[tuple[bool, bool, bool]]]:
        approved = self.service.approve_remediation(self.request.pk, self.actor, restart_approved=True)
        self.assertTrue(approved.is_ok(), approved)
        self.request = approved.unwrap()
        observed: list[tuple[bool, bool, bool]] = []
        gateway = MagicMock()
        gateway.create_snapshot.return_value = Ok("drift-snapshot-fixture")
        gateway.get_server.return_value = Ok(ServerInfo("drift-power-fixture", "node", "running", "1.2.3.4"))

        def power_boundary(*_args: object) -> Ok[bool]:
            observed.append(
                (
                    connection.in_atomic_block,
                    NodeMaintenanceWindow.objects.filter(node=self.node, kind="emergency", status="running").exists(),
                    NodeMaintenanceExecution.objects.filter(
                        deployment=self.deployment,
                        phase="issued",
                        existing_job_type="drift",
                        existing_job_id=str(self.request.pk),
                    ).exists(),
                )
            )
            if on_power is not None:
                on_power()
            return Ok(True)

        gateway.power_on.side_effect = power_boundary
        with (
            patch("apps.infrastructure.drift_remediation.get_provider_token", return_value=Ok("fixture-only")),
            patch("apps.infrastructure.drift_remediation.get_cloud_gateway", return_value=gateway),
            patch("apps.infrastructure.drift_remediation.socket.create_connection"),
            patch("apps.infrastructure.drift_remediation._get_verify_boot_grace", return_value=0),
        ):
            result = self.service.execute_remediation(self.request)
        if expect_success:
            self.assertTrue(result.is_ok(), result)
        self.assertEqual(gateway.power_on.call_count, 1)
        return result, observed

    def test_a_real_approved_power_recovery_creates_emergency_without_an_ordinary_policy(self) -> None:
        NodeMaintenancePolicy.objects.filter(node=self.node).delete()
        result, observed = self.execute()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(observed, [(False, True, True)])
        window = NodeMaintenanceWindow.objects.get(node=self.node)
        self.assertEqual((window.kind, window.status, window.completion_source), ("emergency", "completed", "job"))
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "verified")
        self.assertEqual(window.audience.filter(provenance="execution").count(), 1)

    def test_an_authorized_emergency_supersedes_only_an_unclaimed_future_window(self) -> None:
        ordinary = self.window(future=True)
        result, observed = self.execute()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(observed, [(False, True, True)])
        old = NodeMaintenanceWindow.objects.get(pk=ordinary.pk)
        self.assertEqual((old.status, old.revision), ("cancelled", 2))
        self.assertEqual(old.internal_outcome["code"], "emergency_supersession")
        emergency = NodeMaintenanceWindow.objects.exclude(pk=ordinary.pk).get()
        self.assertEqual(old.internal_outcome["superseded_by"], str(emergency.pk))

    def test_operator_closure_fences_the_same_drift_job_and_its_late_result(self) -> None:
        observed_source: list[str] = []

        def operator_closes() -> None:
            window = NodeMaintenanceWindow.objects.get(node=self.node, status="running")
            change_window(
                window.pk,
                actor=self.actor,
                revision=window.revision,
                action="finish",
                reason="Commands confirmed stopped",
                outcome="failed",
                public_outcome="An operator reviewed the recovery; further work is required.",
                attestation=True,
            )
            observed_source.append(DriftRemediationRequest.objects.get(pk=self.request.pk).status)

        result, _observed = self.execute(on_power=operator_closes, expect_success=False)
        self.assertEqual(observed_source, ["failed"], "Operator closure must also fence the existing source job")
        self.assertTrue(result.is_err(), result)
        self.assertEqual(NodeMaintenanceWindow.objects.get(node=self.node).status, "failed")
        self.assertEqual(DriftRemediationRequest.objects.get(pk=self.request.pk).status, "failed")
