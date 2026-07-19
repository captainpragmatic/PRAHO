"""
Tests for DriftRemediationService

Tests the remediation workflow: approve, reject, schedule, execute, rollback.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.conf import settings as django_settings
from django.test import TestCase
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import Schedule

from apps.common.types import Err, Ok
from apps.infrastructure.apps import InfrastructureConfig
from apps.infrastructure.cloud_gateway import ServerInfo
from apps.infrastructure.drift_remediation import EXECUTION_TASK_TIMEOUT_SECONDS, DriftRemediationService
from apps.infrastructure.models import (
    CloudProvider,
    DriftCheck,
    DriftRemediationRequest,
    DriftReport,
    DriftSnapshot,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)
from apps.infrastructure.tasks import apply_scheduled_remediations_task, recover_stale_remediations_task
from apps.users.models import User


class DriftRemediationTestBase(TestCase):
    """Base test class with common setup for drift remediation tests."""

    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="het",
            credential_identifier="test-cred",
        )
        self.region = NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        self.size = NodeSize.objects.create(
            provider=self.provider,
            name="Small",
            display_name="2 vCPU / 4GB",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.0100",
            monthly_cost_eur="5.00",
        )
        self.panel = PanelType.objects.create(
            name="Virtualmin GPL",
            panel_type="virtualmin",
            ansible_playbook="virtualmin.yml",
        )
        self.deployment = NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            node_size=self.size,
            region=self.region,
            panel_type=self.panel,
            hostname="prd-sha-het-de-fsn1-001",
            node_number=1,
            status="completed",
            external_node_id="12345",
            ipv4_address="1.2.3.4",
        )
        self.check = DriftCheck.objects.create(
            deployment=self.deployment,
            check_type="cloud",
            status="completed",
        )
        self.report = DriftReport.objects.create(
            drift_check=self.check,
            deployment=self.deployment,
            severity="high",
            category="server_state",
            field_name="server_type",
            expected_value="cpx21",
            actual_value="cpx41",
        )
        self.remediation_request = DriftRemediationRequest.objects.create(
            report=self.report,
            deployment=self.deployment,
            action_type="apply_desired",
            action_details={
                "field_name": "server_type",
                "expected_value": "cpx21",
                "actual_value": "cpx41",
            },
            requires_approval=True,
            requires_restart=True,
        )
        self.service = DriftRemediationService()

    def _make_report(self, field_name: str = "ipv4_address", deployment: NodeDeployment | None = None) -> DriftReport:
        """Another open report — the open-request-per-report constraint means
        sibling requests in tests must attach to their own reports."""
        deployment = deployment or self.deployment
        return DriftReport.objects.create(
            drift_check=self.check,
            deployment=deployment,
            severity="critical",
            category="network",
            field_name=field_name,
            expected_value="1.2.3.4",
            actual_value="5.6.7.8",
        )

    def _make_deployment(self, node_number: int) -> NodeDeployment:
        return NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            node_size=self.size,
            region=self.region,
            panel_type=self.panel,
            hostname=f"prd-sha-het-de-fsn1-{node_number:03d}",
            node_number=node_number,
            status="completed",
            external_node_id=f"1234{node_number}",
            ipv4_address="1.2.3.5",
        )


class TestApproveReject(DriftRemediationTestBase):
    """Tests for approve/reject workflows."""

    @patch("django_q.tasks.async_task", return_value="task-123")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService.execute_remediation")
    def test_approve_flow(self, mock_execute, mock_async):
        """Approving sets status=approved and queues execution, never runs it inline."""
        result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "approved")
        self.assertEqual(self.remediation_request.approved_by, self.admin)
        self.assertIsNotNone(self.remediation_request.approved_at)
        self.assertIsNotNone(self.remediation_request.execution_claimed_at)

        mock_execute.assert_not_called()
        mock_async.assert_called_once_with(
            "apps.infrastructure.tasks.execute_remediation_task",
            self.remediation_request.pk,
            task_name=f"remediation_{self.remediation_request.pk}",
            timeout=EXECUTION_TASK_TIMEOUT_SECONDS,
        )

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_approve_manual_intervention_rejected(self, mock_async):
        """Manual-intervention requests cannot be approved for execution."""
        self.remediation_request.action_type = "manual_intervention"
        self.remediation_request.save(update_fields=["action_type"])

        result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_err())
        self.assertIn("no automated fix", result.unwrap_err())
        mock_async.assert_not_called()

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "pending_approval")

    def test_schedule_manual_intervention_rejected(self):
        """Manual-intervention requests cannot be scheduled either."""
        self.remediation_request.action_type = "manual_intervention"
        self.remediation_request.save(update_fields=["action_type"])

        result = self.service.schedule_remediation(
            self.remediation_request.pk, self.admin, timezone.now() + timedelta(hours=2)
        )
        self.assertTrue(result.is_err())
        self.assertIn("no automated fix", result.unwrap_err())

    def test_reject_flow(self):
        """Rejecting should set status=rejected with reason."""
        result = self.service.reject_remediation(
            self.remediation_request.pk, self.admin, "Not needed"
        )
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "rejected")
        self.assertEqual(self.remediation_request.rejected_reason, "Not needed")

    def test_schedule_flow(self):
        """Scheduling should set status=scheduled with datetime."""
        future = timezone.now() + timedelta(hours=2)
        result = self.service.schedule_remediation(
            self.remediation_request.pk, self.admin, future
        )
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "scheduled")
        self.assertEqual(self.remediation_request.scheduled_for, future)

    def test_accept_drift(self):
        """Accepting drift updates the deployment record and marks resolved."""
        bigger = NodeSize.objects.create(
            provider=self.provider,
            name="Medium",
            display_name="4 vCPU / 8GB",
            provider_type_id="cpx41",
            vcpus=4,
            memory_gb=8,
            disk_gb=80,
            hourly_cost_eur="0.0200",
            monthly_cost_eur="10.00",
        )

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")
        self.assertEqual(self.remediation_request.action_type, "accept_actual")

        self.report.refresh_from_db()
        self.assertTrue(self.report.resolved)
        self.assertEqual(self.report.resolution_type, "accepted")
        self.assertEqual(self.report.resolved_by, self.admin)

        # The durable write-back: node_size now matches the observed reality
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.node_size, bigger)

    def test_accept_drift_server_type_requires_matching_node_size(self):
        """Accepting a size PRAHO does not know about is refused, not faked."""
        result = self.service.accept_drift(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_err())
        self.assertIn("No NodeSize matches", result.unwrap_err())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "pending_approval")
        self.report.refresh_from_db()
        self.assertFalse(self.report.resolved)

    def _reshape_report(self, field_name: str, expected: str, actual: str) -> None:
        self.report.field_name = field_name
        self.report.expected_value = expected
        self.report.actual_value = actual
        self.report.save(update_fields=["field_name", "expected_value", "actual_value"])

    def test_accept_drift_writes_ipv4_to_deployment(self):
        self._reshape_report("ipv4_address", "1.2.3.4", "5.6.7.8")

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_ok())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.ipv4_address, "5.6.7.8")

    def test_accept_drift_writes_ipv6_to_deployment(self):
        self.deployment.ipv6_address = "2001:db8::1"
        self.deployment.save(update_fields=["ipv6_address"])
        self._reshape_report("ipv6_address", "2001:db8::1", "2001:db8::99")

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_ok())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.ipv6_address, "2001:db8::99")

    def test_accept_drift_rejects_invalid_observed_address(self):
        self._reshape_report("ipv4_address", "1.2.3.4", "not-an-ip")

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.ipv4_address, "1.2.3.4")

    def test_accept_drift_powered_off_server_stops_deployment(self):
        """Accepting an off server declares it intentionally stopped — it leaves scan scope."""
        self._reshape_report("server_status", "running", "off")

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_ok())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "stopped")

    def test_accept_drift_transient_server_status_refused(self):
        """Only genuinely powered-off states are acceptable as 'stopped'."""
        self._reshape_report("server_status", "running", "rebooting")

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "completed")

    def test_accept_drift_refused_for_non_writable_fields(self):
        """network/server_deleted drift has no durable write — Accept is refused."""
        for field in ("network_unreachable", "server_deleted"):
            self._reshape_report(field, "expected", "actual")

            result = self.service.accept_drift(self.remediation_request.pk, self.admin)

            self.assertTrue(result.is_err(), field)
            self.assertIn("cannot be accepted", result.unwrap_err())
            self.remediation_request.refresh_from_db()
            self.assertEqual(self.remediation_request.status, "pending_approval")

    def test_cannot_approve_already_completed(self):
        """Cannot approve a completed request."""
        self.remediation_request.status = "completed"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_err())
        self.assertIn("Cannot approve", result.unwrap_err())

    def test_cannot_approve_already_rejected(self):
        """Cannot approve a rejected request."""
        self.remediation_request.status = "rejected"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_err())


class TestExecuteRemediation(DriftRemediationTestBase):
    """Tests for remediation execution with snapshot safety."""

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_execute_remediation_success(self, mock_snapshot, mock_gateway, mock_health):
        """Full success flow: snapshot -> apply -> verify."""
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-123",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)

        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw
        mock_health.return_value = Ok(None)

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_snapshot_taken_before_apply(self, mock_snapshot):
        """Snapshot should be taken before remediation."""
        mock_snapshot.return_value = Err("Snapshot failed")

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        mock_snapshot.assert_called_once()

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._rollback")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_rollback_on_health_check_failure(self, mock_snapshot, mock_gateway, mock_health, mock_rollback):
        """Health check failure should trigger rollback."""
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-456",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)

        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw
        mock_health.return_value = Err("Server unreachable")
        mock_rollback.return_value = Ok(True)

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        mock_rollback.assert_called_once()

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "rolled_back")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._rollback")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_execute_remediation_apply_fails(self, mock_snapshot, mock_gateway, mock_rollback):
        """Apply failure should trigger rollback."""
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-789",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)

        mock_gw = MagicMock()
        mock_gw.resize.return_value = Err("Resize failed")
        # New contract: apply-Err alone no longer restores — the provider must
        # be OBSERVED in the wrong state for the rollback to stay justified.
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="prd-sha-het-de-fsn1-001",
                status="running",
                ipv4_address="1.2.3.4",
                server_type="cpx41",
            )
        )
        mock_gateway.return_value = mock_gw
        mock_rollback.return_value = Ok(True)

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        mock_rollback.assert_called_once()

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_concurrent_remediation_prevented(self, mock_snapshot, mock_gateway, mock_health):
        """Only one active remediation per deployment."""
        # Create an existing in-progress remediation (on its own report — only
        # one open request may exist per report)
        DriftRemediationRequest.objects.create(
            report=self._make_report(),
            deployment=self.deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=timezone.now(),
        )

        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-000",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        self.assertIn("already in progress", result.unwrap_err())

    def test_remediation_requires_restart_flag(self):
        """server_type changes should have requires_restart=True."""
        self.assertTrue(self.remediation_request.requires_restart)

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_execute_fails_fast_for_unfixable_field_without_snapshot(self, mock_snapshot):
        """Unfixable fields must fail before any snapshot — no no-op 'remediated', no rollback."""
        self.report.field_name = "ipv4_address"
        self.report.expected_value = "1.2.3.4"
        self.report.actual_value = "5.6.7.8"
        self.report.save(update_fields=["field_name", "expected_value", "actual_value"])
        self.remediation_request.status = "approved"
        self.remediation_request.action_details = {
            "field_name": "ipv4_address",
            "expected_value": "1.2.3.4",
            "actual_value": "5.6.7.8",
        }
        self.remediation_request.save(update_fields=["status", "action_details"])

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        self.assertIn("No automated fix", result.unwrap_err())
        mock_snapshot.assert_not_called()

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")
        self.assertIn("manual intervention required", self.remediation_request.error_message)

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_execute_fails_fast_for_manual_action_type(self, mock_snapshot):
        """manual_intervention requests are never executable, whatever the field."""
        self.remediation_request.status = "approved"
        self.remediation_request.action_type = "manual_intervention"
        self.remediation_request.save(update_fields=["status", "action_type"])

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        mock_snapshot.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")


class TestReviewHardening(DriftRemediationTestBase):
    """Regression tests for the adversarial-review findings."""

    def test_reject_cannot_overwrite_in_progress(self):
        """A stale reject must lose against a concurrent claim (CAS, not blind save)."""
        self.remediation_request.status = "in_progress"
        self.remediation_request.started_at = timezone.now()
        self.remediation_request.save(update_fields=["status", "started_at"])

        result = self.service.reject_remediation(self.remediation_request.pk, self.admin, "too late")

        self.assertTrue(result.is_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "in_progress")

    def test_schedule_cannot_overwrite_in_progress(self):
        self.remediation_request.status = "in_progress"
        self.remediation_request.started_at = timezone.now()
        self.remediation_request.save(update_fields=["status", "started_at"])

        result = self.service.schedule_remediation(
            self.remediation_request.pk, self.admin, timezone.now() + timedelta(hours=1)
        )

        self.assertTrue(result.is_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "in_progress")

    def test_accept_refused_while_sibling_execution_in_progress(self):
        """Accepting a power-off must not race a running remediation."""
        self.report.field_name = "server_status"
        self.report.expected_value = "running"
        self.report.actual_value = "off"
        self.report.save(update_fields=["field_name", "expected_value", "actual_value"])
        DriftRemediationRequest.objects.create(
            report=self._make_report(),
            deployment=self.deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=timezone.now(),
        )

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.assertIn("retry once it settles", result.unwrap_err())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "completed")

    def test_accept_refused_when_report_resolved_meanwhile(self):
        self.report.resolved = True
        self.report.save(update_fields=["resolved"])

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.assertIn("resolved in the meantime", result.unwrap_err())

    def test_is_acceptable_false_for_transitional_server_status(self):
        self.report.field_name = "server_status"
        self.report.actual_value = "rebooting"
        self.assertFalse(self.report.is_acceptable)
        self.report.actual_value = "off"
        self.assertTrue(self.report.is_acceptable)

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_stale_claimed_approved_is_requeued(self, mock_async):
        """The PRIMARY orphan shape: claimed for execution, task lost, claim aged out."""
        self.remediation_request.status = "approved"
        self.remediation_request.approved_at = timezone.now() - timedelta(days=1)
        self.remediation_request.execution_claimed_at = timezone.now() - timedelta(minutes=45)
        self.remediation_request.save(update_fields=["status", "approved_at", "execution_claimed_at"])

        result = recover_stale_remediations_task()

        self.assertEqual(result["requeued_count"], 1)
        mock_async.assert_called_once()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "approved")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_execute_remediation_task_resolves_and_runs(self, mock_snapshot, mock_gateway, mock_verify):
        """The dotted-path task target actually exists and drives execution."""
        task = import_string("apps.infrastructure.tasks.execute_remediation_task")
        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-task",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)
        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw
        mock_verify.return_value = Ok(None)

        outcome = task(self.remediation_request.pk)

        self.assertEqual(outcome, {"status": "completed"})
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._rollback")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_failed_rollback_is_reported_as_rollback_failed(
        self, mock_snapshot, mock_gateway, mock_verify, mock_rollback
    ):
        """A failed snapshot restore must never masquerade as a clean rollback."""
        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-rbf",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)
        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw
        mock_verify.return_value = Err("Server unreachable")
        mock_rollback.return_value = Err("restore failed")

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "rollback_failed")
        self.assertIn("restore failed", self.remediation_request.error_message)

    def test_recover_stale_remediations_schedule_registered(self):
        """Deleting the apps.py schedule entry must not go unnoticed."""
        InfrastructureConfig._schedule_infrastructure_tasks(sender=InfrastructureConfig)

        schedule = Schedule.objects.get(name="infra_recover_stale_remediations")
        self.assertEqual(schedule.func, "apps.infrastructure.tasks.recover_stale_remediations_task")
        self.assertEqual(schedule.minutes, 15)


class TestCleanupSnapshots(DriftRemediationTestBase):
    """Tests for snapshot cleanup."""

    def test_cleanup_expired_snapshots(self):
        """Old snapshots should be deletable."""
        DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-old",
            snapshot_type="pre_remediation",
            status="available",
            expires_at=timezone.now() - timedelta(days=1),
        )
        expired = DriftSnapshot.objects.filter(
            expires_at__lte=timezone.now(), status="available"
        )
        self.assertEqual(expired.count(), 1)
        self.assertEqual(expired.first().provider_snapshot_id, "snap-old")


class TestExecutionClaim(DriftRemediationTestBase):
    """Tests for the claim gate: status precondition, lifecycle and fingerprint checks."""

    def setUp(self) -> None:
        super().setUp()
        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

    def test_execute_requires_approved_status(self):
        """Q-retry re-entry or API misuse cannot re-execute a settled request."""
        self.remediation_request.status = "completed"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        self.assertIn("Cannot execute remediation in status", result.unwrap_err())

    def test_execute_superseded_when_deployment_left_scan_scope(self):
        """A stopped/destroyed deployment must never be remediated."""
        self.deployment.status = "stopped"
        self.deployment.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        self.assertIn("left scan scope", result.unwrap_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "superseded")

    def test_execute_superseded_when_report_resolved(self):
        """A report resolved after approval leaves nothing to remediate."""
        self.report.resolved = True
        self.report.save(update_fields=["resolved"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "superseded")

    def test_execute_fails_when_fingerprint_stale(self):
        """A request approved against older drift values must not execute them."""
        self.report.expected_value = "cpx31"
        self.report.save(update_fields=["expected_value"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        self.assertIn("Drift changed since approval", result.unwrap_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_stale_in_progress_is_reaped_inline_and_new_claim_succeeds(
        self, mock_snapshot, mock_gateway, mock_verify
    ):
        """One crashed execution can never block a deployment forever."""
        stale = DriftRemediationRequest.objects.create(
            report=self._make_report(),
            deployment=self.deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=timezone.now() - timedelta(minutes=31),
        )
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-claim",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)
        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw
        mock_verify.return_value = Ok(None)

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_ok())
        stale.refresh_from_db()
        self.assertEqual(stale.status, "failed")
        self.assertIn("auto-recovered", stale.error_message)
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_completion_refuses_externally_transitioned_row(self, mock_snapshot, mock_gateway, mock_verify):
        """A row the recovery task reaped mid-flight is never overwritten to completed."""
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-cas",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)
        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw

        def _reap_then_ok(*args, **kwargs):
            DriftRemediationRequest.objects.filter(pk=self.remediation_request.pk).update(status="failed")
            return Ok(None)

        mock_verify.side_effect = _reap_then_ok

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        self.assertIn("externally transitioned", result.unwrap_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")
        self.report.refresh_from_db()
        self.assertFalse(self.report.resolved)


class TestRecoverStaleRemediations(DriftRemediationTestBase):
    """Tests for the periodic recovery task (three sweeps)."""

    def _run_task(self) -> dict:
        return recover_stale_remediations_task()

    def test_stale_in_progress_marked_failed_fresh_untouched(self):
        stale = DriftRemediationRequest.objects.create(
            report=self._make_report(),
            deployment=self.deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=timezone.now() - timedelta(minutes=31),
        )
        # A fresh execution on a DIFFERENT deployment (only one in_progress is
        # allowed per deployment) must be left alone.
        other_deployment = self._make_deployment(2)
        fresh = DriftRemediationRequest.objects.create(
            report=self._make_report(deployment=other_deployment),
            deployment=other_deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=timezone.now(),
        )

        result = self._run_task()

        stale.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual(stale.status, "failed")
        self.assertIn("auto-recovered", stale.error_message)
        self.assertEqual(fresh.status, "in_progress")
        self.assertEqual(result["recovered_count"], 1)

    def test_in_progress_without_started_at_treated_as_stale(self):
        anomalous = DriftRemediationRequest.objects.create(
            report=self._make_report(),
            deployment=self.deployment,
            action_type="apply_desired",
            status="in_progress",
            started_at=None,
        )
        # created_at is auto_now_add; age it past the threshold
        DriftRemediationRequest.objects.filter(pk=anomalous.pk).update(
            created_at=timezone.now() - timedelta(minutes=31)
        )

        self._run_task()

        anomalous.refresh_from_db()
        self.assertEqual(anomalous.status, "failed")

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_orphaned_approved_is_requeued_not_failed(self, mock_async):
        """Human approval is re-driven, never silently discarded."""
        self.remediation_request.status = "approved"
        self.remediation_request.approved_at = timezone.now() - timedelta(minutes=45)
        self.remediation_request.save(update_fields=["status", "approved_at"])

        result = self._run_task()

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "approved")
        self.assertIsNotNone(self.remediation_request.execution_claimed_at)
        mock_async.assert_called_once_with(
            "apps.infrastructure.tasks.execute_remediation_task",
            self.remediation_request.pk,
            task_name=f"remediation_{self.remediation_request.pk}",
            timeout=EXECUTION_TASK_TIMEOUT_SECONDS,
        )
        self.assertEqual(result["requeued_count"], 1)

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_just_claimed_approved_is_left_alone(self, mock_async):
        """A freshly claimed batch row must not be double-enqueued by the reaper."""
        self.remediation_request.status = "approved"
        self.remediation_request.approved_at = timezone.now() - timedelta(days=2)  # human approved long ago
        self.remediation_request.execution_claimed_at = timezone.now()  # just claimed for execution
        self.remediation_request.save(update_fields=["status", "approved_at", "execution_claimed_at"])

        result = self._run_task()

        mock_async.assert_not_called()
        self.assertEqual(result["requeued_count"], 0)

    def test_out_of_scope_deployment_drift_is_swept(self):
        self.deployment.status = "stopped"
        self.deployment.save(update_fields=["status"])

        result = self._run_task()

        self.report.refresh_from_db()
        self.remediation_request.refresh_from_db()
        self.assertTrue(self.report.resolved)
        self.assertEqual(self.report.resolution_type, "superseded")
        self.assertEqual(self.remediation_request.status, "superseded")
        self.assertEqual(result["swept_reports"], 1)
        self.assertEqual(result["swept_requests"], 1)


class TestApplyScheduledRemediations(DriftRemediationTestBase):
    """Tests for the per-row claim + enqueue scheduled task."""

    @patch("django_q.tasks.async_task", return_value="task-123")
    def test_due_scheduled_requests_claimed_and_enqueued_individually(self, mock_async):
        self.remediation_request.status = "scheduled"
        self.remediation_request.scheduled_for = timezone.now() - timedelta(minutes=5)
        self.remediation_request.save(update_fields=["status", "scheduled_for"])

        result = apply_scheduled_remediations_task()

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "approved")
        self.assertIsNotNone(self.remediation_request.execution_claimed_at)
        mock_async.assert_called_once_with(
            "apps.infrastructure.tasks.execute_remediation_task",
            self.remediation_request.pk,
            task_name=f"remediation_{self.remediation_request.pk}",
            timeout=EXECUTION_TASK_TIMEOUT_SECONDS,
        )
        self.assertEqual(result, {"claimed": 1, "due": 1})


class _FakeClock:
    """Deterministic stand-in for the module's _monotonic/_sleep aliases."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _verify_settings(key: str, default: int) -> int:
    return {
        "infrastructure.remediation_boot_grace_seconds": 30,
        "infrastructure.remediation_verify_max_wait_seconds": 150,
        "infrastructure.remediation_verify_poll_interval_seconds": 10,
        "infrastructure.health_check_timeout_seconds": 10,
    }.get(key, default)


@patch("apps.settings.services.SettingsService.get_integer_setting", side_effect=_verify_settings)
class TestVerifyRemediation(DriftRemediationTestBase):
    """Tests for the bounded, outcome-aware verification loop."""

    def setUp(self) -> None:
        super().setUp()
        self.clock = _FakeClock()
        clock_patches = [
            patch("apps.infrastructure.drift_remediation._monotonic", self.clock.monotonic),
            patch("apps.infrastructure.drift_remediation._sleep", self.clock.sleep),
        ]
        for p in clock_patches:
            p.start()
            self.addCleanup(p.stop)

    def _server(self, status: str = "running", server_type: str = "cpx21") -> ServerInfo:
        return ServerInfo(
            server_id="12345",
            name=self.deployment.hostname,
            status=status,
            ipv4_address="1.2.3.4",
            server_type=server_type,
        )

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_verify_remediation_polls_outcome_within_budget(self, mock_conn, _settings):
        """Provider still converging on the first poll must not fail verification."""
        gateway = MagicMock()
        gateway.get_server.side_effect = [
            Ok(self._server(server_type="cpx41")),
            Ok(self._server(server_type="cpx21")),
        ]
        result = self.service._verify_remediation(self.deployment, gateway, "server_type", "cpx21")

        self.assertTrue(result.is_ok())
        self.assertEqual(gateway.get_server.call_count, 2)
        self.assertEqual(self.clock.sleeps[0], 30)  # boot grace before first probe

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_power_on_waits_for_running_status(self, mock_conn, _settings):
        """server_status remediation verifies the provider reports running."""
        gateway = MagicMock()
        gateway.get_server.side_effect = [
            Ok(self._server(status="starting")),
            Ok(self._server(status="running")),
        ]
        result = self.service._verify_remediation(self.deployment, gateway, "server_status", "running")

        self.assertTrue(result.is_ok())
        self.assertEqual(gateway.get_server.call_count, 2)

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_outcome_deadline_exhausted_errs_without_ssh_probe(self, mock_conn, _settings):
        """A provider that never converges fails verification after the budget."""
        gateway = MagicMock()
        gateway.get_server.return_value = Ok(self._server(server_type="cpx41"))

        result = self.service._verify_remediation(self.deployment, gateway, "server_type", "cpx21")

        self.assertTrue(result.is_err())
        self.assertIn("not confirmed by provider", result.unwrap_err())
        self.assertLessEqual(self.clock.now, 151)
        mock_conn.assert_not_called()

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_ssh_retries_until_reachable(self, mock_conn, _settings):
        """Connection-refused during boot is retried, not treated as failure."""
        gateway = MagicMock()
        gateway.get_server.return_value = Ok(self._server())
        mock_conn.side_effect = [OSError("refused"), OSError("refused"), MagicMock()]

        result = self.service._verify_remediation(self.deployment, gateway, "server_status", "running")

        self.assertTrue(result.is_ok())
        self.assertEqual(mock_conn.call_count, 3)

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_ssh_deadline_exhausted_is_inconclusive_not_rollback(self, mock_conn, _settings):
        """Provider confirmed + SSH dead = Ok(False): fail WITHOUT snapshot restore."""
        gateway = MagicMock()
        gateway.get_server.return_value = Ok(self._server())
        mock_conn.side_effect = OSError("refused")

        result = self.service._verify_remediation(self.deployment, gateway, "server_status", "running")

        self.assertTrue(result.is_ok())
        inconclusive = result.unwrap()
        self.assertIsNotNone(inconclusive)
        self.assertIn("manual check required", inconclusive)

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_ipv6_only_deployment_skips_reachability_probe(self, mock_conn, _settings):
        """No IPv4 address: a confirmed provider outcome must not be rolled back."""
        self.deployment.ipv4_address = None
        self.deployment.save(update_fields=["ipv4_address"])
        gateway = MagicMock()
        gateway.get_server.return_value = Ok(self._server())

        result = self.service._verify_remediation(self.deployment, gateway, "server_status", "running")

        self.assertTrue(result.is_ok())
        self.assertIsNone(result.unwrap())
        mock_conn.assert_not_called()

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._rollback")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_inconclusive_verification_fails_without_rollback(self, mock_snapshot, mock_gateway, mock_rollback, _settings):
        """An inconclusive verification marks the request failed and never restores the snapshot."""
        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])
        snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-inconclusive",
            snapshot_type="pre_remediation",
            status="available",
        )
        mock_snapshot.return_value = Ok(snapshot)
        mock_gw = MagicMock()
        mock_gw.resize.return_value = Ok(True)
        mock_gateway.return_value = mock_gw

        with patch(
            "apps.infrastructure.drift_remediation.DriftRemediationService._verify_remediation",
            return_value=Ok("Provider confirms the remediation but the server is silent — manual check required"),
        ):
            result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        self.assertIn("manual check required", result.unwrap_err())
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    def test_probe_timeout_clamped_to_remaining_budget(self, mock_conn, _settings):
        """Near the deadline the socket timeout must not overshoot the budget."""
        mock_conn.return_value = MagicMock()

        result = self.service._verify_health(self.deployment, deadline=self.clock.now + 3)

        self.assertTrue(result.is_ok())
        self.assertEqual(mock_conn.call_args.kwargs["timeout"], 3)


class TestAuditEvents(DriftRemediationTestBase):
    """Tests for audit event logging."""

    @patch("django_q.tasks.async_task", return_value="task-123")
    @patch("apps.infrastructure.drift_remediation.InfrastructureAuditService.log_drift_remediation_approved")
    def test_audit_events_logged(self, mock_audit, mock_async):
        """Audit events should be logged on approval."""
        self.service.approve_remediation(self.remediation_request.pk, self.admin)
        mock_audit.assert_called_once()


class TestDestructivePathPreconditions(DriftRemediationTestBase):
    """The destructive restore must re-validate its justification at the moment it acts.

    Snapshot restore is a full rebuild: it may only run when the provider was
    OBSERVED in the wrong state — never on ambiguity (API unreachable, polling
    hiccups) and never after the drift healed or the request left in_progress.
    """

    def setUp(self) -> None:
        super().setUp()
        self.clock = _FakeClock()
        for p in (
            patch("apps.infrastructure.drift_remediation._monotonic", self.clock.monotonic),
            patch("apps.infrastructure.drift_remediation._sleep", self.clock.sleep),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="snap-pre",
            snapshot_type="pre_remediation",
            status="available",
        )

    def _approve(self) -> None:
        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

    def _server(self, server_type: str) -> ServerInfo:
        return ServerInfo(
            server_id="12345",
            name=self.deployment.hostname,
            status="running",
            ipv4_address="1.2.3.4",
            server_type=server_type,
        )

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    @patch.object(DriftRemediationService, "_rollback")
    @patch.object(DriftRemediationService, "_apply_remediation")
    @patch.object(DriftRemediationService, "_get_gateway")
    @patch.object(DriftRemediationService, "_take_snapshot")
    def test_apply_error_with_provider_confirmed_state_does_not_restore(
        self, mock_snapshot, mock_gateway, mock_apply, mock_rollback, mock_conn
    ):
        """Apply reported Err but the provider shows the expected state: the
        mutation landed — verification must continue, not a snapshot rebuild."""
        mock_snapshot.return_value = Ok(self.snapshot)
        gw = MagicMock()
        gw.get_server.return_value = Ok(self._server("cpx21"))
        mock_gateway.return_value = gw
        mock_apply.return_value = Err("action polling timed out")
        self._approve()

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    @patch.object(DriftRemediationService, "_rollback")
    @patch.object(DriftRemediationService, "_apply_remediation")
    @patch.object(DriftRemediationService, "_get_gateway")
    @patch.object(DriftRemediationService, "_take_snapshot")
    def test_apply_error_with_unobservable_provider_marks_manual(
        self, mock_snapshot, mock_gateway, mock_apply, mock_rollback, mock_conn
    ):
        """Apply Err + provider unobservable = total ambiguity: hand to staff,
        never rebuild a server whose true state is unknown."""
        mock_snapshot.return_value = Ok(self.snapshot)
        gw = MagicMock()
        gw.get_server.return_value = Err("provider API unavailable")
        mock_gateway.return_value = gw
        mock_apply.return_value = Err("action polling timed out")
        self._approve()

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")
        self.assertIn("manual", (self.remediation_request.error_message or "").lower())

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    @patch.object(DriftRemediationService, "_rollback")
    @patch.object(DriftRemediationService, "_apply_remediation")
    @patch.object(DriftRemediationService, "_get_gateway")
    @patch.object(DriftRemediationService, "_take_snapshot")
    def test_apply_error_with_provider_showing_wrong_state_still_restores(
        self, mock_snapshot, mock_gateway, mock_apply, mock_rollback, mock_conn
    ):
        """Provider OBSERVED wrong after a failed apply — restore stays justified."""
        mock_snapshot.return_value = Ok(self.snapshot)
        gw = MagicMock()
        gw.get_server.return_value = Ok(self._server("cpx41"))
        mock_gateway.return_value = gw
        mock_apply.return_value = Err("change_type rejected")
        mock_rollback.return_value = Ok(True)
        self._approve()

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        mock_rollback.assert_called_once()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "rolled_back")

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    @patch.object(DriftRemediationService, "_rollback")
    @patch.object(DriftRemediationService, "_apply_remediation")
    @patch.object(DriftRemediationService, "_get_gateway")
    @patch.object(DriftRemediationService, "_take_snapshot")
    def test_verification_never_observing_provider_marks_manual_not_restore(
        self, mock_snapshot, mock_gateway, mock_apply, mock_rollback, mock_conn
    ):
        """The provider API erroring through the whole verify window is
        ambiguity, not confirmation of failure — no rebuild on the unknown."""
        mock_snapshot.return_value = Ok(self.snapshot)
        gw = MagicMock()
        gw.get_server.return_value = Err("api down")
        mock_gateway.return_value = gw
        mock_apply.return_value = Ok(True)
        self._approve()

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_err())
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")
        self.assertIn("manual", (self.remediation_request.error_message or "").lower())

    @patch.object(DriftRemediationService, "_rollback")
    def test_restore_skipped_when_report_healed_during_execution(self, mock_rollback):
        """Drift healed while the worker executed: restoring would undo
        independently-confirmed-correct state."""
        self.remediation_request.status = "in_progress"
        self.remediation_request.save(update_fields=["status"])
        DriftReport.objects.filter(pk=self.report.pk).update(
            resolved=True, resolved_at=timezone.now(), resolution_type="healed"
        )

        result = self.service._rollback_after_failure(
            self.remediation_request, self.deployment, self.snapshot, "Health check failed", "boom"
        )

        self.assertTrue(result.is_err())
        mock_rollback.assert_not_called()
        self.report.refresh_from_db()
        self.assertEqual(self.report.resolution_type, "healed")
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")

    @patch.object(DriftRemediationService, "_rollback")
    def test_restore_skipped_when_request_externally_transitioned(self, mock_rollback):
        """A request the reaper (or staff) already moved out of in_progress no
        longer owns the deployment — it must not fire a restore."""
        self.remediation_request.status = "failed"
        self.remediation_request.save(update_fields=["status"])

        result = self.service._rollback_after_failure(
            self.remediation_request, self.deployment, self.snapshot, "Apply failed", "boom"
        )

        self.assertTrue(result.is_err())
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "failed")

    @patch("apps.infrastructure.drift_remediation.socket.create_connection")
    @patch.object(DriftRemediationService, "_rollback")
    @patch.object(DriftRemediationService, "_get_gateway")
    @patch.object(DriftRemediationService, "_take_snapshot")
    def test_completion_preserves_concurrent_heal_resolution(
        self, mock_snapshot, mock_gateway, mock_rollback, mock_conn
    ):
        """A scan healing the report mid-execution must not be overwritten to
        'remediated' by the completion path."""
        mock_snapshot.return_value = Ok(self.snapshot)
        gw = MagicMock()
        gw.resize.return_value = Ok(True)

        def get_server_heals(_node_id):
            DriftReport.objects.filter(pk=self.report.pk, resolved=False).update(
                resolved=True, resolved_at=timezone.now(), resolution_type="healed"
            )
            return Ok(self._server("cpx21"))

        gw.get_server.side_effect = get_server_heals
        mock_gateway.return_value = gw
        self._approve()

        result = self.service.execute_remediation(self.remediation_request)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        mock_rollback.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")
        self.report.refresh_from_db()
        self.assertEqual(self.report.resolution_type, "healed")

    def test_queue_retry_exceeds_execution_task_timeout(self):
        """django-q2 must not redeliver a task that is still legitimately running."""
        self.assertGreater(int(django_settings.Q_CLUSTER["retry"]), EXECUTION_TASK_TIMEOUT_SECONDS)

    def test_execution_budget_covers_all_provider_stages(self):
        """Snapshot, apply, and restore are each bounded near 300s by provider
        action polling; verify adds its own budget. The task timeout must cover
        the worst-case sequence or django-q2 kills the worker MID-RESTORE."""
        provider_action_bound = 300
        verify_budget_bound = 150
        margin = 60
        self.assertGreaterEqual(
            EXECUTION_TASK_TIMEOUT_SECONDS, 3 * provider_action_bound + verify_budget_bound + margin
        )


class TestAcceptDriftRaceDiagnostics(DriftRemediationTestBase):
    def test_accept_losing_status_race_returns_err_not_transaction_error(self) -> None:
        """After set_rollback the connection refuses queries — the diagnostic
        refresh must happen BEFORE the flag or the caller gets a
        TransactionManagementError instead of the intended Err."""

        def flip_status_then_sync(_deployment, _report):
            DriftRemediationRequest.objects.filter(pk=self.remediation_request.pk).update(status="approved")
            return Ok(True)

        with patch.object(DriftRemediationService, "_sync_accepted_value", side_effect=flip_status_then_sync):
            result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.assertIn("approved", result.unwrap_err())
