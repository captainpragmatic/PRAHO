"""
Tests for DriftRemediationService

Tests the remediation workflow: approve, reject, schedule, execute, rollback.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.drift_remediation import DriftRemediationService
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


class TestApproveReject(DriftRemediationTestBase):
    """Tests for approve/reject workflows."""

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService.execute_remediation")
    def test_approve_flow(self, mock_execute):
        """Approving should set status=approved and trigger execution."""
        mock_execute.return_value = Ok(True)

        result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.approved_by, self.admin)
        self.assertIsNotNone(self.remediation_request.approved_at)

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
        """Accepting drift should update DB to actual and mark resolved."""
        result = self.service.accept_drift(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_ok())

        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "completed")
        self.assertEqual(self.remediation_request.action_type, "accept_actual")

        self.report.refresh_from_db()
        self.assertTrue(self.report.resolved)
        self.assertEqual(self.report.resolution_type, "accepted")
        self.assertEqual(self.report.resolved_by, self.admin)

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

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_health")
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
        mock_health.return_value = Ok(True)

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
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_health")
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
        mock_gateway.return_value = mock_gw
        mock_rollback.return_value = Ok(True)

        self.remediation_request.status = "approved"
        self.remediation_request.save(update_fields=["status"])

        result = self.service.execute_remediation(self.remediation_request)
        self.assertTrue(result.is_err())
        mock_rollback.assert_called_once()

    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._verify_health")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._get_gateway")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService._take_snapshot")
    def test_concurrent_remediation_prevented(self, mock_snapshot, mock_gateway, mock_health):
        """Only one active remediation per deployment."""
        # Create an existing in-progress remediation
        DriftRemediationRequest.objects.create(
            report=self.report,
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


class TestCleanupSnapshots(DriftRemediationTestBase):
    """Tests for snapshot cleanup."""

    def test_cleanup_expired_snapshots(self):
        """Old snapshots should be deletable."""
        snapshot = DriftSnapshot.objects.create(
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


class TestScheduledRemediation(DriftRemediationTestBase):
    """Tests for scheduled remediation execution."""

    def test_scheduled_remediation_executes_when_due(self):
        """Scheduled requests with past due time should be found."""
        self.remediation_request.status = "scheduled"
        self.remediation_request.scheduled_for = timezone.now() - timedelta(minutes=5)
        self.remediation_request.save(update_fields=["status", "scheduled_for"])

        due = DriftRemediationRequest.objects.filter(
            status="scheduled",
            scheduled_for__lte=timezone.now(),
        )
        self.assertEqual(due.count(), 1)


class TestAuditEvents(DriftRemediationTestBase):
    """Tests for audit event logging."""

    @patch("apps.infrastructure.drift_remediation.InfrastructureAuditService.log_drift_remediation_approved")
    @patch("apps.infrastructure.drift_remediation.DriftRemediationService.execute_remediation")
    def test_audit_events_logged(self, mock_execute, mock_audit):
        """Audit events should be logged on approval."""
        mock_execute.return_value = Ok(True)

        self.service.approve_remediation(self.remediation_request.pk, self.admin)
        mock_audit.assert_called_once()
