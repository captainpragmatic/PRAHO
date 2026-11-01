"""Approval, scheduling, due workers and accepting actual drift share the node gate."""

from datetime import time, timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.infrastructure.tasks import apply_scheduled_remediations_task
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.test_drift_remediation import DriftRemediationTestBase


class NodeMaintenanceDriftAdmissionTests(DriftRemediationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.node = VirtualminServer.objects.create(name="Drift node", hostname="drift-maintenance.example.test")
        self.deployment.virtualmin_server = self.node
        self.deployment.save(update_fields=["virtualmin_server"])

    def running_window(self) -> None:
        NodeMaintenancePolicy.objects.create(
            node=self.node,
            timezone="UTC",
            weekdays=list(range(7)),
            starts_time=time(0),
            ends_time=time(23, 59),
            max_defer_minutes=30,
        )
        starts_at = timezone.now() - timedelta(seconds=10)
        window = create_window(
            self.node.pk,
            actor=self.admin,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting software maintenance.",
        )
        change_window(window.pk, actor=self.admin, revision=1, action="start", reason="Approved maintenance")

    def test_approval_is_refused_before_queue_publication(self) -> None:
        self.running_window()
        with patch("django_q.tasks.async_task") as enqueue:
            result = self.service.approve_remediation(self.remediation_request.pk, self.admin)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        enqueue.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "pending_approval")

    def test_scheduling_is_refused_while_an_existing_window_owns_the_node(self) -> None:
        self.running_window()
        result = self.service.schedule_remediation(
            self.remediation_request.pk, self.admin, timezone.now() + timedelta(hours=1)
        )
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "pending_approval")

    def test_due_scheduled_drift_is_not_approved_or_enqueued_over_a_running_window(self) -> None:
        due_at = timezone.now() + timedelta(minutes=10)
        self.assertTrue(self.service.schedule_remediation(self.remediation_request.pk, self.admin, due_at).is_ok())
        self.running_window()

        with patch("django.utils.timezone.now", return_value=due_at), patch("django_q.tasks.async_task") as enqueue:
            result = apply_scheduled_remediations_task()

        self.assertEqual(result["claimed"], 0)
        enqueue.assert_not_called()
        self.remediation_request.refresh_from_db()
        self.assertEqual(self.remediation_request.status, "scheduled")

    def test_accepting_actual_network_state_cannot_bypass_the_window_gate(self) -> None:
        self.report.field_name = "ipv4_address"
        self.report.expected_value = "1.2.3.4"
        self.report.actual_value = "5.6.7.8"
        self.report.save(update_fields=["field_name", "expected_value", "actual_value"])
        self.running_window()

        result = self.service.accept_drift(self.remediation_request.pk, self.admin)

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.ipv4_address, "1.2.3.4")
