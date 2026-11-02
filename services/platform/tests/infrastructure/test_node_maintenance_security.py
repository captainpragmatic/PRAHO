"""Reviewed hardening and node maintenance share actual durable ownership."""

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.provisioning.virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution
from tests.infrastructure.maintenance_security_fixtures import MaintenanceSecurityFixture


@override_settings(Q_CLUSTER={"name": "maintenance-security", "orm": "default", "retry": 100000})
class NodeMaintenanceSecurityTests(MaintenanceSecurityFixture, TestCase):
    def test_running_window_refuses_hardening_before_decision_or_execution(self) -> None:
        window = self.start(self.window())

        with self.assertRaisesMessage(ValidationError, "Maintenance"):
            self.harden()

        self.node.refresh_from_db()
        self.assertIsNone(self.node.security_operation)
        self.assertFalse(NodeSecurityDecision.objects.exists())
        self.assertFalse(NodeSecurityExecution.objects.exists())
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")

    def test_hardening_refuses_window_start_before_execution_is_published(self) -> None:
        window = self.window()
        execution = self.harden()

        with self.assertRaisesMessage(ValidationError, "hardening"):
            self.start(window)

        self.node.refresh_from_db()
        self.assertEqual(self.node.security_operation, execution.pk)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
        self.assertFalse(window.executions.exists())

    def test_future_schedule_does_not_reserve_the_node_against_reviewed_hardening(self) -> None:
        window = self.window(future=True)

        execution = self.harden()

        self.node.refresh_from_db()
        self.assertEqual(self.node.security_operation, execution.pk)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
        self.assertFalse(window.executions.exists())
