"""Emergency publication owns a real node without inventing provider authority or ordinary policy."""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.infrastructure.node_maintenance_execution import create_emergency_window
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_service import change_window, create_window
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-execution", "orm": "default", "retry": 100000})
class NodeMaintenanceEmergencyTests(MaintenanceAdmissionFixture, TestCase):
    def test_system_recovery_publishes_a_running_owned_window_without_ordinary_policy(self) -> None:
        NodeMaintenancePolicy.objects.filter(node=self.node).delete()

        window = create_emergency_window(
            self.node.pk, reason="Observed stopped server recovery", timezone_name="Europe/Bucharest"
        )

        self.assertEqual(NodeMaintenanceWindow.objects.count(), 1)
        self.assertEqual(window.kind, "emergency")
        self.assertEqual(window.status, "running")
        self.assertEqual(window.origin, "system")
        self.assertIsNone(window.policy_id)
        self.assertIsNone(window.created_by_id)
        self.assertIsNotNone(window.current_execution_id)
        execution = NodeMaintenanceExecution.objects.get(pk=window.current_execution_id)
        self.assertEqual(execution.window_id, window.pk)
        self.assertEqual(execution.node_uuid, self.node.pk)
        self.assertEqual(execution.window_revision, window.revision)

    def test_an_unclaimed_ordinary_future_window_is_superseded_with_history(self) -> None:
        old = self.window(future=True)

        emergency = create_emergency_window(self.node.pk, reason="Observed stopped server", timezone_name="UTC")

        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=old.pk).status, "cancelled")
        self.assertNotEqual(old.pk, emergency.pk)
        self.assertEqual(NodeMaintenanceWindow.objects.count(), 2)
        self.assertEqual(NodeMaintenanceWindow.objects.filter(status="running").count(), 1)

    def test_genuine_emergency_does_not_preempt_running_or_uncertain_work(self) -> None:
        running = self.start(self.window())

        with self.assertRaises(ValidationError):
            create_emergency_window(self.node.pk, reason="Recovery requested", timezone_name="UTC")

        self.assertEqual(NodeMaintenanceWindow.objects.count(), 1)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=running.pk).status, "running")


class NodeMaintenanceAdapterChoiceTests(MaintenanceAdmissionFixture, TestCase):
    def create(self, kind: str, mode: str, downtime: bool) -> NodeMaintenanceWindow:
        starts_at = timezone.now() + timedelta(minutes=10)
        return create_window(
            self.node.pk,
            actor=self.actor,
            kind=kind,
            execution_mode=mode,
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=downtime,
            expected_downtime_minutes=5 if downtime else 0,
            customer_note="A hosting maintenance window.",
        )

    def test_provider_reboot_cannot_borrow_an_update_only_window(self) -> None:
        with self.assertRaises(ValidationError):
            self.create("panel_update", "reboot", True)

    def test_security_action_cannot_borrow_a_restart_only_window(self) -> None:
        with self.assertRaises(ValidationError):
            self.create("reboot", "security", True)

    def test_automated_restart_cannot_claim_no_expected_downtime(self) -> None:
        with self.assertRaises(ValidationError):
            self.create("reboot", "reboot", False)


class NodeMaintenanceManualTargetTests(MaintenanceAdmissionFixture, TestCase):
    def test_changed_imported_transport_cannot_complete_the_original_manual_work(self) -> None:
        # Simulate an out-of-band identity writer; the public edit path has its own gate tests.
        for field, replacement in (
            ("hostname", "replacement.example.test"),
            ("ssh_port", 2222),
            ("api_port", 10001),
            ("api_username", "replacement"),
            ("ipv4_address", "95.217.0.10"),
            ("ssl_verify", False),
        ):
            with self.subTest(field=field):
                original = getattr(self.node, field)
                window = self.start(self.window())
                setattr(self.node, field, replacement)
                self.node.save(update_fields=[field])
                try:
                    with self.assertRaisesMessage(ValidationError, "target"):
                        change_window(
                            window.pk,
                            actor=self.actor,
                            revision=window.revision,
                            action="finish",
                            reason="Reviewed result",
                            outcome="completed",
                            public_outcome="Work completed.",
                            attestation=True,
                        )
                    self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
                finally:
                    setattr(self.node, field, original)
                    self.node.save(update_fields=[field])
                    current = NodeMaintenanceWindow.objects.get(pk=window.pk)
                    if current.status == "running":
                        change_window(
                            window.pk,
                            actor=self.actor,
                            revision=window.revision,
                            action="finish",
                            reason="Original target reviewed",
                            outcome="failed",
                            public_outcome="The operator closed this work.",
                            attestation=True,
                        )
