"""Database fences preserve window identity even if a caller skips form validation."""

from datetime import time, timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceDelivery,
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.provisioning.virtualmin_models import VirtualminServer


class NodeMaintenanceConstraintTests(TestCase):
    def setUp(self) -> None:
        self.node = VirtualminServer.objects.create(
            name="Constraint node", hostname="constraint.example.test", api_username="api", encrypted_api_password=b""
        )
        self.policy = NodeMaintenancePolicy.objects.create(
            node=self.node,
            timezone="Europe/Bucharest",
            weekdays=[0, 1, 2, 3, 4, 5, 6],
            starts_time=time(0, 0),
            ends_time=time(23, 59),
            max_defer_minutes=30,
        )

    def window(self, **changes: object) -> NodeMaintenanceWindow:
        starts_at = timezone.now() + timedelta(days=3)
        values: dict[str, object] = {
            "node": self.node,
            "node_uuid": self.node.pk,
            "policy": self.policy,
            "policy_revision": 1,
            "policy_timezone": "Europe/Bucharest",
            "kind": "panel_update",
            "execution_mode": "manual",
            "starts_at": starts_at,
            "ends_at": starts_at + timedelta(minutes=30),
            "start_by": starts_at + timedelta(minutes=10),
            "customer_note": "Hosting software updates.",
        }
        values.update(changes)
        return NodeMaintenanceWindow.objects.create(**values)

    def test_two_applicable_windows_on_one_node_are_refused_by_the_database(self) -> None:
        self.window()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.window()

    def test_an_empty_window_is_refused_by_the_strict_duration_constraint(self) -> None:
        starts_at = timezone.now() + timedelta(days=3)
        with self.assertRaisesRegex(IntegrityError, "maintenance_window_positive"), transaction.atomic():
            self.window(starts_at=starts_at, ends_at=starts_at, start_by=starts_at)

    def test_a_backwards_window_is_refused_by_the_database(self) -> None:
        starts_at = timezone.now() + timedelta(days=3)
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.window(starts_at=starts_at, ends_at=starts_at - timedelta(minutes=1), start_by=starts_at)

    def test_a_latest_start_outside_the_window_is_refused_by_the_database(self) -> None:
        starts_at = timezone.now() + timedelta(days=3)
        ends_at = starts_at + timedelta(minutes=30)
        for start_by in (starts_at - timedelta(seconds=1), ends_at + timedelta(seconds=1)):
            with (
                self.subTest(start_by=start_by),
                self.assertRaisesRegex(IntegrityError, "maintenance_latest_start_within"),
                transaction.atomic(),
            ):
                self.window(starts_at=starts_at, ends_at=ends_at, start_by=start_by)

    def test_an_active_window_cannot_lose_its_node_binding(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.window(node=None)

    def test_an_active_window_cannot_claim_a_different_node_identity(self) -> None:
        from uuid import uuid4  # noqa: PLC0415

        with self.assertRaises(IntegrityError), transaction.atomic():
            self.window(node_uuid=uuid4())

    def test_policy_rejects_unknown_timezone_and_invalid_weekdays(self) -> None:
        cases = (("Not/AZone", [0]), ("Europe/Bucharest", []), ("Europe/Bucharest", [7]), ("Europe/Bucharest", [0, 0]))
        for zone, weekdays in cases:
            with self.subTest(zone=zone, weekdays=weekdays):
                policy = NodeMaintenancePolicy(
                    node=self.node,
                    timezone=zone,
                    weekdays=weekdays,
                    starts_time=time(1, 0),
                    ends_time=time(2, 0),
                    max_defer_minutes=10,
                )
                with self.assertRaises(ValidationError):
                    policy.clean()

    def test_unknown_window_state_cannot_silently_escape_the_active_gate(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.window(status="unknown")

    def test_unknown_execution_phase_cannot_silently_escape_the_active_gate(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            NodeMaintenanceExecution.objects.create(
                node=self.node, node_uuid=self.node.pk, phase="unknown", action="reboot", adapter="provider"
            )

    def test_unknown_delivery_phase_is_refused(self) -> None:
        window = self.window()
        with self.assertRaises(IntegrityError), transaction.atomic():
            NodeMaintenanceDelivery.objects.create(
                window=window,
                revision=1,
                customer_id_snapshot=1,
                kind="scheduled",
                due_at=timezone.now(),
                phase="unknown",
            )
