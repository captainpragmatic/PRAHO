"""
Tests for NodeDeployment state machine and deployment service transitions.

Verifies:
- All valid state transitions succeed
- Invalid transitions raise ValidationError
- transition_to() saves internally (no redundant save needed)
- The deployment pipeline transitions through the correct state sequence
- _mark_failed uses the state machine instead of bypassing it
- "stopped" state participates in transitions correctly
- Every STATUS_CHOICES entry has a VALID_TRANSITIONS entry
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeDeploymentLog,
    NodeRegion,
    NodeSize,
    PanelType,
)

User = get_user_model()


def _create_deployment(status: str = "pending") -> NodeDeployment:
    """Create a minimal NodeDeployment for testing state transitions.

    Uses get_or_create for shared fixtures (provider, region, size, panel, user)
    so repeated calls within the same TestCase transaction don't hit unique
    constraints.  Each NodeDeployment gets a fresh node_number derived from
    the current count to satisfy the unique_together constraint.
    """
    provider, _ = CloudProvider.objects.get_or_create(
        code="TST",
        defaults={
            "name": "Test Provider",
            "provider_type": "hetzner",
            "is_active": True,
        },
    )
    region, _ = NodeRegion.objects.get_or_create(
        provider=provider,
        normalized_code="tst1",
        defaults={
            "name": "Test Region",
            "provider_region_id": "tst1",
            "country_code": "de",
            "city": "Test",
            "is_active": True,
        },
    )
    size, _ = NodeSize.objects.get_or_create(
        provider=provider,
        provider_type_id="cx11",
        defaults={
            "name": "TEST",
            "display_name": "Test Size",
            "vcpus": 1,
            "memory_gb": 2,
            "disk_gb": 20,
            "hourly_cost_eur": "0.0050",
            "monthly_cost_eur": "3.29",
            "is_active": True,
        },
    )
    panel, _ = PanelType.objects.get_or_create(
        panel_type="virtualmin",
        defaults={
            "name": "Virtualmin GPL",
            "version": "7.10.0",
            "is_active": True,
        },
    )
    user, _ = User.objects.get_or_create(
        email="deployer@test.com",
        defaults={"password": "!unusable"},
    )
    next_number = NodeDeployment.objects.filter(
        environment="dev", node_type="sha", provider=provider, region=region
    ).count() + 1
    deployment = NodeDeployment(
        environment="dev",
        node_type="sha",
        provider=provider,
        region=region,
        node_size=size,
        panel_type=panel,
        hostname=f"test-deployment-{next_number:03d}",
        dns_zone="test.example.com",
        node_number=next_number,
        initiated_by=user,
        status=status,
    )
    # Save without triggering transition_to
    deployment.save()
    return deployment


class TestValidTransitions(TestCase):
    """Every declared valid transition must succeed."""

    def test_pending_to_provisioning_node(self) -> None:
        deployment = _create_deployment("pending")
        deployment.transition_to("provisioning_node")
        self.assertEqual(deployment.status, "provisioning_node")

    def test_provisioning_node_to_configuring_dns(self) -> None:
        deployment = _create_deployment("provisioning_node")
        deployment.transition_to("configuring_dns")
        self.assertEqual(deployment.status, "configuring_dns")

    def test_configuring_dns_to_installing_panel(self) -> None:
        deployment = _create_deployment("configuring_dns")
        deployment.transition_to("installing_panel")
        self.assertEqual(deployment.status, "installing_panel")

    def test_installing_panel_to_configuring_backups(self) -> None:
        deployment = _create_deployment("installing_panel")
        deployment.transition_to("configuring_backups")
        self.assertEqual(deployment.status, "configuring_backups")

    def test_configuring_backups_to_validating(self) -> None:
        deployment = _create_deployment("configuring_backups")
        deployment.transition_to("validating")
        self.assertEqual(deployment.status, "validating")

    def test_validating_to_registering(self) -> None:
        deployment = _create_deployment("validating")
        deployment.transition_to("registering")
        self.assertEqual(deployment.status, "registering")

    def test_registering_to_completed(self) -> None:
        deployment = _create_deployment("registering")
        deployment.transition_to("completed")
        self.assertEqual(deployment.status, "completed")

    def test_completed_to_stopped(self) -> None:
        deployment = _create_deployment("completed")
        deployment.transition_to("stopped")
        self.assertEqual(deployment.status, "stopped")

    def test_stopped_to_completed(self) -> None:
        """Stopped nodes can be restarted."""
        deployment = _create_deployment("stopped")
        deployment.transition_to("completed")
        self.assertEqual(deployment.status, "completed")

    def test_stopped_to_destroying(self) -> None:
        deployment = _create_deployment("stopped")
        deployment.transition_to("destroying")
        self.assertEqual(deployment.status, "destroying")

    def test_completed_to_destroying(self) -> None:
        deployment = _create_deployment("completed")
        deployment.transition_to("destroying")
        self.assertEqual(deployment.status, "destroying")

    def test_failed_to_pending_for_retry(self) -> None:
        deployment = _create_deployment("failed")
        deployment.transition_to("pending")
        self.assertEqual(deployment.status, "pending")

    def test_failed_to_destroying(self) -> None:
        deployment = _create_deployment("failed")
        deployment.transition_to("destroying")
        self.assertEqual(deployment.status, "destroying")

    def test_destroying_to_destroyed(self) -> None:
        deployment = _create_deployment("destroying")
        deployment.transition_to("destroyed")
        self.assertEqual(deployment.status, "destroyed")

    def test_any_active_state_to_failed(self) -> None:
        """Every non-terminal active state can transition to failed."""
        active_states = [
            "pending", "provisioning_node", "configuring_dns",
            "installing_panel", "configuring_backups", "validating",
            "registering", "stopped", "destroying",
        ]
        for state in active_states:
            with self.subTest(state=state):
                deployment = _create_deployment(state)
                deployment.transition_to("failed")
                self.assertEqual(deployment.status, "failed")


class TestInvalidTransitions(TestCase):
    """Invalid transitions must raise ValidationError."""

    def test_pending_to_completed_rejected(self) -> None:
        """Cannot skip straight to completed."""
        deployment = _create_deployment("pending")
        with self.assertRaises(ValidationError):
            deployment.transition_to("completed")

    def test_same_state_transition_rejected(self) -> None:
        """Cannot transition to the same state (the original bug)."""
        deployment = _create_deployment("provisioning_node")
        with self.assertRaises(ValidationError):
            deployment.transition_to("provisioning_node")

    def test_destroyed_is_terminal(self) -> None:
        """Destroyed deployments cannot transition to any state."""
        deployment = _create_deployment("destroyed")
        for target in ["pending", "failed", "completed", "destroying"]:
            with self.subTest(target=target), self.assertRaises(ValidationError):
                deployment.transition_to(target)

    def test_completed_cannot_go_backwards(self) -> None:
        """Completed cannot go back to provisioning stages."""
        deployment = _create_deployment("completed")
        with self.assertRaises(ValidationError):
            deployment.transition_to("pending")

    def test_backwards_transition_rejected(self) -> None:
        """Cannot go backwards in the pipeline."""
        deployment = _create_deployment("configuring_dns")
        with self.assertRaises(ValidationError):
            deployment.transition_to("provisioning_node")


class TestTransitionToSavesInternally(TestCase):
    """transition_to() must persist state to the database without extra save()."""

    def test_status_persisted_after_transition(self) -> None:
        """Database has the new status after transition_to without explicit save."""
        deployment = _create_deployment("pending")
        deployment.transition_to("provisioning_node")

        # Re-read from database
        refreshed = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(refreshed.status, "provisioning_node")

    def test_transition_returns_none(self) -> None:
        """transition_to is a void method — must not be used in boolean checks."""
        deployment = _create_deployment("pending")
        result = deployment.transition_to("provisioning_node")
        self.assertIsNone(result)


class TestTransitionsMapCompleteness(TestCase):
    """Every status in STATUS_CHOICES must have an entry in VALID_TRANSITIONS."""

    def test_every_status_has_transitions_entry(self) -> None:
        status_codes = {code for code, _label in NodeDeployment.STATUS_CHOICES}
        transition_keys = set(NodeDeployment.VALID_TRANSITIONS.keys())

        missing = status_codes - transition_keys
        self.assertEqual(
            missing,
            set(),
            f"STATUS_CHOICES has statuses not in VALID_TRANSITIONS: {missing}",
        )

    def test_all_transition_targets_are_valid_statuses(self) -> None:
        """Every target in VALID_TRANSITIONS must be a valid STATUS_CHOICES code."""
        status_codes = {code for code, _label in NodeDeployment.STATUS_CHOICES}
        for source, targets in NodeDeployment.VALID_TRANSITIONS.items():
            for target in targets:
                with self.subTest(source=source, target=target):
                    self.assertIn(
                        target,
                        status_codes,
                        f"Transition target '{target}' from '{source}' is not a valid status",
                    )


class TestHappyPathPipeline(TestCase):
    """The full deployment pipeline follows the expected state sequence."""

    EXPECTED_SEQUENCE: ClassVar[list[str]] = [
        "pending",
        "provisioning_node",
        "configuring_dns",
        "installing_panel",
        "configuring_backups",
        "validating",
        "registering",
        "completed",
    ]

    def test_full_pipeline_transitions(self) -> None:
        """Walk through the entire pipeline — every transition must succeed."""
        deployment = _create_deployment("pending")

        for i in range(1, len(self.EXPECTED_SEQUENCE)):
            prev = self.EXPECTED_SEQUENCE[i - 1]
            next_state = self.EXPECTED_SEQUENCE[i]
            with self.subTest(transition=f"{prev} -> {next_state}"):
                self.assertEqual(deployment.status, prev)
                deployment.transition_to(next_state)
                self.assertEqual(deployment.status, next_state)

        # Verify final state persisted
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "completed")


class TestDeployNodeTransitionBugFix(TestCase):
    """Regression test for the 'not transition_to()' bug.

    The original code was:
        if not deployment.transition_to("provisioning_node"):
            return Err(...)

    Since transition_to returns None, `not None` is True, causing the deploy
    to always fail with 'Invalid state transition from provisioning_node to
    provisioning_node'.
    """

    def test_deploy_node_transitions_from_pending(self) -> None:
        """deploy_node must successfully transition pending -> provisioning_node."""
        deployment = _create_deployment("pending")
        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            service = NodeDeploymentService()

        # Mock all external services to isolate the transition logic
        service._ssh_manager = MagicMock()
        service._ansible = MagicMock()
        service._validation = MagicMock()
        service._registration = MagicMock()

        # SSH key generation returns error (simplest path to test transition)
        service._ssh_manager.generate_deployment_key.return_value = MagicMock(
            is_err=lambda: True,
            unwrap_err=lambda: "SSH not available",
        )
        service._ssh_manager.get_master_key.return_value = MagicMock(
            is_err=lambda: True,
            unwrap_err=lambda: "No master key",
        )

        result = service.deploy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        # The deploy should fail at SSH stage, NOT at the transition
        self.assertTrue(result.is_err())
        err_msg = result.unwrap_err()
        self.assertNotIn("Invalid state transition", err_msg)
        self.assertIn("SSH key generation failed", err_msg)

        # Deployment should be in "failed" state (from _mark_failed), not "pending"
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")

    def test_deploy_node_rejects_already_provisioning(self) -> None:
        """deploy_node correctly rejects a deployment already in provisioning_node."""
        deployment = _create_deployment("provisioning_node")
        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            service = NodeDeploymentService()

        result = service.deploy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Cannot deploy node in status", result.unwrap_err())


class TestMarkFailedUsesStateMachine(TestCase):
    """_mark_failed must use transition_to instead of bypassing the state machine."""

    def test_mark_failed_from_provisioning(self) -> None:
        """_mark_failed transitions through the state machine."""
        deployment = _create_deployment("provisioning_node")
        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            service = NodeDeploymentService()

        service._mark_failed(deployment, "test error")

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")

    def test_mark_failed_creates_log(self) -> None:
        """_mark_failed creates a deployment log entry."""
        deployment = _create_deployment("provisioning_node")
        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            service = NodeDeploymentService()

        service._mark_failed(deployment, "something went wrong")

        log = NodeDeploymentLog.objects.filter(
            deployment=deployment,
            level="ERROR",
        ).first()
        self.assertIsNotNone(log)
        self.assertIn("something went wrong", log.message)
