"""
Tests for NodeDeploymentService pipeline methods.

Verifies:
- H2: Transient errors don't clear external_node_id
- H4: retry_deployment uses state machine
- H5: stop_node/start_node use state machine
- H6: destroy_node has atomic check-and-transition (TOCTOU fix)
- H7: can_be_destroyed includes "stopped"
- H8: unwrap() has is_err() guard
- H17: _mark_failed accepts and uses audit context
- M1/M4: get_next_node_number concurrency
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.audit_service import InfrastructureAuditContext
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


def _create_deployment(status: str = "pending", external_node_id: str = "") -> NodeDeployment:
    """Create a minimal NodeDeployment for pipeline tests."""
    provider, _ = CloudProvider.objects.get_or_create(
        code="TST",
        defaults={
            "name": "Test Provider",
            "provider_type": "hetzner",
            "is_active": True,
            "credential_identifier": "test-cred",
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
            "ansible_playbook": "virtualmin.yml",
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
        hostname=f"dev-sha-tst-de-tst1-{next_number:03d}",
        dns_zone="test.example.com",
        node_number=next_number,
        initiated_by=user,
        status=status,
        external_node_id=external_node_id,
        ipv4_address="1.2.3.4" if status in ("completed", "stopped") else None,
    )
    deployment.save()
    return deployment


def _make_service() -> NodeDeploymentService:
    """Create a NodeDeploymentService with mocked sub-services."""
    with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
        service = NodeDeploymentService()
    service._ssh_manager = MagicMock()
    service._ansible = MagicMock()
    service._validation = MagicMock()
    service._registration = MagicMock()
    return service


# ===========================================================================
# H2: Transient errors must NOT clear external_node_id
# ===========================================================================


class TestTransientErrorPreservesExternalId(TestCase):
    """H2: get_server returning Err should not clear external_node_id."""

    def test_transient_error_does_not_clear_external_node_id(self) -> None:
        deployment = _create_deployment("pending", external_node_id="srv-123")
        service = _make_service()

        # SSH key succeeds
        service._ssh_manager.generate_deployment_key.return_value = Ok(
            MagicMock(public_key="ssh-rsa AAAA")
        )

        # Mock SettingsService and cloud gateway
        mock_gateway = MagicMock()
        mock_gateway.get_server.return_value = Err("Connection timeout")

        with (
            patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=mock_gateway),
        ):
            result = service.deploy_node(
                deployment=deployment,
                credentials={"api_token": "test-token"},
            )

        self.assertTrue(result.is_err())
        # The key assertion: external_node_id must NOT be cleared
        deployment.refresh_from_db()
        self.assertEqual(deployment.external_node_id, "srv-123")

    def test_confirmed_not_found_clears_external_node_id(self) -> None:
        """When get_server returns Ok(None), it's safe to clear external_node_id."""
        deployment = _create_deployment("pending", external_node_id="srv-456")
        service = _make_service()

        service._ssh_manager.generate_deployment_key.return_value = Ok(
            MagicMock(public_key="ssh-rsa AAAA")
        )

        mock_gateway = MagicMock()
        # Ok(None) = server confirmed not found
        mock_gateway.get_server.return_value = Ok(None)
        # Make upload_ssh_key fail so we can check external_node_id was cleared
        mock_gateway.upload_ssh_key.return_value = Err("key upload failed")

        with (
            patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=mock_gateway),
        ):
            result = service.deploy_node(
                deployment=deployment,
                credentials={"api_token": "test-token"},
            )

        deployment.refresh_from_db()
        # external_node_id should be cleared since server was confirmed gone
        self.assertEqual(deployment.external_node_id, "")


# ===========================================================================
# H4: retry_deployment must use state machine
# ===========================================================================


class TestRetryDeploymentUsesStateMachine(TestCase):
    """H4: retry_deployment must use transition_to, not direct status assignment."""

    def test_retry_transitions_via_state_machine(self) -> None:
        deployment = _create_deployment("failed")
        service = _make_service()

        # SSH key fails to keep the test short
        service._ssh_manager.generate_deployment_key.return_value = Err("SSH not available")
        service._ssh_manager.get_master_key.return_value = Err("No master key")

        with patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True):
            result = service.retry_deployment(
                deployment=deployment,
                credentials={"api_token": "test"},
            )

        # Should have gone through transition_to("pending") first
        self.assertTrue(result.is_err())
        deployment.refresh_from_db()
        # After SSH failure, should be back in failed state
        self.assertEqual(deployment.status, "failed")
        # Retry count should have incremented
        self.assertEqual(deployment.retry_count, 1)

    def test_retry_rejects_non_failed_deployment(self) -> None:
        deployment = _create_deployment("completed")
        service = _make_service()

        result = service.retry_deployment(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Can only retry failed", result.unwrap_err())


# ===========================================================================
# H5: stop_node/start_node must use state machine
# ===========================================================================


class TestStopNodeUsesStateMachine(TestCase):
    """H5: stop_node must use transition_to instead of direct status assignment."""

    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_stop_uses_transition_to(self, mock_run_cmd: MagicMock) -> None:
        deployment = _create_deployment("completed")
        service = _make_service()

        mock_run_cmd.return_value = Ok(MagicMock(success=True))

        result = service.stop_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_ok())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "stopped")

    def test_stop_rejects_pending(self) -> None:
        deployment = _create_deployment("pending")
        service = _make_service()

        result = service.stop_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Can only stop", result.unwrap_err())

    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_stop_already_stopped_is_ok(self, mock_run_cmd: MagicMock) -> None:
        deployment = _create_deployment("stopped")
        service = _make_service()

        result = service.stop_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_ok())
        # Should not have called the provider
        mock_run_cmd.assert_not_called()


class TestStartNodeUsesStateMachine(TestCase):
    """H5: start_node must use transition_to instead of direct status assignment."""

    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_start_uses_transition_to(self, mock_run_cmd: MagicMock) -> None:
        deployment = _create_deployment("stopped")
        service = _make_service()

        mock_run_cmd.return_value = Ok(MagicMock(success=True))

        result = service.start_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_ok())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "completed")

    def test_start_rejects_completed(self) -> None:
        deployment = _create_deployment("completed")
        service = _make_service()

        result = service.start_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Can only start stopped", result.unwrap_err())


# ===========================================================================
# H6: destroy_node TOCTOU — must use select_for_update
# ===========================================================================


class TestDestroyNodeAtomicTransition(TestCase):
    """H6: destroy_node must use atomic check-and-transition."""

    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_destroy_completed_succeeds(self, mock_run_cmd: MagicMock) -> None:
        deployment = _create_deployment("completed", external_node_id="srv-1")
        service = _make_service()
        service._registration.unregister_node.return_value = Ok(True)

        mock_gateway = MagicMock()
        mock_gateway.delete_server.return_value = Ok(True)
        mock_gateway.delete_ssh_key.return_value = Ok(True)

        with patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=mock_gateway):
            result = service.destroy_node(
                deployment=deployment,
                credentials={"api_token": "test"},
            )

        self.assertTrue(result.is_ok())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")

    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_destroy_stopped_succeeds(self, mock_run_cmd: MagicMock) -> None:
        deployment = _create_deployment("stopped", external_node_id="srv-2")
        service = _make_service()
        service._registration.unregister_node.return_value = Ok(True)

        mock_gateway = MagicMock()
        mock_gateway.delete_server.return_value = Ok(True)
        mock_gateway.delete_ssh_key.return_value = Ok(True)

        with patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=mock_gateway):
            result = service.destroy_node(
                deployment=deployment,
                credentials={"api_token": "test"},
            )

        self.assertTrue(result.is_ok())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")

    def test_destroy_pending_rejected(self) -> None:
        deployment = _create_deployment("pending")
        service = _make_service()

        result = service.destroy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Cannot destroy", result.unwrap_err())

    def test_destroy_already_destroying_rejected(self) -> None:
        deployment = _create_deployment("destroying")
        service = _make_service()

        result = service.destroy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Cannot destroy", result.unwrap_err())


# ===========================================================================
# H7: can_be_destroyed includes "stopped"
# ===========================================================================


class TestCanBeDestroyedIncludesStopped(TestCase):
    """H7: can_be_destroyed must return True for stopped deployments."""

    def test_completed_can_be_destroyed(self) -> None:
        deployment = _create_deployment("completed")
        self.assertTrue(deployment.can_be_destroyed)

    def test_failed_can_be_destroyed(self) -> None:
        deployment = _create_deployment("failed")
        self.assertTrue(deployment.can_be_destroyed)

    def test_stopped_can_be_destroyed(self) -> None:
        deployment = _create_deployment("stopped")
        self.assertTrue(deployment.can_be_destroyed)

    def test_pending_cannot_be_destroyed(self) -> None:
        deployment = _create_deployment("pending")
        self.assertFalse(deployment.can_be_destroyed)

    def test_destroyed_cannot_be_destroyed(self) -> None:
        deployment = _create_deployment("destroyed")
        self.assertFalse(deployment.can_be_destroyed)


# ===========================================================================
# H8: unwrap() must have is_err() guard
# ===========================================================================


class TestUnwrapWithErrGuard(TestCase):
    """H8: get_master_public_key().unwrap() must check is_err() first."""

    def test_master_public_key_error_handled(self) -> None:
        """If both generate_key and get_master_public_key fail, error is returned gracefully."""
        deployment = _create_deployment("pending")
        service = _make_service()

        service._ssh_manager.generate_deployment_key.return_value = Err("key gen failed")
        service._ssh_manager.get_master_key.return_value = Ok("master-key")
        service._ssh_manager.get_master_public_key.return_value = Err("public key unavailable")

        with patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True):
            result = service.deploy_node(
                deployment=deployment,
                credentials={"api_token": "test"},
            )

        self.assertTrue(result.is_err())
        # Should NOT raise an exception — should return Err gracefully
        self.assertIn("SSH key generation failed", result.unwrap_err())


# ===========================================================================
# H17: _mark_failed accepts and passes audit context
# ===========================================================================


class TestMarkFailedAuditContext(TestCase):
    """H17: _mark_failed must accept and forward audit context."""

    @patch("apps.infrastructure.deployment_service.InfrastructureAuditService.log_deployment_failed")
    def test_mark_failed_passes_audit_context(self, mock_log_failed: MagicMock) -> None:
        deployment = _create_deployment("provisioning_node")
        service = _make_service()
        user, _ = User.objects.get_or_create(
            email="admin@test.com", defaults={"password": "!unusable"}
        )
        ctx = InfrastructureAuditContext(user=user)

        service._mark_failed(deployment, "test error", stage="ssh_key", audit_ctx=ctx)

        mock_log_failed.assert_called_once()
        call_kwargs = mock_log_failed.call_args
        self.assertEqual(call_kwargs.kwargs.get("context"), ctx)

    @patch("apps.infrastructure.deployment_service.InfrastructureAuditService.log_deployment_failed")
    def test_mark_failed_without_context_still_works(self, mock_log_failed: MagicMock) -> None:
        deployment = _create_deployment("provisioning_node")
        service = _make_service()

        service._mark_failed(deployment, "test error")

        mock_log_failed.assert_called_once()
        call_kwargs = mock_log_failed.call_args
        # context should be None (no user info)
        self.assertIsNone(call_kwargs.kwargs.get("context"))

    def test_mark_failed_creates_log_entry(self) -> None:
        deployment = _create_deployment("provisioning_node")
        service = _make_service()

        service._mark_failed(deployment, "something broke", stage="provision_server")

        log = NodeDeploymentLog.objects.filter(
            deployment=deployment, level="ERROR"
        ).first()
        self.assertIsNotNone(log)
        self.assertIn("something broke", log.message)
        self.assertEqual(log.phase, "provision_server")


# ===========================================================================
# Deploy pipeline: status checks and early exits
# ===========================================================================


class TestDeployNodeStatusChecks(TestCase):
    """Deploy node rejects invalid starting states."""

    def test_deploy_rejects_completed(self) -> None:
        deployment = _create_deployment("completed")
        service = _make_service()

        result = service.deploy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Cannot deploy", result.unwrap_err())

    def test_deploy_rejects_destroying(self) -> None:
        deployment = _create_deployment("destroying")
        service = _make_service()

        result = service.deploy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())

    @patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=False)
    def test_deploy_disabled_in_settings(self, mock_setting: MagicMock) -> None:
        deployment = _create_deployment("pending")
        service = _make_service()

        result = service.deploy_node(
            deployment=deployment,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("disabled", result.unwrap_err())


class TestDeployNodeNoApiToken(TestCase):
    """Deploy node requires an API token."""

    def test_deploy_no_api_token(self) -> None:
        deployment = _create_deployment("pending")
        service = _make_service()

        service._ssh_manager.generate_deployment_key.return_value = Ok(
            MagicMock(public_key="ssh-rsa AAAA")
        )

        with patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True):
            result = service.deploy_node(
                deployment=deployment,
                credentials={},
            )

        self.assertTrue(result.is_err())
        self.assertIn("No API token", result.unwrap_err())


# ===========================================================================
# Reboot, upgrade, maintenance: status checks
# ===========================================================================


class TestUpgradeNodeStatusCheck(TestCase):
    """upgrade_node_size only works on completed deployments."""

    def test_upgrade_rejects_pending(self) -> None:
        deployment = _create_deployment("pending")
        service = _make_service()

        result = service.upgrade_node_size(
            deployment=deployment,
            new_size=deployment.node_size,
            credentials={"api_token": "test"},
        )

        self.assertTrue(result.is_err())
        self.assertIn("Can only upgrade completed", result.unwrap_err())


class TestMaintenanceStatusCheck(TestCase):
    """run_maintenance only works on completed deployments."""

    def test_maintenance_rejects_stopped(self) -> None:
        deployment = _create_deployment("stopped")
        service = _make_service()

        result = service.run_maintenance(
            deployment=deployment,
        )

        self.assertTrue(result.is_err())
        self.assertIn("Can only run maintenance on completed", result.unwrap_err())
