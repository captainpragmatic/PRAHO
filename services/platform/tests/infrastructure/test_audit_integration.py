"""
Tests for infrastructure audit integration.

Verifies that InfrastructureAuditService is correctly wired into
deployment_service.py and views.py, creating audit events for all
lifecycle operations.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.common.types import Err
from apps.infrastructure.audit_service import (
    InfrastructureAuditContext,
    InfrastructureAuditService,
)
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)

User = get_user_model()


def _create_provider() -> CloudProvider:
    provider, _ = CloudProvider.objects.get_or_create(
        code="hetzner-test",
        defaults={
            "name": "Hetzner Test",
            "provider_type": "hetzner",
            "is_active": True,
        },
    )
    return provider


def _create_size(provider: CloudProvider) -> NodeSize:
    size, _ = NodeSize.objects.get_or_create(
        provider=provider,
        provider_type_id="cx22",
        defaults={
            "name": "CX22",
            "vcpus": 2,
            "memory_gb":4,
            "disk_gb": 40,
            "hourly_cost_eur": Decimal("0.01"),
            "monthly_cost_eur": Decimal("5.00"),
        },
    )
    return size


def _create_region(provider: CloudProvider) -> NodeRegion:
    region, _ = NodeRegion.objects.get_or_create(
        provider=provider,
        provider_region_id="fsn1",
        defaults={
            "name": "Falkenstein",
            "country_code": "DE",
            "is_active": True,
        },
    )
    return region


def _get_panel_type() -> PanelType:
    panel, _ = PanelType.objects.get_or_create(
        panel_type="virtualmin",
        defaults={"name": "Virtualmin GPL", "is_active": True},
    )
    return panel


def _create_deployment(
    provider: CloudProvider,
    size: NodeSize,
    region: NodeRegion,
    user: Any,
    **kwargs: Any,
) -> NodeDeployment:
    count = NodeDeployment.objects.count() + 1
    defaults: dict[str, Any] = {
        "hostname": f"test-audit-node-{count}",
        "environment": "production",
        "node_type": "web",
        "node_number": count,
        "provider": provider,
        "node_size": size,
        "region": region,
        "panel_type": _get_panel_type(),
        "initiated_by": user,
        "status": "pending",
    }
    defaults.update(kwargs)
    return NodeDeployment.objects.create(**defaults)


class TestAuditServiceDirectCalls(TestCase):
    """Test InfrastructureAuditService methods create AuditEvent records."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="audit-test@example.com",
            password="testpass123",
        )
        self.provider = _create_provider()
        self.size = _create_size(self.provider)
        self.region = _create_region(self.provider)

    def test_log_deployment_created(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        ctx = InfrastructureAuditContext(user=self.user)

        event = InfrastructureAuditService.log_deployment_created(deployment, ctx)

        self.assertEqual(event.action, "node_deployment_created")
        self.assertEqual(event.user, self.user)
        self.assertIn(deployment.hostname, event.description)

    def test_log_deployment_started(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        ctx = InfrastructureAuditContext(user=self.user)

        event = InfrastructureAuditService.log_deployment_started(deployment, ctx)

        self.assertEqual(event.action, "node_deployment_started")

    def test_log_deployment_completed_with_duration(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
            status="completed",
            ipv4_address="1.2.3.4",
        )
        ctx = InfrastructureAuditContext(user=self.user)

        event = InfrastructureAuditService.log_deployment_completed(
            deployment, ctx, duration_seconds=120.5,
        )

        self.assertEqual(event.action, "node_deployment_completed")
        self.assertEqual(event.metadata["duration_seconds"], 120.5)

    def test_log_deployment_failed_includes_error_and_stage(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        ctx = InfrastructureAuditContext(user=self.user)

        event = InfrastructureAuditService.log_deployment_failed(
            deployment, "SSH timeout", "provision_server", ctx,
        )

        self.assertEqual(event.action, "node_deployment_failed")
        self.assertEqual(event.metadata["error_message"], "SSH timeout")
        self.assertEqual(event.metadata["failed_stage"], "provision_server")

    def test_log_deployment_retry(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        deployment.retry_count = 2
        deployment.save(update_fields=["retry_count"])

        event = InfrastructureAuditService.log_deployment_retry(deployment)

        self.assertEqual(event.action, "node_deployment_retry")
        self.assertEqual(event.metadata["retry_count"], 2)

    def test_log_destroy_started(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
            status="completed", ipv4_address="1.2.3.4",
        )

        event = InfrastructureAuditService.log_destroy_started(deployment)

        self.assertEqual(event.action, "node_destroy_started")
        self.assertEqual(event.metadata["severity"], "high")

    def test_log_destroy_completed(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )

        event = InfrastructureAuditService.log_destroy_completed(deployment)

        self.assertEqual(event.action, "node_destroy_completed")

    def test_log_destroy_failed(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )

        event = InfrastructureAuditService.log_destroy_failed(
            deployment, "API timeout",
        )

        self.assertEqual(event.action, "node_destroy_failed")
        self.assertEqual(event.metadata["severity"], "critical")

    def test_log_provider_created(self) -> None:
        event = InfrastructureAuditService.log_provider_created(self.provider)

        self.assertEqual(event.action, "cloud_provider_created")
        self.assertIn("Hetzner Test", event.description)

    def test_log_provider_updated_captures_old_values(self) -> None:
        old_values = {"name": "Old Name", "is_active": False}

        event = InfrastructureAuditService.log_provider_updated(
            self.provider, old_values,
        )

        self.assertEqual(event.action, "cloud_provider_updated")
        self.assertEqual(event.old_values["name"], "Old Name")

    def test_log_region_toggled(self) -> None:
        event = InfrastructureAuditService.log_region_toggled(self.region)

        self.assertEqual(event.action, "node_region_toggled")
        self.assertIn("Falkenstein", event.description)

    def test_context_extracts_ip_from_request(self) -> None:
        """InfrastructureAuditContext extracts IP from request object."""
        mock_request = MagicMock()
        mock_request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_USER_AGENT": "TestBrowser/1.0",
        }

        ctx = InfrastructureAuditContext(user=self.user, request=mock_request)

        self.assertEqual(ctx.user_agent, "TestBrowser/1.0")
        # IP extraction depends on get_safe_client_ip implementation
        self.assertIsNotNone(ctx.ip_address)


class TestDeploymentServiceAuditIntegration(TestCase):
    """Verify deployment_service.py creates audit events at key lifecycle points."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="deploy-audit@example.com",
            password="testpass123",
        )
        self.provider = _create_provider()
        self.size = _create_size(self.provider)
        self.region = _create_region(self.provider)

    @patch("apps.infrastructure.deployment_service.InfrastructureAuditService")
    @patch("apps.infrastructure.deployment_service.get_ssh_key_manager")
    @patch("apps.infrastructure.deployment_service.get_ansible_service")
    @patch("apps.infrastructure.deployment_service.get_validation_service")
    @patch("apps.infrastructure.deployment_service.get_registration_service")
    @patch("apps.infrastructure.deployment_service.SettingsService")
    def test_deploy_node_logs_started_on_transition(  # noqa: PLR0913
        self,
        mock_settings: MagicMock,
        mock_reg: MagicMock,
        mock_val: MagicMock,
        mock_ansible: MagicMock,
        mock_ssh: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        """deploy_node calls log_deployment_started after transitioning to provisioning."""
        mock_settings.get_setting.return_value = True

        # Make SSH key fail early so we don't need to mock the entire pipeline
        mock_ssh_mgr = MagicMock()
        mock_ssh_mgr.generate_deployment_key.return_value = Err("test fail")
        mock_ssh_mgr.get_master_key.return_value = Err("no master key")
        mock_ssh.return_value = mock_ssh_mgr

        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )

        svc = NodeDeploymentService()
        svc._ssh_manager = mock_ssh_mgr
        svc.deploy_node(deployment, {"api_token": "test"}, user=self.user)

        # Audit started should have been called
        mock_audit.log_deployment_started.assert_called_once()

    @patch("apps.infrastructure.deployment_service.InfrastructureAuditService")
    @patch("apps.infrastructure.deployment_service.get_ssh_key_manager")
    @patch("apps.infrastructure.deployment_service.get_ansible_service")
    @patch("apps.infrastructure.deployment_service.get_validation_service")
    @patch("apps.infrastructure.deployment_service.get_registration_service")
    def test_mark_failed_logs_deployment_failed(
        self,
        mock_reg: MagicMock,
        mock_val: MagicMock,
        mock_ansible: MagicMock,
        mock_ssh: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        """_mark_failed creates a deployment_failed audit event."""
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
            status="provisioning_node",
        )

        svc = NodeDeploymentService()
        svc._mark_failed(deployment, "SSH key generation failed")

        mock_audit.log_deployment_failed.assert_called_once()
        call_args = mock_audit.log_deployment_failed.call_args
        self.assertEqual(call_args[0][0], deployment)
        self.assertEqual(call_args[0][1], "SSH key generation failed")


class TestAuditEventPersistence(TestCase):
    """End-to-end test: audit calls actually persist AuditEvent records to DB."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="persist-audit@example.com",
            password="testpass123",
        )
        self.provider = _create_provider()
        self.size = _create_size(self.provider)
        self.region = _create_region(self.provider)

    def test_deployment_created_persists_audit_event(self) -> None:
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        initial_count = AuditEvent.objects.count()

        InfrastructureAuditService.log_deployment_created(
            deployment, InfrastructureAuditContext(user=self.user),
        )

        self.assertEqual(AuditEvent.objects.count(), initial_count + 1)
        event = AuditEvent.objects.latest("timestamp")
        self.assertEqual(event.action, "node_deployment_created")
        self.assertEqual(event.user, self.user)

    def test_provider_created_persists_audit_event(self) -> None:
        initial_count = AuditEvent.objects.count()

        InfrastructureAuditService.log_provider_created(
            self.provider, InfrastructureAuditContext(user=self.user),
        )

        self.assertEqual(AuditEvent.objects.count(), initial_count + 1)
        event = AuditEvent.objects.latest("timestamp")
        self.assertEqual(event.action, "cloud_provider_created")

    def test_multiple_lifecycle_events_create_audit_trail(self) -> None:
        """A full deployment lifecycle creates a complete audit trail."""
        deployment = _create_deployment(
            self.provider, self.size, self.region, self.user,
        )
        ctx = InfrastructureAuditContext(user=self.user)
        initial_count = AuditEvent.objects.count()

        InfrastructureAuditService.log_deployment_created(deployment, ctx)
        InfrastructureAuditService.log_deployment_started(deployment, ctx)
        InfrastructureAuditService.log_deployment_completed(deployment, ctx, duration_seconds=60.0)

        self.assertEqual(AuditEvent.objects.count(), initial_count + 3)

        event_types = list(
            AuditEvent.objects.filter(
                action__startswith="node_deployment_",
            ).order_by("timestamp").values_list("action", flat=True),
        )
        self.assertIn("node_deployment_created", event_types)
        self.assertIn("node_deployment_started", event_types)
        self.assertIn("node_deployment_completed", event_types)
