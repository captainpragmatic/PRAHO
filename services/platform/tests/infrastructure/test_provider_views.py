"""
Tests for provider create and edit views.

Verifies that provider management views correctly handle form submission,
token storage in the credential vault, and permission checks.
Also covers deployment detail context, drift dashboard counts, and
remediation approval transactional safety.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.urls import reverse

import apps.common.credential_vault as vault_module
from apps.common.credential_vault import EncryptedCredential
from apps.infrastructure.models import (
    CloudProvider,
    DriftCheck,
    DriftRemediationRequest,
    DriftReport,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)

User = get_user_model()


class TestProviderCreateView(TestCase):
    """Tests for the provider_create view."""

    def setUp(self) -> None:
        # Reset vault singleton so it reinitializes with test settings key
        vault_module._vault_instance = None
        self.url = reverse("infrastructure:provider_create")
        self.superuser = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )

    def test_get_renders_form(self) -> None:
        """GET returns 200 with the provider form."""
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

    def test_post_creates_provider_without_token(self) -> None:
        """POST without api_token creates provider, no vault entry."""
        self.client.force_login(self.superuser)
        data = {
            "name": "New Provider",
            "provider_type": "hetzner",
            "code": "NEW",
            "is_active": True,
            "config": "{}",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(CloudProvider.objects.filter(name="New Provider").exists())
        self.assertEqual(EncryptedCredential.objects.count(), 0)

    def test_post_creates_provider_with_token_stores_in_vault(self) -> None:
        """POST with api_token creates provider and stores token in vault."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Vault Provider",
            "provider_type": "hetzner",
            "code": "VLT",
            "is_active": True,
            "config": "{}",
            "api_token": "secret-api-token",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        provider = CloudProvider.objects.get(name="Vault Provider")
        self.assertTrue(provider.credential_identifier)
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="cloud_provider",
                service_identifier=provider.credential_identifier,
            ).exists()
        )

    def test_requires_login(self) -> None:
        """Anonymous GET redirects to login."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.url)


class TestProviderEditView(TestCase):
    """Tests for the provider_edit view."""

    def setUp(self) -> None:
        vault_module._vault_instance = None
        self.superuser = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )
        self.provider = CloudProvider.objects.create(
            name="Edit Provider",
            provider_type="hetzner",
            code="EDT",
            is_active=True,
        )
        self.url = reverse("infrastructure:provider_edit", args=[self.provider.pk])

    def test_get_renders_form_with_provider(self) -> None:
        """GET returns 200 with provider data in form."""
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

    def test_post_updates_provider_without_touching_token(self) -> None:
        """POST without api_token updates provider but creates no vault entry."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Renamed Provider",
            "provider_type": "hetzner",
            "code": "EDT",
            "is_active": True,
            "config": "{}",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertEqual(self.provider.name, "Renamed Provider")
        self.assertEqual(EncryptedCredential.objects.count(), 0)

    def test_post_updates_token_in_vault(self) -> None:
        """POST with api_token stores a new token in the vault."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Edit Provider",
            "provider_type": "hetzner",
            "code": "EDT",
            "is_active": True,
            "config": "{}",
            "api_token": "new-secret-token",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertTrue(self.provider.credential_identifier)
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="cloud_provider",
            ).exists()
        )

    def test_404_for_nonexistent_provider(self) -> None:
        """GET with bad pk returns 404."""
        self.client.force_login(self.superuser)
        url = reverse("infrastructure:provider_edit", args=[99999])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_requires_login(self) -> None:
        """Anonymous GET redirects to login."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.url)


class _DeploymentTestMixin:
    """Shared setup for deployment-related tests."""

    def _create_deployment(self, status: str = "completed", hostname: str = "prd-sha-het-de-fsn1-001") -> NodeDeployment:
        provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="HET", is_active=True)
        region = NodeRegion.objects.create(
            provider=provider, name="Falkenstein", provider_region_id="fsn1",
            normalized_code="fsn1", country_code="de", city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider, name="Small", display_name="2 vCPU / 4GB",
            provider_type_id="cpx21", vcpus=2, memory_gb=4, disk_gb=40,
            hourly_cost_eur=Decimal("0.0100"), monthly_cost_eur=Decimal("7.20"),
        )
        panel = PanelType.objects.create(
            name="Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml",
        )
        return NodeDeployment.objects.create(
            environment="prd", node_type="sha", provider=provider,
            node_size=size, region=region, panel_type=panel,
            hostname=hostname, node_number=1, status=status,
        )


class TestDeploymentDetailProgress(_DeploymentTestMixin, TestCase):
    """C10: Verify deployment detail and status partial provide progress_step and stages list."""

    def setUp(self) -> None:
        self.superuser = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.superuser)

    def test_deployment_detail_has_progress_step_in_context(self) -> None:
        """deployment_detail context includes progress_step and stages list."""
        deployment = self._create_deployment(status="running_ansible")
        url = reverse("infrastructure:deployment_detail", args=[deployment.pk])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("progress_step", response.context)
        self.assertIn("stages", response.context)
        self.assertIsInstance(response.context["stages"], list)
        self.assertEqual(len(response.context["stages"]), 6)
        # "SSH Key" must survive as a single item (the old split bug would break it)
        self.assertIn("SSH Key", response.context["stages"])

    def test_progress_step_never_exceeds_6(self) -> None:
        """progress_step is clamped to max 6 (one per stage)."""
        deployment = self._create_deployment(status="completed")
        url = reverse("infrastructure:deployment_detail", args=[deployment.pk])
        response = self.client.get(url)

        # completed = 100%, 100 // 16 = 6 → min(6, 6) = 6
        self.assertLessEqual(response.context["progress_step"], 6)

    def test_progress_step_zero_for_pending(self) -> None:
        """progress_step is 0 when deployment is pending (0% progress)."""
        deployment = self._create_deployment(status="pending")
        url = reverse("infrastructure:deployment_detail", args=[deployment.pk])
        response = self.client.get(url)

        self.assertEqual(response.context["progress_step"], 0)
        self.assertEqual(response.context["progress_percentage"], 0)

    def test_status_partial_correct_stages_list(self) -> None:
        """deployment_status_partial also provides stages as a Python list."""
        deployment = self._create_deployment(status="provisioning_node")
        url = reverse("infrastructure:deployment_status_partial", args=[deployment.pk])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("progress_step", response.context)
        self.assertIsInstance(response.context["stages"], list)
        # progress_percentage=15, 15//16=0 → progress_step=0
        self.assertEqual(response.context["progress_step"], 0)


class TestDriftDashboardCounts(_DeploymentTestMixin, TestCase):
    """M2: Verify drift_dashboard uses distinct=True in Count annotations."""

    def setUp(self) -> None:
        self.superuser = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.superuser)

    def test_drift_dashboard_uses_distinct_counts(self) -> None:
        """Count annotations must not inflate when deployment has multiple related objects."""
        deployment = self._create_deployment(status="completed")

        # Create 2 drift checks to cause join multiplication
        check1 = DriftCheck.objects.create(deployment=deployment, check_type="cloud", status="completed")
        check2 = DriftCheck.objects.create(deployment=deployment, check_type="network", status="completed")

        # Create 2 unresolved drift reports
        report1 = DriftReport.objects.create(
            drift_check=check1, deployment=deployment, severity="high",
            category="server_state", field_name="memory", expected_value="4GB",
            actual_value="2GB", resolved=False,
        )
        report2 = DriftReport.objects.create(
            drift_check=check2, deployment=deployment, severity="critical",
            category="network", field_name="firewall", expected_value="on",
            actual_value="off", resolved=False,
        )

        # Create 2 pending remediation requests
        DriftRemediationRequest.objects.create(
            report=report1, deployment=deployment, action_type="apply_desired",
            status="pending_approval",
        )
        DriftRemediationRequest.objects.create(
            report=report2, deployment=deployment, action_type="apply_desired",
            status="pending_approval",
        )

        url = reverse("infrastructure:drift_dashboard")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        # Without distinct=True, these counts would be inflated by the join
        self.assertEqual(response.context["total_unresolved"], 2)
        self.assertEqual(response.context["total_pending"], 2)


class TestDriftRemediationApproveTransaction(_DeploymentTestMixin, TestCase):
    """H1: Verify remediation approve wraps DB write + async_task in transaction.atomic."""

    def setUp(self) -> None:
        self.superuser = User.objects.create_superuser(email="admin@test.com", password="testpass123")
        self.client.force_login(self.superuser)

    def _create_pending_remediation(self) -> DriftRemediationRequest:
        deployment = self._create_deployment(status="completed")
        check = DriftCheck.objects.create(deployment=deployment, check_type="cloud", status="completed")
        report = DriftReport.objects.create(
            drift_check=check, deployment=deployment, severity="high",
            category="server_state", field_name="memory", expected_value="4GB",
            actual_value="2GB", resolved=False,
        )
        return DriftRemediationRequest.objects.create(
            report=report, deployment=deployment, action_type="apply_desired",
            status="pending_approval",
        )

    @patch("django_q.tasks.async_task")
    def test_deployment_create_queue_inside_transaction(self, mock_async: object) -> None:
        """async_task is called inside transaction.atomic (verified by checking DB state)."""
        req = self._create_pending_remediation()
        url = reverse("infrastructure:drift_remediation_approve", args=[req.pk])

        response = self.client.post(url)

        self.assertEqual(response.status_code, 302)
        req.refresh_from_db()
        self.assertEqual(req.status, "approved")
        self.assertIsNotNone(req.approved_at)

    @patch("django_q.tasks.async_task", side_effect=RuntimeError("Queue down"))
    def test_failed_queue_rolls_back_deployment(self, mock_async: object) -> None:
        """If async_task raises, the status change must be rolled back."""
        req = self._create_pending_remediation()
        url = reverse("infrastructure:drift_remediation_approve", args=[req.pk])

        with self.assertRaises(RuntimeError):
            self.client.post(url)

        req.refresh_from_db()
        # Status must remain pending_approval because the transaction rolled back
        self.assertEqual(req.status, "pending_approval")
        self.assertIsNone(req.approved_at)


class TestDeploymentCreateUniqueHostnames(_DeploymentTestMixin, TestCase):
    """Verify hostname uniqueness is enforced at the database level."""

    def test_deployment_create_unique_hostnames(self) -> None:
        """Two deployments cannot share the same hostname."""
        from django.db import IntegrityError

        self._create_deployment(status="completed", hostname="prd-sha-het-de-fsn1-001")

        provider = CloudProvider.objects.get(code="HET")
        region = NodeRegion.objects.get(normalized_code="fsn1")
        size = NodeSize.objects.get(provider_type_id="cpx21")
        panel = PanelType.objects.get(panel_type="virtualmin")

        with self.assertRaises(IntegrityError):
            NodeDeployment.objects.create(
                environment="prd", node_type="sha", provider=provider,
                node_size=size, region=region, panel_type=panel,
                hostname="prd-sha-het-de-fsn1-001", node_number=2, status="pending",
            )
