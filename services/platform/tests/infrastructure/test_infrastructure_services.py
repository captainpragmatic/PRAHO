# ===============================================================================
# INFRASTRUCTURE SERVICES TESTS
# ===============================================================================
"""
Tests for Infrastructure app services.

Covers:
- CostTrackingService
- SSHKeyManager
- ValidationService
- RegistrationService
"""

from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeDeploymentCostRecord,
    NodeRegion,
    NodeSize,
    PanelType,
)
from apps.infrastructure.cost_service import (
    CostSummary,
    CostTrackingService,
    DeploymentCostBreakdown,
    get_cost_tracking_service,
)
from apps.infrastructure.ssh_key_manager import SSHKeyManager, SSHKeyPair

User = get_user_model()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def create_test_infrastructure():
    """Create test infrastructure objects"""
    user = User.objects.create_user(
        email="test@example.com",
        password="testpass123",
    )

    provider = CloudProvider.objects.create(
        name="Hetzner Cloud",
        code="het",
        provider_type="hetzner",
        credential_identifier="hetzner_api_token",
        is_active=True,
    )

    region = NodeRegion.objects.create(
        provider=provider,
        name="Falkenstein DC14",
        provider_region_id="fsn1-dc14",
        normalized_code="fsn1",
        country_code="de",
        city="Falkenstein",
        is_active=True,
    )

    size = NodeSize.objects.create(
        provider=provider,
        name="CX22",
        display_name="2 vCPU / 4GB RAM / 40GB",
        provider_type_id="cx22",
        vcpus=2,
        memory_gb=4,
        disk_gb=40,
        hourly_cost_eur=Decimal("0.006"),
        monthly_cost_eur=Decimal("4.35"),
        max_domains=25,
        is_active=True,
    )

    panel = PanelType.objects.create(
        name="Virtualmin GPL",
        panel_type="virtualmin",
        version="7.10.0",
        ansible_playbook="virtualmin.yml",
        is_active=True,
    )

    return {
        "user": user,
        "provider": provider,
        "region": region,
        "size": size,
        "panel": panel,
    }


# ===============================================================================
# COST TRACKING SERVICE TESTS
# ===============================================================================


class CostTrackingServiceTests(TestCase):
    """Tests for CostTrackingService"""

    def setUp(self):
        infra = create_test_infrastructure()
        self.user = infra["user"]
        self.provider = infra["provider"]
        self.region = infra["region"]
        self.size = infra["size"]
        self.panel = infra["panel"]
        self.service = CostTrackingService()
        self._deployment_counter = 0

    def create_deployment(self, **kwargs):
        """Helper to create deployments"""
        self._deployment_counter += 1
        now = timezone.now()
        node_number = kwargs.pop("node_number", self._deployment_counter)
        defaults = {
            "hostname": f"prd-sha-het-de-fsn1-{node_number:03d}",
            "environment": "prd",
            "node_type": "sha",
            "node_number": node_number,
            "provider": self.provider,
            "region": self.region,
            "node_size": self.size,
            "panel_type": self.panel,
            "dns_zone": "test.com",
            "initiated_by": self.user,
            "status": "completed",
            "started_at": now - timedelta(days=1),
        }
        defaults.update(kwargs)
        return NodeDeployment.objects.create(**defaults)

    def test_calculate_deployment_costs(self):
        """Test calculating costs for a single deployment"""
        deployment = self.create_deployment(
            started_at=timezone.now() - timedelta(hours=24),
        )

        period_start = timezone.now() - timedelta(hours=24)
        period_end = timezone.now()

        result = self.service.calculate_deployment_costs(
            deployment, period_start, period_end
        )

        self.assertTrue(result.is_ok())
        record = result.unwrap()
        self.assertIsInstance(record, NodeDeploymentCostRecord)
        self.assertEqual(record.deployment, deployment)
        # Cost should be approximately 24 hours of usage
        # Monthly cost is 4.35 EUR, hourly is ~0.006 EUR
        self.assertGreater(record.cost_eur, Decimal("0"))
        self.assertLess(record.cost_eur, Decimal("1"))  # Less than 1 EUR for 24h

    def test_calculate_deployment_costs_invalid_period(self):
        """Test error when period end is before start"""
        deployment = self.create_deployment()

        period_start = timezone.now()
        period_end = timezone.now() - timedelta(hours=24)

        result = self.service.calculate_deployment_costs(
            deployment, period_start, period_end
        )

        self.assertTrue(result.is_err())
        self.assertIn("after", result.unwrap_err())

    def test_calculate_deployment_costs_not_deployed(self):
        """Test handling deployment that wasn't active during period"""
        deployment = self.create_deployment(
            started_at=timezone.now() + timedelta(days=1),  # Future
        )

        period_start = timezone.now() - timedelta(hours=24)
        period_end = timezone.now()

        result = self.service.calculate_deployment_costs(
            deployment, period_start, period_end
        )

        self.assertTrue(result.is_err())

    def test_get_cost_summary(self):
        """Test getting cost summary for a period"""
        deployment = self.create_deployment()

        # Create cost record
        now = timezone.now()
        NodeDeploymentCostRecord.objects.create(
            deployment=deployment,
            period_start=now - timedelta(days=1),
            period_end=now,
            cost_eur=Decimal("0.15"),
            compute_cost=Decimal("0.15"),
            bandwidth_cost=Decimal("0"),
            storage_cost=Decimal("0"),
        )

        summary = self.service.get_cost_summary(
            now - timedelta(days=1),
            now,
        )

        self.assertIsInstance(summary, CostSummary)
        self.assertEqual(summary.total_eur, Decimal("0.15"))
        self.assertEqual(summary.compute_eur, Decimal("0.15"))
        self.assertEqual(summary.node_count, 1)

    def test_get_monthly_summary(self):
        """Test getting monthly summary"""
        deployment = self.create_deployment()
        now = timezone.now()

        NodeDeploymentCostRecord.objects.create(
            deployment=deployment,
            period_start=now.replace(day=1),
            period_end=now,
            cost_eur=Decimal("4.35"),
            compute_cost=Decimal("4.35"),
        )

        summary = self.service.get_monthly_summary(now.year, now.month)

        self.assertIsInstance(summary, CostSummary)
        self.assertEqual(summary.total_eur, Decimal("4.35"))

    def test_get_current_month_to_date(self):
        """Test getting MTD costs"""
        deployment = self.create_deployment()
        now = timezone.now()

        NodeDeploymentCostRecord.objects.create(
            deployment=deployment,
            period_start=now.replace(day=1),
            period_end=now,
            cost_eur=Decimal("2.50"),
            compute_cost=Decimal("2.50"),
        )

        mtd = self.service.get_current_month_to_date()

        self.assertIsInstance(mtd, CostSummary)
        self.assertEqual(mtd.total_eur, Decimal("2.50"))

    def test_project_monthly_cost(self):
        """Test monthly cost projection"""
        deployment = self.create_deployment()

        projected = self.service.project_monthly_cost(deployment)

        self.assertEqual(projected, self.size.monthly_cost_eur)

    def test_project_monthly_cost_no_size(self):
        """Test projection when deployment has no size (unsaved state)"""
        deployment = self.create_deployment()
        # Test the method logic without persisting - just set _id to None directly
        deployment.node_size_id = None
        # Don't save since node_size is NOT NULL - just test the method handles None

        projected = self.service.project_monthly_cost(deployment)

        self.assertEqual(projected, Decimal("0"))

    def test_get_provider_breakdown(self):
        """Test getting costs by provider"""
        deployment = self.create_deployment()
        now = timezone.now()

        NodeDeploymentCostRecord.objects.create(
            deployment=deployment,
            period_start=now - timedelta(days=1),
            period_end=now,
            cost_eur=Decimal("1.00"),
        )

        breakdown = self.service.get_provider_breakdown(
            now - timedelta(days=1),
            now,
        )

        self.assertIn("Hetzner Cloud", breakdown)
        self.assertEqual(breakdown["Hetzner Cloud"], Decimal("1.00"))

    def test_singleton_service(self):
        """Test that get_cost_tracking_service returns singleton"""
        service1 = get_cost_tracking_service()
        service2 = get_cost_tracking_service()

        self.assertIs(service1, service2)


# ===============================================================================
# SSH KEY MANAGER TESTS
# ===============================================================================


class SSHKeyManagerTests(TestCase):
    """Tests for SSHKeyManager"""

    def setUp(self):
        self.manager = SSHKeyManager()

    def test_generate_key_pair(self):
        """Test generating an ED25519 key pair"""
        key_pair = self.manager.generate_key_pair()

        self.assertIsInstance(key_pair, SSHKeyPair)
        self.assertTrue(key_pair.private_key.startswith("-----BEGIN"))
        self.assertTrue(key_pair.public_key.startswith("ssh-ed25519"))
        self.assertTrue(len(key_pair.fingerprint) > 0)

    def test_generate_key_pair_unique(self):
        """Test that each generated key pair is unique"""
        key1 = self.manager.generate_key_pair()
        key2 = self.manager.generate_key_pair()

        self.assertNotEqual(key1.private_key, key2.private_key)
        self.assertNotEqual(key1.public_key, key2.public_key)
        self.assertNotEqual(key1.fingerprint, key2.fingerprint)

    def test_fingerprint_format(self):
        """Test that fingerprint is in expected format"""
        key_pair = self.manager.generate_key_pair()

        # Fingerprint should be SHA256:base64
        self.assertTrue(key_pair.fingerprint.startswith("SHA256:"))

    def test_has_master_key_false(self):
        """Test has_master_key returns False when not configured"""
        self.assertFalse(self.manager.has_master_key())

    def test_get_master_key_not_configured(self):
        """Test get_master_key returns error when not configured"""
        result = self.manager.get_master_key()

        self.assertTrue(result.is_err())
        self.assertIn("not configured", result.unwrap_err())
