# ===============================================================================
# INFRASTRUCTURE MODELS TESTS
# ===============================================================================
"""
Tests for Infrastructure app models.

Covers:
- CloudProvider model
- NodeRegion model
- NodeSize model
- PanelType model
- NodeDeployment model
- NodeDeploymentLog model
- NodeDeploymentCostRecord model
"""

from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeDeploymentCostRecord,
    NodeDeploymentLog,
    NodeRegion,
    NodeSize,
    PanelType,
)

User = get_user_model()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def create_test_user(email: str = "test@example.com", **kwargs) -> User:
    """Helper to create test users"""
    defaults = {
        "first_name": "Test",
        "last_name": "User",
        "password": "testpass123",
    }
    defaults.update(kwargs)
    return User.objects.create_user(email=email, **defaults)


def create_test_provider(**kwargs) -> CloudProvider:
    """Helper to create test cloud providers"""
    defaults = {
        "name": "Hetzner Cloud",
        "code": "het",
        "provider_type": "hetzner",
        "credential_identifier": "hetzner_api_token",
        "is_active": True,
    }
    defaults.update(kwargs)
    return CloudProvider.objects.create(**defaults)


def create_test_region(provider: CloudProvider, **kwargs) -> NodeRegion:
    """Helper to create test regions"""
    defaults = {
        "provider": provider,
        "name": "Falkenstein DC14",
        "provider_region_id": "fsn1-dc14",
        "normalized_code": "fsn1",
        "country_code": "de",
        "city": "Falkenstein",
        "is_active": True,
    }
    defaults.update(kwargs)
    return NodeRegion.objects.create(**defaults)


def create_test_size(provider: CloudProvider, **kwargs) -> NodeSize:
    """Helper to create test node sizes"""
    defaults = {
        "provider": provider,
        "name": "CX22",
        "display_name": "2 vCPU / 4GB RAM / 40GB",
        "provider_type_id": "cx22",
        "vcpus": 2,
        "memory_gb": 4,
        "disk_gb": 40,
        "hourly_cost_eur": Decimal("0.006"),
        "monthly_cost_eur": Decimal("4.35"),
        "max_domains": 25,
        "is_active": True,
    }
    defaults.update(kwargs)
    return NodeSize.objects.create(**defaults)


def create_test_panel(**kwargs) -> PanelType:
    """Helper to create test panel types"""
    defaults = {
        "name": "Virtualmin GPL",
        "panel_type": "virtualmin",
        "version": "7.10.0",
        "ansible_playbook": "virtualmin.yml",
        "is_active": True,
    }
    defaults.update(kwargs)
    return PanelType.objects.create(**defaults)


# ===============================================================================
# CLOUD PROVIDER TESTS
# ===============================================================================


class CloudProviderModelTests(TestCase):
    """Tests for CloudProvider model"""

    def test_create_cloud_provider(self):
        """Test creating a cloud provider"""
        provider = create_test_provider()

        self.assertEqual(provider.name, "Hetzner Cloud")
        self.assertEqual(provider.code, "het")
        self.assertEqual(provider.provider_type, "hetzner")
        self.assertTrue(provider.is_active)
        self.assertIsNotNone(provider.id)

    def test_provider_code_unique(self):
        """Test that provider code must be unique"""
        create_test_provider(code="het")

        with self.assertRaises(IntegrityError):
            create_test_provider(code="het", name="Another Provider")

    def test_provider_str_representation(self):
        """Test string representation"""
        provider = create_test_provider(name="Test Provider", code="tst")

        self.assertEqual(str(provider), "Test Provider (tst)")

    def test_provider_type_choices(self):
        """Test valid provider types"""
        valid_types = ["hetzner", "digitalocean", "aws", "gcp"]
        for provider_type in valid_types:
            provider = CloudProvider(
                name=f"Test {provider_type}",
                code=provider_type[:3],
                provider_type=provider_type,
                credential_identifier=f"{provider_type}_api_token",
            )
            # Should not raise
            provider.full_clean()


# ===============================================================================
# NODE REGION TESTS
# ===============================================================================


class NodeRegionModelTests(TestCase):
    """Tests for NodeRegion model"""

    def setUp(self):
        self.provider = create_test_provider()

    def test_create_region(self):
        """Test creating a region"""
        region = create_test_region(self.provider)

        self.assertEqual(region.name, "Falkenstein DC14")
        self.assertEqual(region.provider_region_id, "fsn1-dc14")
        self.assertEqual(region.normalized_code, "fsn1")
        self.assertEqual(region.country_code, "de")
        self.assertTrue(region.is_active)

    def test_region_str_representation(self):
        """Test string representation"""
        region = create_test_region(self.provider, name="Test Region")

        self.assertEqual(str(region), "Test Region (DE/fsn1)")

    def test_region_provider_relationship(self):
        """Test region-provider relationship"""
        region = create_test_region(self.provider)

        self.assertEqual(region.provider, self.provider)
        self.assertIn(region, self.provider.regions.all())


# ===============================================================================
# NODE SIZE TESTS
# ===============================================================================


class NodeSizeModelTests(TestCase):
    """Tests for NodeSize model"""

    def setUp(self):
        self.provider = create_test_provider()

    def test_create_size(self):
        """Test creating a node size"""
        size = create_test_size(self.provider)

        self.assertEqual(size.name, "CX22")
        self.assertEqual(size.vcpus, 2)
        self.assertEqual(size.memory_gb, 4)
        self.assertEqual(size.disk_gb, 40)
        self.assertEqual(size.monthly_cost_eur, Decimal("4.35"))

    def test_size_display_name(self):
        """Test display name property"""
        size = create_test_size(self.provider, display_name="2 vCPU / 4GB RAM")

        self.assertEqual(size.display_name, "2 vCPU / 4GB RAM")

    def test_size_str_representation(self):
        """Test string representation"""
        size = create_test_size(
            self.provider,
            name="CX42",
            display_name="4 vCPU / 8GB RAM",
        )

        self.assertEqual(str(size), "4 vCPU / 8GB RAM (het)")


# ===============================================================================
# PANEL TYPE TESTS
# ===============================================================================


class PanelTypeModelTests(TestCase):
    """Tests for PanelType model"""

    def test_create_panel_type(self):
        """Test creating a panel type"""
        panel = create_test_panel()

        self.assertEqual(panel.name, "Virtualmin GPL")
        self.assertEqual(panel.panel_type, "virtualmin")
        self.assertEqual(panel.version, "7.10.0")
        self.assertEqual(panel.ansible_playbook, "virtualmin.yml")
        self.assertTrue(panel.is_active)

    def test_panel_name_unique(self):
        """Test that panel name must be unique"""
        create_test_panel(name="Test Panel")

        with self.assertRaises(IntegrityError):
            create_test_panel(name="Test Panel")


# ===============================================================================
# NODE DEPLOYMENT TESTS
# ===============================================================================


class NodeDeploymentModelTests(TestCase):
    """Tests for NodeDeployment model"""

    def setUp(self):
        self.user = create_test_user()
        self.provider = create_test_provider()
        self.region = create_test_region(self.provider)
        self.size = create_test_size(self.provider)
        self.panel = create_test_panel()

    def create_deployment(self, **kwargs) -> NodeDeployment:
        """Helper to create a deployment"""
        defaults = {
            "hostname": "prd-sha-het-de-fsn1-001",
            "display_name": "Test Server",
            "environment": "prd",
            "node_type": "sha",
            "node_number": 1,
            "provider": self.provider,
            "region": self.region,
            "node_size": self.size,
            "panel_type": self.panel,
            "dns_zone": "nodes.prahohost.com",
            "initiated_by": self.user,
        }
        defaults.update(kwargs)
        return NodeDeployment.objects.create(**defaults)

    def test_create_deployment(self):
        """Test creating a deployment"""
        deployment = self.create_deployment()

        self.assertEqual(deployment.hostname, "prd-sha-het-de-fsn1-001")
        self.assertEqual(deployment.environment, "prd")
        self.assertEqual(deployment.node_type, "sha")
        self.assertEqual(deployment.status, "pending")
        self.assertIsNone(deployment.started_at)

    def test_deployment_hostname_unique(self):
        """Test that hostname must be unique"""
        self.create_deployment(hostname="prd-sha-het-de-fsn1-002", node_number=2)

        with self.assertRaises(IntegrityError):
            self.create_deployment(hostname="prd-sha-het-de-fsn1-002", node_number=3)

    def test_deployment_status_choices(self):
        """Test valid deployment statuses"""
        deployment = self.create_deployment()

        valid_statuses = [
            "pending",
            "provisioning_node",
            "configuring_dns",
            "completed",
            "failed",
            "stopped",
            "destroyed",
        ]
        for status in valid_statuses:
            deployment.status = status
            deployment.save()
            deployment.refresh_from_db()
            self.assertEqual(deployment.status, status)

    def test_deployment_str_representation(self):
        """Test string representation"""
        deployment = self.create_deployment()

        self.assertEqual(str(deployment), "prd-sha-het-de-fsn1-001")

    def test_deployment_fqdn(self):
        """Test FQDN property"""
        deployment = self.create_deployment(
            hostname="prd-sha-het-de-fsn1-001",
            dns_zone="nodes.prahohost.com",
        )

        self.assertEqual(deployment.fqdn, "prd-sha-het-de-fsn1-001.nodes.prahohost.com")

    def test_deployment_relationships(self):
        """Test deployment relationships"""
        deployment = self.create_deployment()

        self.assertEqual(deployment.provider, self.provider)
        self.assertEqual(deployment.region, self.region)
        self.assertEqual(deployment.node_size, self.size)
        self.assertEqual(deployment.panel_type, self.panel)
        self.assertEqual(deployment.initiated_by, self.user)


# ===============================================================================
# NODE DEPLOYMENT LOG TESTS
# ===============================================================================


class NodeDeploymentLogModelTests(TestCase):
    """Tests for NodeDeploymentLog model"""

    def setUp(self):
        self.user = create_test_user()
        self.provider = create_test_provider()
        self.region = create_test_region(self.provider)
        self.size = create_test_size(self.provider)
        self.panel = create_test_panel()
        self.deployment = NodeDeployment.objects.create(
            hostname="stg-vps-het-de-fsn1-001",
            environment="stg",
            node_type="vps",
            node_number=1,
            provider=self.provider,
            region=self.region,
            node_size=self.size,
            panel_type=self.panel,
            dns_zone="test.com",
            initiated_by=self.user,
        )

    def test_create_log(self):
        """Test creating a deployment log"""
        log = NodeDeploymentLog.objects.create(
            deployment=self.deployment,
            level="info",
            message="Deployment started",
            phase="terraform_init",
        )

        self.assertEqual(log.deployment, self.deployment)
        self.assertEqual(log.level, "info")
        self.assertEqual(log.message, "Deployment started")
        self.assertEqual(log.phase, "terraform_init")

    def test_log_levels(self):
        """Test valid log levels"""
        for level in ["debug", "info", "warning", "error"]:
            log = NodeDeploymentLog.objects.create(
                deployment=self.deployment,
                level=level,
                message=f"Test {level} message",
                phase="test",
            )
            self.assertEqual(log.level, level)

    def test_log_ordering(self):
        """Test logs are ordered by created_at asc"""
        NodeDeploymentLog.objects.create(
            deployment=self.deployment,
            level="info",
            message="First",
            phase="test",
        )
        NodeDeploymentLog.objects.create(
            deployment=self.deployment,
            level="info",
            message="Second",
            phase="test",
        )

        logs = list(self.deployment.logs.all())
        self.assertEqual(logs[0].message, "First")
        self.assertEqual(logs[1].message, "Second")


# ===============================================================================
# COST RECORD TESTS
# ===============================================================================


class NodeDeploymentCostRecordModelTests(TestCase):
    """Tests for NodeDeploymentCostRecord model"""

    def setUp(self):
        self.user = create_test_user()
        self.provider = create_test_provider()
        self.region = create_test_region(self.provider)
        self.size = create_test_size(self.provider)
        self.panel = create_test_panel()
        self.deployment = NodeDeployment.objects.create(
            hostname="prd-sha-het-de-fsn1-001",
            environment="prd",
            node_type="sha",
            node_number=1,
            provider=self.provider,
            region=self.region,
            node_size=self.size,
            panel_type=self.panel,
            dns_zone="test.com",
            initiated_by=self.user,
            status="completed",
        )

    def test_create_cost_record(self):
        """Test creating a cost record"""
        now = timezone.now()
        record = NodeDeploymentCostRecord.objects.create(
            deployment=self.deployment,
            period_start=now - timezone.timedelta(days=1),
            period_end=now,
            cost_eur=Decimal("0.14"),
            compute_cost=Decimal("0.14"),
            bandwidth_cost=Decimal("0"),
            storage_cost=Decimal("0"),
        )

        self.assertEqual(record.deployment, self.deployment)
        self.assertEqual(record.cost_eur, Decimal("0.14"))
        self.assertEqual(record.compute_cost, Decimal("0.14"))

    def test_cost_record_relationship(self):
        """Test cost record relationship to deployment"""
        now = timezone.now()
        NodeDeploymentCostRecord.objects.create(
            deployment=self.deployment,
            period_start=now - timezone.timedelta(days=1),
            period_end=now,
            cost_eur=Decimal("1.00"),
        )

        self.assertEqual(self.deployment.cost_records.count(), 1)
