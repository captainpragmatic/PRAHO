"""
Tests for infrastructure models — NodeDeployment focus.

Covers max_domains logic, hostname generation, state machine transitions,
and model properties.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
    validate_hostname_format,
)


class InfrastructureTestMixin:
    """Shared fixture creation for infrastructure tests."""

    def _create_fixtures(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Hetzner Cloud",
            provider_type="hetzner",
            code="het",
            is_active=True,
            credential_identifier="hcloud_token",
        )
        self.region = NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
            is_active=True,
        )
        self.size_4gb = NodeSize.objects.create(
            provider=self.provider,
            name="CPX21",
            display_name="3 vCPU / 4GB RAM / 80GB",
            provider_type_id="cpx21",
            vcpus=3,
            memory_gb=4,
            disk_gb=80,
            hourly_cost_eur="0.0080",
            monthly_cost_eur="5.39",
            max_domains=50,
            is_active=True,
        )
        self.size_16gb = NodeSize.objects.create(
            provider=self.provider,
            name="CPX41",
            display_name="8 vCPU / 16GB RAM / 240GB",
            provider_type_id="cpx41",
            vcpus=8,
            memory_gb=16,
            disk_gb=240,
            hourly_cost_eur="0.0280",
            monthly_cost_eur="18.59",
            max_domains=200,
            is_active=True,
        )
        self.panel = PanelType.objects.create(
            name="Virtualmin GPL",
            panel_type="virtualmin",
            version="7.10.0",
            ansible_playbook="virtualmin.yml",
            is_active=True,
        )


class TestHostnameValidation(TestCase):
    """Tests for the hostname format validator."""

    def test_valid_hostname(self):
        validate_hostname_format("prd-sha-het-de-fsn1-001")

    def test_invalid_hostname_too_short(self):
        with self.assertRaises(ValidationError):
            validate_hostname_format("prd-sha")

    def test_invalid_hostname_uppercase(self):
        with self.assertRaises(ValidationError):
            validate_hostname_format("PRD-SHA-HET-DE-FSN1-001")

    def test_invalid_hostname_wrong_separator(self):
        with self.assertRaises(ValidationError):
            validate_hostname_format("prd_sha_het_de_fsn1_001")


class TestHostnameGeneration(InfrastructureTestMixin, TestCase):
    """Tests for NodeDeployment.generate_hostname()."""

    def setUp(self):
        self._create_fixtures()

    def test_generate_hostname_format(self):
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )
        hostname = deployment.generate_hostname()
        self.assertEqual(hostname, "prd-sha-het-de-fsn1-001")

    def test_generate_hostname_zero_padded(self):
        deployment = NodeDeployment(
            environment="stg",
            node_type="vps",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=42,
        )
        self.assertEqual(deployment.generate_hostname(), "stg-vps-het-de-fsn1-042")

    def test_auto_generates_hostname_on_save(self):
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )
        deployment.save()
        self.assertEqual(deployment.hostname, "prd-sha-het-de-fsn1-001")

    def test_does_not_overwrite_explicit_hostname(self):
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=5,
            hostname="prd-sha-het-de-fsn1-005",
        )
        deployment.save()
        self.assertEqual(deployment.hostname, "prd-sha-het-de-fsn1-005")


class TestMaxDomains(InfrastructureTestMixin, TestCase):
    """Tests for max_domains field and set_max_domains_from_size()."""

    def setUp(self):
        self._create_fixtures()

    def test_default_max_domains(self):
        """Default max_domains is 50."""
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )
        self.assertEqual(deployment.max_domains, 50)

    def test_set_max_domains_from_4gb_size(self):
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )
        deployment.set_max_domains_from_size()
        self.assertEqual(deployment.max_domains, 50)

    def test_set_max_domains_from_16gb_size(self):
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_16gb,
            panel_type=self.panel,
            node_number=1,
        )
        deployment.set_max_domains_from_size()
        self.assertEqual(deployment.max_domains, 200)

    def test_auto_set_on_creation(self):
        """On first save, max_domains is auto-set from size when at default."""
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_16gb,
            panel_type=self.panel,
            node_number=1,
        )
        deployment.save()
        self.assertEqual(deployment.max_domains, 200)

    def test_max_domains_by_memory_class_var(self):
        """MAX_DOMAINS_BY_MEMORY has expected thresholds."""
        expected = [(2, 25), (4, 50), (8, 100), (16, 200), (32, 500)]
        self.assertEqual(NodeDeployment.MAX_DOMAINS_BY_MEMORY, expected)

    def test_set_max_domains_small_memory(self):
        """Size with 2GB memory gets minimum 25 domains."""
        size_2gb = NodeSize.objects.create(
            provider=self.provider,
            name="CX11",
            display_name="1 vCPU / 2GB RAM / 20GB",
            provider_type_id="cx11",
            vcpus=1,
            memory_gb=2,
            disk_gb=20,
            hourly_cost_eur="0.0040",
            monthly_cost_eur="3.29",
            max_domains=25,
            is_active=True,
        )
        deployment = NodeDeployment(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=size_2gb,
            panel_type=self.panel,
            node_number=10,
        )
        deployment.set_max_domains_from_size()
        self.assertEqual(deployment.max_domains, 25)


class TestStateMachine(InfrastructureTestMixin, TestCase):
    """Tests for NodeDeployment state transitions."""

    def setUp(self):
        self._create_fixtures()
        self.deployment = NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )

    def test_initial_status_is_pending(self):
        self.assertEqual(self.deployment.status, "pending")

    def test_valid_transition_pending_to_provisioning(self):
        self.assertTrue(self.deployment.is_valid_transition("provisioning_node"))

    def test_valid_transition_pending_to_failed(self):
        self.assertTrue(self.deployment.is_valid_transition("failed"))

    def test_invalid_transition_pending_to_completed(self):
        self.assertFalse(self.deployment.is_valid_transition("completed"))

    def test_invalid_transition_pending_to_destroyed(self):
        self.assertFalse(self.deployment.is_valid_transition("destroyed"))

    def test_transition_to_advances_status(self):
        self.deployment.transition_to("provisioning_node", "Starting server creation")
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "provisioning_node")
        self.assertEqual(self.deployment.status_message, "Starting server creation")

    def test_transition_to_invalid_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            self.deployment.transition_to("completed")

    def test_full_happy_path(self):
        """Walk through the entire provisioning pipeline."""
        phases = [
            "provisioning_node",
            "configuring_dns",
            "installing_panel",
            "configuring_backups",
            "validating",
            "registering",
            "completed",
        ]
        for phase in phases:
            self.deployment.transition_to(phase)
        self.assertEqual(self.deployment.status, "completed")

    def test_completed_can_only_go_to_destroying(self):
        # Walk to completed
        for phase in ["provisioning_node", "configuring_dns", "installing_panel",
                       "configuring_backups", "validating", "registering", "completed"]:
            self.deployment.transition_to(phase)

        self.assertTrue(self.deployment.is_valid_transition("destroying"))
        self.assertFalse(self.deployment.is_valid_transition("failed"))
        self.assertFalse(self.deployment.is_valid_transition("pending"))

    def test_failed_can_retry_or_destroy(self):
        self.deployment.transition_to("failed")

        self.assertTrue(self.deployment.is_valid_transition("pending"))
        self.assertTrue(self.deployment.is_valid_transition("destroying"))
        self.assertFalse(self.deployment.is_valid_transition("completed"))

    def test_destroyed_is_terminal(self):
        self.deployment.transition_to("provisioning_node")
        self.deployment.transition_to("failed")
        self.deployment.transition_to("destroying")
        self.deployment.transition_to("destroyed")

        self.assertEqual(NodeDeployment.VALID_TRANSITIONS["destroyed"], [])
        self.assertFalse(self.deployment.is_valid_transition("pending"))
        self.assertFalse(self.deployment.is_valid_transition("failed"))


class TestNodeDeploymentProperties(InfrastructureTestMixin, TestCase):
    """Tests for computed properties on NodeDeployment."""

    def setUp(self):
        self._create_fixtures()
        self.deployment = NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )

    def test_is_active_when_completed(self):
        for phase in ["provisioning_node", "configuring_dns", "installing_panel",
                       "configuring_backups", "validating", "registering", "completed"]:
            self.deployment.transition_to(phase)
        self.assertTrue(self.deployment.is_active)

    def test_is_active_false_when_pending(self):
        self.assertFalse(self.deployment.is_active)

    def test_is_in_progress(self):
        self.assertTrue(self.deployment.is_in_progress)  # pending
        self.deployment.transition_to("provisioning_node")
        self.assertTrue(self.deployment.is_in_progress)

    def test_is_failed(self):
        self.deployment.transition_to("failed")
        self.assertTrue(self.deployment.is_failed)

    def test_is_destroyed(self):
        self.deployment.transition_to("failed")
        self.deployment.transition_to("destroying")
        self.assertTrue(self.deployment.is_destroyed)

    def test_can_be_destroyed(self):
        self.assertFalse(self.deployment.can_be_destroyed)  # pending
        self.deployment.transition_to("failed")
        self.assertTrue(self.deployment.can_be_destroyed)

    def test_can_retry(self):
        self.deployment.transition_to("failed")
        self.assertFalse(self.deployment.can_retry)  # no last_successful_phase

        self.deployment.last_successful_phase = "provisioning_node"
        self.assertTrue(self.deployment.can_retry)

    def test_fqdn_with_dns_zone(self):
        self.deployment.dns_zone = "nodes.pragmatichost.com"
        self.assertEqual(self.deployment.fqdn, "prd-sha-het-de-fsn1-001.nodes.pragmatichost.com")

    def test_fqdn_without_dns_zone(self):
        self.assertEqual(self.deployment.fqdn, "prd-sha-het-de-fsn1-001")


class TestGetNextNodeNumber(InfrastructureTestMixin, TestCase):
    """Tests for NodeDeployment.get_next_node_number()."""

    def setUp(self):
        self._create_fixtures()

    def test_first_node_returns_1(self):
        num = NodeDeployment.get_next_node_number("prd", "sha", self.provider, self.region)
        self.assertEqual(num, 1)

    def test_increments_after_existing(self):
        NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=1,
        )
        num = NodeDeployment.get_next_node_number("prd", "sha", self.provider, self.region)
        self.assertEqual(num, 2)

    def test_different_env_starts_at_1(self):
        NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            region=self.region,
            node_size=self.size_4gb,
            panel_type=self.panel,
            node_number=5,
        )
        num = NodeDeployment.get_next_node_number("stg", "sha", self.provider, self.region)
        self.assertEqual(num, 1)
