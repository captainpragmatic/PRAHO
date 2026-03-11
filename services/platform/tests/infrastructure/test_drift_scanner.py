"""
Tests for DriftScannerService

Tests drift detection across cloud, network, and application layers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_gateway import ServerInfo
from apps.infrastructure.drift_scanner import DriftScannerService
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


class DriftScannerTestBase(TestCase):
    """Base test class with common setup for drift scanner tests."""

    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="het",
            credential_identifier="test-cred",
        )
        self.region = NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        self.size = NodeSize.objects.create(
            provider=self.provider,
            name="Small",
            display_name="2 vCPU / 4GB",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.0100",
            monthly_cost_eur="5.00",
        )
        self.panel = PanelType.objects.create(
            name="Virtualmin GPL",
            panel_type="virtualmin",
            ansible_playbook="virtualmin.yml",
        )
        self.deployment = NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            node_size=self.size,
            region=self.region,
            panel_type=self.panel,
            hostname="prd-sha-het-de-fsn1-001",
            node_number=1,
            status="completed",
            external_node_id="12345",
            ipv4_address="1.2.3.4",
            ipv6_address="2001:db8::1",
        )
        self.scanner = DriftScannerService()


class TestCloudDriftDetection(DriftScannerTestBase):
    """Tests for cloud layer drift detection."""

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_cloud_drift_detected_server_type_changed(self, mock_gateway_factory, mock_token):
        """Server type mismatch should create HIGH drift report."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="test", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx41",  # Different from cpx21
        ))
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        type_reports = [r for r in reports if r.field_name == "server_type"]
        self.assertEqual(len(type_reports), 1)
        self.assertEqual(type_reports[0].severity, "high")

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_cloud_drift_detected_server_deleted(self, mock_gateway_factory, mock_token):
        """Server not found should create CRITICAL drift report."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(None)
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        self.assertTrue(any(r.field_name == "server_deleted" and r.severity == "critical" for r in reports))

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_cloud_drift_detected_ip_changed(self, mock_gateway_factory, mock_token):
        """IP address change should create CRITICAL drift report."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="test", status="running",
            ipv4_address="5.6.7.8",  # Different IP
            ipv6_address="2001:db8::1",
            server_type="cpx21",
        ))
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        ip_reports = [r for r in reports if r.field_name == "ipv4_address"]
        self.assertEqual(len(ip_reports), 1)
        self.assertEqual(ip_reports[0].severity, "critical")

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_cloud_no_drift(self, mock_gateway_factory, mock_token):
        """Matching server should produce no reports."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="prd-sha-het-de-fsn1-001", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx21",
            labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
        ))
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 0)

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_scan_failed_gateway_error(self, mock_gateway_factory, mock_token):
        """Gateway error should mark check as failed."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.side_effect = Exception("API timeout")
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())

        failed_checks = DriftCheck.objects.filter(
            deployment=self.deployment, status="failed"
        )
        self.assertEqual(failed_checks.count(), 1)


class TestNetworkDriftDetection(DriftScannerTestBase):
    """Tests for network layer drift detection."""

    @patch("apps.infrastructure.drift_scanner.DriftScannerService._tcp_probe")
    def test_network_unreachable(self, mock_probe):
        """Single network failure should create HIGH report."""
        mock_probe.return_value = False

        result = self.scanner.scan_deployment(self.deployment, check_types=["network"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        self.assertTrue(any(r.field_name == "network_unreachable" and r.severity == "high" for r in reports))

    @patch("apps.infrastructure.drift_scanner.DriftScannerService._tcp_probe")
    def test_network_unreachable_consecutive(self, mock_probe):
        """3+ consecutive network failures should create CRITICAL report."""
        mock_probe.return_value = False

        # Create 2 previous failed network checks
        for _ in range(2):
            check = DriftCheck.objects.create(
                deployment=self.deployment, check_type="network", status="completed",
            )
            DriftReport.objects.create(
                drift_check=check, deployment=self.deployment,
                severity="high", category="network",
                field_name="network_unreachable",
                expected_value="reachable", actual_value="unreachable",
            )

        result = self.scanner.scan_deployment(self.deployment, check_types=["network"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        self.assertTrue(
            any(r.field_name == "network_unreachable_consecutive" and r.severity == "critical" for r in reports)
        )


class TestAutoResolution(DriftScannerTestBase):
    """Tests for automatic drift resolution."""

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_auto_resolve_low_drift(self, mock_gateway_factory, mock_token):
        """LOW auto-resolvable drift should be auto-synced."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="prd-sha-het-de-fsn1-001", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx21",
            labels={"managed-by": "praho", "hostname": "wrong-hostname"},  # Wrong label
        ))
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        reports = result.unwrap()
        label_reports = [r for r in reports if r.field_name == "labels"]
        self.assertEqual(len(label_reports), 1)
        # Should be auto-resolved
        label_reports[0].refresh_from_db()
        self.assertTrue(label_reports[0].resolved)
        self.assertEqual(label_reports[0].resolution_type, "auto_sync")

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_high_drift_creates_remediation_request(self, mock_gateway_factory, mock_token):
        """HIGH drift should create a pending remediation request."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="test", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx41",  # Different type -> HIGH
            labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
        ))
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())

        remediations = DriftRemediationRequest.objects.filter(deployment=self.deployment)
        self.assertTrue(remediations.exists())
        self.assertEqual(remediations.first().status, "pending_approval")

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_critical_drift_creates_remediation_request(self, mock_gateway_factory, mock_token):
        """CRITICAL drift should also create a remediation request."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(None)  # Server deleted
        mock_gateway_factory.return_value = mock_gw

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())

        remediations = DriftRemediationRequest.objects.filter(deployment=self.deployment)
        self.assertTrue(remediations.exists())


class TestScanDeployment(DriftScannerTestBase):
    """Tests for overall scan_deployment behavior."""

    @patch("apps.infrastructure.drift_scanner.DriftScannerService._tcp_probe")
    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_scan_deployment_multiple_layers(self, mock_gateway_factory, mock_token, mock_probe):
        """Scanning multiple layers should create checks for each."""
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="test", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx21",
            labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
        ))
        mock_gateway_factory.return_value = mock_gw
        mock_probe.return_value = True

        result = self.scanner.scan_deployment(self.deployment)
        self.assertTrue(result.is_ok())

        checks = DriftCheck.objects.filter(deployment=self.deployment)
        check_types = set(checks.values_list("check_type", flat=True))
        self.assertIn("cloud", check_types)
        self.assertIn("network", check_types)
        self.assertIn("application", check_types)

    def test_scan_skips_inactive_deployments(self):
        """Should reject scans on non-completed deployments."""
        self.deployment.status = "pending"
        self.deployment.save(update_fields=["status"])

        result = self.scanner.scan_deployment(self.deployment)
        self.assertTrue(result.is_err())
        self.assertIn("Cannot scan", result.unwrap_err())
