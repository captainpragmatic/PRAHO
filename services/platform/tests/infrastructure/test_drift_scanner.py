"""
Tests for DriftScannerService

Tests drift detection across cloud, network, and application layers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.types import Ok
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
    def test_network_failure_streak_escalates_single_open_report(self, mock_probe):
        """3 consecutive failures escalate ONE open report to critical in place."""
        mock_probe.return_value = False

        for _ in range(3):
            result = self.scanner.scan_deployment(self.deployment, check_types=["network"])
            self.assertTrue(result.is_ok())

        open_reports = DriftReport.objects.filter(deployment=self.deployment, resolved=False)
        self.assertEqual(open_reports.count(), 1)
        report = open_reports.first()
        self.assertEqual(report.field_name, "network_unreachable")  # name stays stable
        self.assertEqual(report.severity, "critical")
        self.assertEqual(report.occurrence_count, 3)

    @patch("apps.infrastructure.drift_scanner.DriftScannerService._tcp_probe")
    def test_network_recovery_heals_open_report(self, mock_probe):
        """A successful probe closes the open network report and its request."""
        mock_probe.return_value = False
        self.scanner.scan_deployment(self.deployment, check_types=["network"])
        report = DriftReport.objects.get(deployment=self.deployment, resolved=False)
        request = report.remediation_requests.get()

        mock_probe.return_value = True
        self.scanner.scan_deployment(self.deployment, check_types=["network"])

        report.refresh_from_db()
        request.refresh_from_db()
        self.assertTrue(report.resolved)
        self.assertEqual(report.resolution_type, "healed")
        self.assertEqual(request.status, "superseded")


class TestAutoResolution(DriftScannerTestBase):
    """Tests for automatic drift resolution."""

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_label_drift_stays_open_as_single_aggregated_report(self, mock_gateway_factory, mock_token):
        """Label mismatches aggregate into ONE honest open low report, no request.

        (Previously they were marked 'auto_sync' resolved without any actual
        sync, re-minting a resolved duplicate every scan forever.)
        """
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(
            server_id="12345", name="prd-sha-het-de-fsn1-001", status="running",
            ipv4_address="1.2.3.4", ipv6_address="2001:db8::1",
            server_type="cpx21",
            labels={"managed-by": "other", "hostname": "wrong-hostname"},  # Both labels wrong
        ))
        mock_gateway_factory.return_value = mock_gw

        for _ in range(2):
            result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
            self.assertTrue(result.is_ok())

        label_reports = DriftReport.objects.filter(deployment=self.deployment, field_name="labels")
        self.assertEqual(label_reports.count(), 1)
        report = label_reports.first()
        self.assertFalse(report.resolved)
        self.assertEqual(report.occurrence_count, 2)
        self.assertIn("hostname=", report.expected_value)
        self.assertIn("managed-by=", report.expected_value)
        self.assertFalse(report.remediation_requests.exists())

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
        self.assertEqual(remediations.first().action_type, "apply_desired")

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
        # server_deleted has no automated fix — it must be routed to manual work
        self.assertEqual(remediations.first().action_type, "manual_intervention")


class TestDedupAndConvergence(DriftScannerTestBase):
    """Tests for open-report dedup, request maintenance, and healing."""

    def _mock_gateway(self, mock_gateway_factory, mock_token, **server_kwargs):
        defaults = {
            "server_id": "12345",
            "name": "prd-sha-het-de-fsn1-001",
            "status": "running",
            "ipv4_address": "1.2.3.4",
            "ipv6_address": "2001:db8::1",
            "server_type": "cpx21",
            "labels": {"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
        }
        defaults.update(server_kwargs)
        mock_token.return_value = Ok("test-token")
        mock_gw = MagicMock()
        mock_gw.get_server.return_value = Ok(ServerInfo(**defaults))
        mock_gateway_factory.return_value = mock_gw
        return mock_gw

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_second_scan_does_not_duplicate_open_report(self, mock_gateway_factory, mock_token):
        """The 15-min cadence must refresh, not mint ~96 duplicates a day."""
        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx41")

        for _ in range(2):
            result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
            self.assertTrue(result.is_ok())

        open_reports = DriftReport.objects.filter(
            deployment=self.deployment, field_name="server_type", resolved=False
        )
        self.assertEqual(open_reports.count(), 1)
        report = open_reports.first()
        self.assertEqual(report.occurrence_count, 2)
        self.assertIsNotNone(report.last_seen_at)
        self.assertEqual(report.remediation_requests.count(), 1)

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_healed_drift_closes_report_and_supersedes_request(self, mock_gateway_factory, mock_token):
        """A clean scan closes drift fixed out-of-band (manual fixes converge)."""
        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx41")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        report = DriftReport.objects.get(deployment=self.deployment, field_name="server_type")
        request = report.remediation_requests.get()

        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx21")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])

        report.refresh_from_db()
        request.refresh_from_db()
        self.assertTrue(report.resolved)
        self.assertEqual(report.resolution_type, "healed")
        self.assertEqual(request.status, "superseded")

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_rejected_request_not_reminted_while_drift_unchanged(self, mock_gateway_factory, mock_token):
        """Reject means 'stop asking' — until the observed drift changes."""
        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx41")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        report = DriftReport.objects.get(deployment=self.deployment, field_name="server_type")
        request = report.remediation_requests.get()
        request.status = "rejected"
        request.save(update_fields=["status"])

        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertEqual(report.remediation_requests.count(), 1)  # no re-mint

        # The drift evolves -> the rejection no longer covers it
        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx51")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertEqual(report.remediation_requests.count(), 2)
        self.assertTrue(report.remediation_requests.filter(status="pending_approval").exists())

    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_pending_request_updated_in_place_when_drift_evolves(self, mock_gateway_factory, mock_token):
        """A pending request always reflects the drift it would act on."""
        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx41")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        report = DriftReport.objects.get(deployment=self.deployment, field_name="server_type")
        request = report.remediation_requests.get()
        self.assertEqual(request.action_details["actual_value"], "cpx41")

        self._mock_gateway(mock_gateway_factory, mock_token, server_type="cpx51")
        self.scanner.scan_deployment(self.deployment, check_types=["cloud"])

        self.assertEqual(report.remediation_requests.count(), 1)
        request.refresh_from_db()
        self.assertEqual(request.action_details["actual_value"], "cpx51")
        self.assertEqual(request.action_details["severity"], "high")

    @override_settings(
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "drift-lock"}}
    )
    @patch("apps.infrastructure.drift_scanner.get_provider_token")
    @patch("apps.infrastructure.drift_scanner.get_cloud_gateway")
    def test_scan_lock_blocks_concurrent_scan_and_is_released(self, mock_gateway_factory, mock_token):
        """Per-deployment lock serializes every scan entry point."""
        self._mock_gateway(mock_gateway_factory, mock_token)
        lock_key = f"drift_scan_dep_{self.deployment.pk}"

        cache.add(lock_key, "other-scanner", 900)
        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_err())
        self.assertIn("already running", result.unwrap_err())
        cache.delete(lock_key)

        result = self.scanner.scan_deployment(self.deployment, check_types=["cloud"])
        self.assertTrue(result.is_ok())
        self.assertIsNone(cache.get(lock_key))  # released after the scan


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
