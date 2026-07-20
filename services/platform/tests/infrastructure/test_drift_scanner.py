"""
Tests for DriftScannerService

Tests drift detection across cloud, network, and application layers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.db import IntegrityError
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
from apps.infrastructure.tasks import execute_remediation_task


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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="test",
                status="running",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:db8::1",
                server_type="cpx41",  # Different from cpx21
            )
        )
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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="test",
                status="running",
                ipv4_address="5.6.7.8",  # Different IP
                ipv6_address="2001:db8::1",
                server_type="cpx21",
            )
        )
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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="prd-sha-het-de-fsn1-001",
                status="running",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:db8::1",
                server_type="cpx21",
                labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
            )
        )
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

        failed_checks = DriftCheck.objects.filter(deployment=self.deployment, status="failed")
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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="prd-sha-het-de-fsn1-001",
                status="running",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:db8::1",
                server_type="cpx21",
                labels={"managed-by": "other", "hostname": "wrong-hostname"},  # Both labels wrong
            )
        )
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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="test",
                status="running",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:db8::1",
                server_type="cpx41",  # Different type -> HIGH
                labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
            )
        )
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

        open_reports = DriftReport.objects.filter(deployment=self.deployment, field_name="server_type", resolved=False)
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
        mock_gw.get_server.return_value = Ok(
            ServerInfo(
                server_id="12345",
                name="test",
                status="running",
                ipv4_address="1.2.3.4",
                ipv6_address="2001:db8::1",
                server_type="cpx21",
                labels={"managed-by": "praho", "hostname": "prd-sha-het-de-fsn1-001"},
            )
        )
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


class TestApprovalIntegrityAndDedupRaces(DriftScannerTestBase):
    """Approval-gated writes and dedup catch-paths must survive real races."""

    def setUp(self) -> None:
        super().setUp()
        self.check = DriftCheck.objects.create(
            deployment=self.deployment,
            check_type="cloud",
            status="completed",
        )
        self.report = DriftReport.objects.create(
            drift_check=self.check,
            deployment=self.deployment,
            severity="high",
            category="server_state",
            field_name="server_type",
            expected_value="cpx21",
            actual_value="cpx41",
        )

    def _pending_request(self, **overrides) -> DriftRemediationRequest:
        details = {
            "field_name": "server_type",
            "expected_value": "cpx21",
            "actual_value": "cpx31",
            "severity": "high",
        }
        params = {
            "report": self.report,
            "deployment": self.deployment,
            "action_type": "apply_desired",
            "action_details": details,
            "requires_approval": True,
            "status": "pending_approval",
        }
        params.update(overrides)
        return DriftRemediationRequest.objects.create(**params)

    def test_pending_fingerprint_sync_loses_to_concurrent_approval(self) -> None:
        """The CAS must refuse to overwrite a row that left pending_approval
        between the scanner's read and its write — an unconditional save would
        execute values the approving human never saw."""
        request = self._pending_request()
        stale_instance = DriftRemediationRequest.objects.get(pk=request.pk)
        approved_details = dict(stale_instance.action_details)
        DriftRemediationRequest.objects.filter(pk=request.pk).update(status="approved")

        won = self.scanner._sync_pending_fingerprint(stale_instance, self.report)

        self.assertFalse(won)
        request.refresh_from_db()
        self.assertEqual(request.action_details, approved_details)
        self.assertEqual(request.status, "approved")

    def test_pending_fingerprint_sync_wins_when_genuinely_pending(self) -> None:
        request = self._pending_request()

        won = self.scanner._sync_pending_fingerprint(request, self.report)

        self.assertTrue(won)
        request.refresh_from_db()
        self.assertEqual(request.action_details["actual_value"], "cpx41")

    def test_lost_fingerprint_race_supersedes_and_remints(self) -> None:
        """When the sync loses because the row is now approved with stale
        values, the scanner must retire that approval and mint a fresh
        pending request for the current drift."""
        request = self._pending_request()

        def approve_then_lose(req, report):
            DriftRemediationRequest.objects.filter(pk=request.pk).update(status="approved")
            return False

        with patch.object(DriftScannerService, "_sync_pending_fingerprint", side_effect=approve_then_lose):
            self.scanner._ensure_remediation_request(self.report)

        request.refresh_from_db()
        self.assertEqual(request.status, "superseded")
        fresh = self.report.remediation_requests.get(status="pending_approval")
        self.assertEqual(fresh.action_details["actual_value"], "cpx41")

    def test_report_create_race_falls_back_to_concurrent_winner(self) -> None:
        """A concurrent scan winning the report-create race must be refreshed,
        not crash the loser — delete this except-path and this test errors."""
        winner = DriftReport.objects.create(
            drift_check=self.check,
            deployment=self.deployment,
            severity="high",
            category="network",
            field_name="ipv4_address",
            expected_value="1.2.3.4",
            actual_value="5.6.7.8",
            occurrence_count=1,
        )
        with patch(
            "apps.infrastructure.drift_scanner.DriftReport.objects.create",
            side_effect=IntegrityError("uniq_open_report_per_field"),
        ):
            outcome = self.scanner._record_drift(
                self.check, self.deployment, "ipv4_address", "critical", "network", "1.2.3.4", "5.6.7.8"
            )

        self.assertEqual(outcome.report.pk, winner.pk)
        winner.refresh_from_db()
        self.assertEqual(winner.occurrence_count, 2)
        self.assertEqual(
            DriftReport.objects.filter(deployment=self.deployment, field_name="ipv4_address", resolved=False).count(),
            1,
        )

    def test_request_mint_race_returns_concurrent_winner(self) -> None:
        """A concurrent scan winning the request-mint race must not crash the
        loser or duplicate the open request."""
        winner = self._pending_request()
        with patch(
            "apps.infrastructure.drift_scanner.DriftRemediationRequest.objects.create",
            side_effect=IntegrityError("uniq_open_request_per_report"),
        ):
            self.scanner._ensure_remediation_request(self.report)

        self.assertEqual(self.report.remediation_requests.count(), 1)
        self.assertEqual(self.report.remediation_requests.get().pk, winner.pk)


class TestExecuteTaskGuards(DriftScannerTestBase):
    def test_execute_remediation_task_handles_missing_request(self) -> None:
        """A vanished request must be reported, not crash the worker."""
        outcome = execute_remediation_task(987654321)

        self.assertEqual(outcome, {"status": "missing"})


class TestDismissedReportNotRerequested(DriftScannerTestBase):
    """#332 RX1: the symmetric lock — a report dismissed (resolved='ignored')
    must not get a fresh remediation request minted by a concurrent scan path."""

    def test_create_request_skips_dismissed_report(self):
        report = DriftReport.objects.create(
            drift_check=DriftCheck.objects.create(deployment=self.deployment, check_type="cloud", status="completed"),
            deployment=self.deployment,
            severity="high",
            category="server_state",
            field_name="server_type",
            expected_value="cpx21",
            actual_value="cpx41",
            resolved=True,
            resolution_type="ignored",
        )

        created = self.scanner._create_remediation_request(report)

        self.assertIsNone(created, "a dismissed report must not receive a new request")
        self.assertEqual(report.remediation_requests.count(), 0)


class TestScanAuditResilience(DriftScannerTestBase):
    """#320: the scanner's scan-started / scan-completed audit calls were
    unwrapped, so an audit-backend exception aborted an otherwise-successful
    scan. They must be best-effort like every other drift audit call site."""

    @patch("apps.infrastructure.drift_scanner.DriftScannerService._tcp_probe")
    @patch(
        "apps.infrastructure.drift_scanner.InfrastructureAuditService.log_drift_scan_completed",
        side_effect=RuntimeError("audit backend down"),
    )
    @patch(
        "apps.infrastructure.drift_scanner.InfrastructureAuditService.log_drift_scan_started",
        side_effect=RuntimeError("audit backend down"),
    )
    def test_scan_survives_audit_failure(self, _mock_started, _mock_completed, mock_probe):
        mock_probe.return_value = True  # reachable → clean scan, no drift to record

        result = self.scanner.scan_deployment(self.deployment, check_types=["network"])

        self.assertTrue(result.is_ok(), f"scan must survive an audit failure, got {result}")
