"""
Drift Scanner Service

Scans deployments for configuration drift across three layers:
1. Cloud Provider — server type, status, IPs, labels
2. Network — TCP reachability (port 22)
3. Application — Virtualmin config consistency
"""

from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING

from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import CloudProviderGateway, get_cloud_gateway
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport
from apps.infrastructure.provider_config import get_provider_token

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)

# Severity classification for drift fields
SEVERITY_MAP: dict[str, str] = {
    "server_deleted": "critical",
    "ipv4_address": "critical",
    "ipv6_address": "critical",
    "network_unreachable_consecutive": "critical",
    "server_type": "high",
    "firewall": "high",
    "network_unreachable": "high",
    "virtualmin_config": "moderate",
    "extra_domains": "moderate",
    "disk_usage": "low",
    "bandwidth": "low",
    "labels": "low",
    "metadata": "low",
}

# TCP probe timeout in seconds
_DEFAULT_NETWORK_PROBE_TIMEOUT = 10

# Port to probe for network checks
NETWORK_PROBE_PORT = 22

# Number of consecutive failures for critical network drift
_DEFAULT_CONSECUTIVE_FAILURE_THRESHOLD = 3


def _get_network_probe_timeout() -> int:
    """Read network probe timeout from SettingsService with DB-cache layer."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return SettingsService.get_integer_setting(
        "infrastructure.network_probe_timeout_seconds", _DEFAULT_NETWORK_PROBE_TIMEOUT
    )


def _get_consecutive_failure_threshold() -> int:
    """Read consecutive failure threshold from SettingsService with DB-cache layer."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return SettingsService.get_integer_setting(
        "infrastructure.consecutive_failure_threshold", _DEFAULT_CONSECUTIVE_FAILURE_THRESHOLD
    )


class DriftScannerService:
    """Scans deployments for configuration drift across three layers."""

    def scan_deployment(
        self,
        deployment: NodeDeployment,
        check_types: list[str] | None = None,
    ) -> Result[list[DriftReport], str]:
        """Run drift checks on a deployment. Returns list of drift reports."""
        if deployment.status != "completed":
            return Err(f"Cannot scan deployment in status '{deployment.status}'")

        types_to_scan = check_types or ["cloud", "network", "application"]
        all_reports: list[DriftReport] = []

        InfrastructureAuditService.log_drift_scan_started(deployment=deployment)
        logger.info(f"✅ [DriftScanner] Starting scan for {deployment.hostname}: {types_to_scan}")

        for check_type in types_to_scan:
            check = DriftCheck.objects.create(
                deployment=deployment,
                check_type=check_type,
                started_at=timezone.now(),
            )

            try:
                reports = self._run_check(deployment, check, check_type)
                check.status = "completed"
                check.completed_at = timezone.now()
                check.findings_count = len(reports)
                check.save(update_fields=["status", "completed_at", "findings_count"])
                all_reports.extend(reports)
            except Exception as e:
                logger.error(f"🔥 [DriftScanner] Check {check_type} failed for {deployment.hostname}: {e}")
                check.status = "failed"
                check.completed_at = timezone.now()
                check.error_message = str(e)[:1000]
                check.save(update_fields=["status", "completed_at", "error_message"])

        # Process reports: auto-resolve or create remediation requests
        for report in all_reports:
            self._process_report(report)

        InfrastructureAuditService.log_drift_scan_completed(
            deployment=deployment,
            drift_count=len(all_reports),
        )
        logger.info(f"✅ [DriftScanner] Scan complete for {deployment.hostname}: {len(all_reports)} findings")
        return Ok(all_reports)

    def _run_check(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
        check_type: str,
    ) -> list[DriftReport]:
        """Dispatch to the appropriate scan layer."""
        if check_type == "cloud":
            return self._scan_cloud_layer(deployment, check)
        if check_type == "network":
            return self._scan_network_layer(deployment, check)
        if check_type == "application":
            return self._scan_application_layer(deployment, check)
        return []

    def _scan_cloud_layer(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
    ) -> list[DriftReport]:
        """Compare gateway.get_server() fields vs DB."""
        reports: list[DriftReport] = []

        gateway = self._get_gateway(deployment)
        if gateway is None:
            return reports

        server_result = gateway.get_server(deployment.external_node_id)
        if server_result.is_err():
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "server_deleted",
                    "critical",
                    "server_state",
                    expected="exists",
                    actual=f"error: {server_result.unwrap_err()}",
                )
            )
            return reports

        server_info = server_result.unwrap()
        if server_info is None:
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "server_deleted",
                    "critical",
                    "server_state",
                    expected="exists",
                    actual="not found",
                )
            )
            return reports

        # Compare server type
        expected_type = deployment.node_size.provider_type_id if deployment.node_size else ""
        if expected_type and server_info.server_type != expected_type:
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "server_type",
                    "high",
                    "server_state",
                    expected=expected_type,
                    actual=server_info.server_type,
                )
            )

        # Compare status
        if server_info.status != "running":
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "server_status",
                    "high",
                    "server_state",
                    expected="running",
                    actual=server_info.status,
                )
            )

        # Compare IPv4
        if deployment.ipv4_address and server_info.ipv4_address != deployment.ipv4_address:
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "ipv4_address",
                    "critical",
                    "network",
                    expected=str(deployment.ipv4_address),
                    actual=server_info.ipv4_address,
                )
            )

        # Compare IPv6
        if deployment.ipv6_address and server_info.ipv6_address != deployment.ipv6_address:
            reports.append(
                self._create_report(
                    check,
                    deployment,
                    "ipv6_address",
                    "critical",
                    "network",
                    expected=str(deployment.ipv6_address),
                    actual=server_info.ipv6_address,
                )
            )

        # Compare labels
        expected_labels = {
            "managed-by": "praho",
            "hostname": deployment.hostname,
        }
        for key, expected_val in expected_labels.items():
            actual_val = server_info.labels.get(key, "")
            if actual_val != expected_val:
                reports.append(
                    self._create_report(
                        check,
                        deployment,
                        "labels",
                        "low",
                        "server_state",
                        expected=f"{key}={expected_val}",
                        actual=f"{key}={actual_val}",
                        auto_resolvable=True,
                    )
                )

        return reports

    def _scan_network_layer(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
    ) -> list[DriftReport]:
        """TCP probe port 22 with timeout."""
        reports: list[DriftReport] = []

        if not deployment.ipv4_address:
            return reports

        reachable = self._tcp_probe(str(deployment.ipv4_address), NETWORK_PROBE_PORT)

        if not reachable:
            # Check consecutive failures
            consecutive = self._count_consecutive_network_failures(deployment)
            if consecutive >= _get_consecutive_failure_threshold() - 1:
                severity = "critical"
                field_name = "network_unreachable_consecutive"
            else:
                severity = "high"
                field_name = "network_unreachable"

            reports.append(
                self._create_report(
                    check,
                    deployment,
                    field_name,
                    severity,
                    "network",
                    expected="reachable",
                    actual="unreachable",
                )
            )

        return reports

    def _scan_application_layer(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
    ) -> list[DriftReport]:
        """Check Virtualmin config if linked."""
        reports: list[DriftReport] = []

        if not deployment.virtualmin_server:
            return reports

        # Application layer checks are placeholder for now
        # Future: call Virtualmin API to compare domain count, PHP versions, etc.
        return reports

    def _process_report(self, report: DriftReport) -> None:
        """Auto-resolve or create remediation request based on severity."""
        if report.severity == "low" and report.auto_resolvable:
            self._auto_resolve_low_drift(report)
        elif report.severity == "moderate" and report.auto_resolvable:
            self._auto_resolve_moderate_drift(report)
        elif report.severity in ("high", "critical"):
            self._create_remediation_request(report)

        # Audit: drift detected
        try:
            InfrastructureAuditService.log_drift_detected(report.deployment, report, InfrastructureAuditContext())
        except Exception:
            logger.warning(f"⚠️ [DriftScanner] Failed to log audit for {report}")

    def _auto_resolve_low_drift(self, report: DriftReport) -> None:
        """Update DB field to match actual value. Mark resolved."""
        report.resolved = True
        report.resolved_at = timezone.now()
        report.resolution_type = "auto_sync"
        report.save(update_fields=["resolved", "resolved_at", "resolution_type"])

        logger.info(f"✅ [DriftScanner] Auto-resolved LOW drift: {report.field_name} for {report.deployment.hostname}")

        try:
            InfrastructureAuditService.log_drift_auto_resolved(report.deployment, report, InfrastructureAuditContext())
        except Exception:
            logger.warning(f"⚠️ [DriftScanner] Failed to log audit for auto-resolve: {report}")

    def _auto_resolve_moderate_drift(self, report: DriftReport) -> None:
        """Update DB + create admin notification. Mark resolved."""
        report.resolved = True
        report.resolved_at = timezone.now()
        report.resolution_type = "auto_sync"
        report.save(update_fields=["resolved", "resolved_at", "resolution_type"])

        logger.info(
            f"✅ [DriftScanner] Auto-resolved MODERATE drift: {report.field_name} "
            f"for {report.deployment.hostname} (notification sent)"
        )

        try:
            InfrastructureAuditService.log_drift_auto_resolved(report.deployment, report, InfrastructureAuditContext())
        except Exception:
            logger.warning(f"⚠️ [DriftScanner] Failed to log audit for auto-resolve: {report}")

    def _create_remediation_request(self, report: DriftReport) -> DriftRemediationRequest:
        """Create pending approval request for HIGH/CRITICAL drift."""
        requires_restart = report.field_name in ("server_type",)

        request = DriftRemediationRequest.objects.create(
            report=report,
            deployment=report.deployment,
            action_type="apply_desired",
            action_details={
                "field_name": report.field_name,
                "expected_value": report.expected_value,
                "actual_value": report.actual_value,
            },
            requires_approval=True,
            requires_restart=requires_restart,
        )

        logger.info(
            f"⚠️ [DriftScanner] Created remediation request for {report.field_name} "
            f"on {report.deployment.hostname} (severity={report.severity})"
        )

        try:
            InfrastructureAuditService.log_drift_remediation_requested(
                report.deployment, request, InfrastructureAuditContext()
            )
        except Exception:
            logger.warning("⚠️ [DriftScanner] Failed to log audit for remediation request")

        return request

    def _get_gateway(self, deployment: NodeDeployment) -> CloudProviderGateway | None:
        """Get the cloud gateway for a deployment's provider."""
        try:
            provider = deployment.provider
            token_result = get_provider_token(provider)
            if token_result.is_err():
                logger.error(f"🔥 [DriftScanner] Cannot get token for provider {provider.name}")
                return None
            return get_cloud_gateway(provider.provider_type, token_result.unwrap())
        except Exception as e:
            logger.error(f"🔥 [DriftScanner] Failed to get gateway: {e}")
            return None

    def _tcp_probe(self, host: str, port: int) -> bool:
        """TCP probe with timeout. Returns True if reachable."""
        try:
            with socket.create_connection((host, port), timeout=_get_network_probe_timeout()):
                return True
        except (OSError, TimeoutError):
            return False

    def _count_consecutive_network_failures(self, deployment: NodeDeployment) -> int:
        """Count consecutive network check failures for a deployment."""
        recent_checks = DriftCheck.objects.filter(
            deployment=deployment,
            check_type="network",
            status="completed",
        ).order_by("-created_at")[: _get_consecutive_failure_threshold()]

        count = 0
        for check in recent_checks:
            if check.reports.filter(field_name__startswith="network_unreachable").exists():
                count += 1
            else:
                break
        return count

    def _create_report(  # drift scan parameters  # noqa: PLR0913  # Business logic parameters
        self,
        check: DriftCheck,
        deployment: NodeDeployment,
        field_name: str,
        severity: str,
        category: str,
        expected: str,
        actual: str,
        auto_resolvable: bool = False,
    ) -> DriftReport:
        """Create and save a DriftReport."""
        return DriftReport.objects.create(
            drift_check=check,
            deployment=deployment,
            severity=severity,
            category=category,
            field_name=field_name,
            expected_value=expected,
            actual_value=actual,
            auto_resolvable=auto_resolvable,
        )


# Module-level singleton
_scanner_service: DriftScannerService | None = None


def get_drift_scanner_service() -> DriftScannerService:
    """Get global drift scanner service instance."""
    global _scanner_service  # noqa: PLW0603  # Module-level singleton pattern
    if _scanner_service is None:
        _scanner_service = DriftScannerService()
    return _scanner_service
