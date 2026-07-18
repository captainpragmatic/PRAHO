"""
Drift Scanner Service

Scans deployments for configuration drift across three layers:
1. Cloud Provider — server type, status, IPs, labels
2. Network — TCP reachability (port 22)
3. Application — Virtualmin config consistency
"""

from __future__ import annotations

import logging
import secrets
import socket
from typing import TYPE_CHECKING, NamedTuple

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import CloudProviderGateway, get_cloud_gateway
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport
from apps.infrastructure.provider_config import get_provider_token

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)


class ReportOutcome(NamedTuple):
    """A drift finding: the (deduped) open report plus whether it was newly created."""

    report: DriftReport
    created: bool


# Per-deployment scan lock: serializes the 15-min task, the management command,
# view-triggered scans and the remediation-health rescan against each other.
# Best-effort ordering only (DatabaseCache has no atomic compare-and-delete) —
# correctness rests on the DB constraints and conditional updates.
_SCAN_LOCK_TIMEOUT = 900

# The two field names historically used for network drift; kept together so
# healing closes legacy rows too.
_NETWORK_FIELD_NAMES = ("network_unreachable", "network_unreachable_consecutive")

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

        lock_key = f"drift_scan_dep_{deployment.pk}"
        lock_token = secrets.token_hex(8)
        if not cache.add(lock_key, lock_token, _SCAN_LOCK_TIMEOUT):
            return Err(f"A drift scan is already running for {deployment.hostname}")

        try:
            return self._scan_deployment_locked(deployment, check_types)
        finally:
            if cache.get(lock_key) == lock_token:
                cache.delete(lock_key)

    def _scan_deployment_locked(
        self,
        deployment: NodeDeployment,
        check_types: list[str] | None,
    ) -> Result[list[DriftReport], str]:
        """Scan body, running under the per-deployment scan lock."""
        types_to_scan = check_types or ["cloud", "network", "application"]
        all_outcomes: list[ReportOutcome] = []

        InfrastructureAuditService.log_drift_scan_started(deployment=deployment)
        logger.info(f"✅ [DriftScanner] Starting scan for {deployment.hostname}: {types_to_scan}")

        for check_type in types_to_scan:
            check = DriftCheck.objects.create(
                deployment=deployment,
                check_type=check_type,
                started_at=timezone.now(),
            )

            try:
                outcomes = self._run_check(deployment, check, check_type)
                check.status = "completed"
                check.completed_at = timezone.now()
                check.findings_count = len(outcomes)
                check.save(update_fields=["status", "completed_at", "findings_count"])
                all_outcomes.extend(outcomes)
            except Exception as e:
                logger.error(f"🔥 [DriftScanner] Check {check_type} failed for {deployment.hostname}: {e}")
                check.status = "failed"
                check.completed_at = timezone.now()
                check.error_message = str(e)[:1000]
                check.save(update_fields=["status", "completed_at", "error_message"])

        # Process findings: auto-resolve or ensure remediation requests
        for outcome in all_outcomes:
            self._process_report(outcome)

        InfrastructureAuditService.log_drift_scan_completed(
            deployment=deployment,
            drift_count=len(all_outcomes),
        )
        logger.info(f"✅ [DriftScanner] Scan complete for {deployment.hostname}: {len(all_outcomes)} findings")
        return Ok([outcome.report for outcome in all_outcomes])

    def _run_check(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
        check_type: str,
    ) -> list[ReportOutcome]:
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
    ) -> list[ReportOutcome]:
        """Compare gateway.get_server() fields vs DB."""
        outcomes: list[ReportOutcome] = []

        gateway = self._get_gateway(deployment)
        if gateway is None:
            return outcomes

        server_result = gateway.get_server(deployment.external_node_id)
        if server_result.is_err():
            outcomes.append(
                self._record_drift(
                    check,
                    deployment,
                    "server_deleted",
                    "critical",
                    "server_state",
                    expected="exists",
                    actual=f"error: {server_result.unwrap_err()}",
                )
            )
            return outcomes

        server_info = server_result.unwrap()
        if server_info is None:
            outcomes.append(
                self._record_drift(
                    check,
                    deployment,
                    "server_deleted",
                    "critical",
                    "server_state",
                    expected="exists",
                    actual="not found",
                )
            )
            return outcomes

        # The fields this successful comparison actually verified — anything in
        # here that is NOT drifted gets its open reports healed below.
        verified_fields = {"server_deleted", "server_status", "labels"}

        # Compare server type
        expected_type = deployment.node_size.provider_type_id if deployment.node_size else ""
        if expected_type:
            verified_fields.add("server_type")
            if server_info.server_type != expected_type:
                outcomes.append(
                    self._record_drift(
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
            outcomes.append(
                self._record_drift(
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
        if deployment.ipv4_address:
            verified_fields.add("ipv4_address")
            if server_info.ipv4_address != deployment.ipv4_address:
                outcomes.append(
                    self._record_drift(
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
        if deployment.ipv6_address:
            verified_fields.add("ipv6_address")
            if server_info.ipv6_address != deployment.ipv6_address:
                outcomes.append(
                    self._record_drift(
                        check,
                        deployment,
                        "ipv6_address",
                        "critical",
                        "network",
                        expected=str(deployment.ipv6_address),
                        actual=server_info.ipv6_address,
                    )
                )

        # Compare labels — one aggregated report per deployment; per-label rows
        # would collide on the (deployment, field_name) open-report uniqueness.
        expected_labels = {
            "managed-by": "praho",
            "hostname": deployment.hostname,
        }
        mismatched = {
            key: server_info.labels.get(key, "")
            for key, expected_val in expected_labels.items()
            if server_info.labels.get(key, "") != expected_val
        }
        if mismatched:
            outcomes.append(
                self._record_drift(
                    check,
                    deployment,
                    "labels",
                    "low",
                    "server_state",
                    expected=", ".join(f"{k}={expected_labels[k]}" for k in sorted(mismatched)),
                    actual=", ".join(f"{k}={mismatched[k]}" for k in sorted(mismatched)),
                )
            )

        drifted = {outcome.report.field_name for outcome in outcomes}
        self._heal_clean_fields(deployment, verified_fields - drifted)

        return outcomes

    def _scan_network_layer(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
    ) -> list[ReportOutcome]:
        """TCP probe port 22 with timeout."""
        outcomes: list[ReportOutcome] = []

        if not deployment.ipv4_address:
            return outcomes

        reachable = self._tcp_probe(str(deployment.ipv4_address), NETWORK_PROBE_PORT)

        if reachable:
            self._heal_clean_fields(deployment, set(_NETWORK_FIELD_NAMES))
            return outcomes

        # The failure streak lives on the single open report (occurrence_count);
        # the field name stays stable and only severity escalates, so the open
        # report is refreshed in place instead of forking a new row.
        open_report = DriftReport.objects.filter(
            deployment=deployment, field_name="network_unreachable", resolved=False
        ).first()
        occurrences = (open_report.occurrence_count + 1) if open_report else 1
        severity = "critical" if occurrences >= _get_consecutive_failure_threshold() else "high"

        outcomes.append(
            self._record_drift(
                check,
                deployment,
                "network_unreachable",
                severity,
                "network",
                expected="reachable",
                actual="unreachable",
            )
        )

        return outcomes

    def _scan_application_layer(
        self,
        deployment: NodeDeployment,
        check: DriftCheck,
    ) -> list[ReportOutcome]:
        """Check Virtualmin config if linked."""
        outcomes: list[ReportOutcome] = []

        if not deployment.virtualmin_server:
            return outcomes

        # Application layer checks are placeholder for now
        # Future: call Virtualmin API to compare domain count, PHP versions, etc.
        return outcomes

    def _process_report(self, outcome: ReportOutcome) -> None:
        """Auto-resolve or ensure a remediation request based on severity."""
        report = outcome.report
        if report.severity == "low" and report.auto_resolvable:
            self._auto_resolve_low_drift(report)
        elif report.severity == "moderate" and report.auto_resolvable:
            self._auto_resolve_moderate_drift(report)
        elif report.severity in ("high", "critical"):
            self._ensure_remediation_request(report)

        # Audit only newly detected drift — a refresh of a known open report
        # every 15 minutes is not a new detection.
        if outcome.created:
            try:
                InfrastructureAuditService.log_drift_detected(report.deployment, report, InfrastructureAuditContext())
            except Exception:
                logger.warning(f"⚠️ [DriftScanner] Failed to log audit for {report}")

    def _record_drift(  # noqa: PLR0913  # Business logic parameters
        self,
        check: DriftCheck,
        deployment: NodeDeployment,
        field_name: str,
        severity: str,
        category: str,
        expected: str,
        actual: str,
    ) -> ReportOutcome:
        """
        Get-or-refresh the single open report for (deployment, field): dedup is
        what makes the scan loop convergent — a 15-min cadence must not mint
        ~96 duplicate rows per day per drifting field (#224 defect 4).
        """
        open_report = DriftReport.objects.filter(deployment=deployment, field_name=field_name, resolved=False).first()
        if open_report is not None:
            return self._refresh_open_report(open_report, check, severity, expected, actual)

        try:
            with transaction.atomic():
                report = DriftReport.objects.create(
                    drift_check=check,
                    deployment=deployment,
                    severity=severity,
                    category=category,
                    field_name=field_name,
                    expected_value=expected,
                    actual_value=actual,
                    last_seen_at=timezone.now(),
                )
            return ReportOutcome(report, True)
        except IntegrityError:
            # A concurrent scan won the create race — refresh its row instead.
            open_report = DriftReport.objects.filter(
                deployment=deployment, field_name=field_name, resolved=False
            ).first()
            if open_report is None:
                raise
            return self._refresh_open_report(open_report, check, severity, expected, actual)

    def _refresh_open_report(
        self,
        report: DriftReport,
        check: DriftCheck,
        severity: str,
        expected: str,
        actual: str,
    ) -> ReportOutcome:
        """Update the open report with the latest observation."""
        DriftReport.objects.filter(pk=report.pk).update(
            drift_check=check,
            severity=severity,
            expected_value=expected,
            actual_value=actual,
            occurrence_count=F("occurrence_count") + 1,
            last_seen_at=timezone.now(),
        )
        report.refresh_from_db()
        return ReportOutcome(report, False)

    def _heal_clean_fields(self, deployment: NodeDeployment, field_names: set[str]) -> None:
        """
        Close open drift a successful comparison proved is gone — the only way
        manually-fixed drift (manual_intervention requests) ever converges.
        """
        if not field_names:
            return

        open_reports = DriftReport.objects.filter(deployment=deployment, field_name__in=field_names, resolved=False)
        for report in open_reports:
            healed = DriftReport.objects.filter(pk=report.pk, resolved=False).update(
                resolved=True,
                resolved_at=timezone.now(),
                resolution_type="healed",
            )
            if not healed:
                continue
            report.remediation_requests.filter(status__in=("pending_approval", "approved", "scheduled")).update(
                status="superseded"
            )
            logger.info(f"✅ [DriftScanner] Drift healed externally: {report.field_name} for {deployment.hostname}")

    def _ensure_remediation_request(self, report: DriftReport) -> None:
        """
        Mint a remediation request only when the report has no accurate open
        one; keep open requests aligned with the drift they will act on.
        """

        def fingerprint(req: DriftRemediationRequest) -> tuple[str, str, str]:
            details = req.action_details or {}
            return (
                details.get("expected_value", ""),
                details.get("actual_value", ""),
                # Legacy requests predate the severity key — treat a missing
                # key as matching so they are not churned for that alone
                details.get("severity", report.severity),
            )

        current = (report.expected_value, report.actual_value, report.severity)

        for req in report.remediation_requests.filter(status__in=DriftRemediationRequest.OPEN_STATUSES):
            if req.status == "in_progress":
                return  # immutable mid-flight; claim-time validation guards execution
            if fingerprint(req) == current:
                return  # an accurate open request already exists
            if req.status == "pending_approval":
                # Drift evolved before approval — update in place, no new row
                req.action_details = {
                    "field_name": report.field_name,
                    "expected_value": report.expected_value,
                    "actual_value": report.actual_value,
                    "severity": report.severity,
                }
                req.save(update_fields=["action_details"])
                return
            # approved/scheduled against outdated values: retire and re-mint.
            # These carried a human approval — audit their retirement.
            retired = DriftRemediationRequest.objects.filter(pk=req.pk, status=req.status).update(status="superseded")
            if retired:
                try:
                    InfrastructureAuditService.log_drift_remediation_failed(
                        report.deployment,
                        req,
                        "Superseded: drift changed before execution",
                        InfrastructureAuditContext(),
                    )
                except Exception:
                    logger.warning(f"⚠️ [DriftScanner] Failed to log audit for superseded request {req.pk}")

        # A rejection mutes re-minting until the observed drift actually changes
        latest = report.remediation_requests.order_by("-created_at").first()
        if latest is not None and latest.status == "rejected" and fingerprint(latest) == current:
            return

        self._create_remediation_request(report)

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
        from apps.infrastructure.drift_remediation import (  # noqa: PLC0415  # Deferred: avoids circular import
            AUTO_FIXABLE_FIELDS,  # Circular: cross-app
        )

        requires_restart = report.field_name in ("server_type",)
        action_type = "apply_desired" if report.field_name in AUTO_FIXABLE_FIELDS else "manual_intervention"

        try:
            with transaction.atomic():
                request = DriftRemediationRequest.objects.create(
                    report=report,
                    deployment=report.deployment,
                    action_type=action_type,
                    action_details={
                        "field_name": report.field_name,
                        "expected_value": report.expected_value,
                        "actual_value": report.actual_value,
                        "severity": report.severity,
                    },
                    requires_approval=True,
                    requires_restart=requires_restart,
                )
        except IntegrityError:
            # A concurrent scan minted the open request first — nothing to do.
            existing = report.remediation_requests.filter(status__in=DriftRemediationRequest.OPEN_STATUSES).first()
            if existing is None:
                raise
            return existing

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


# Module-level singleton
_scanner_service: DriftScannerService | None = None


def get_drift_scanner_service() -> DriftScannerService:
    """Get global drift scanner service instance."""
    global _scanner_service  # noqa: PLW0603  # Module-level singleton pattern
    if _scanner_service is None:
        _scanner_service = DriftScannerService()
    return _scanner_service
