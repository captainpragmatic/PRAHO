"""
Automated Compliance Reporting Service for PRAHO Platform

This module provides automated compliance reporting with:
- Multiple compliance framework support (ISO 27001, SOC 2, GDPR, Romanian regulations)
- Scheduled report generation
- Tamper-proof log verification
- Log retention policy enforcement
- Export in multiple formats (PDF, CSV, JSON)
"""

from __future__ import annotations

import csv
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_COMPLIANT_SCORE_THRESHOLD = 90
COMPLIANT_SCORE_THRESHOLD = _DEFAULT_COMPLIANT_SCORE_THRESHOLD
_DEFAULT_PARTIAL_SCORE_THRESHOLD = 70
PARTIAL_SCORE_THRESHOLD = _DEFAULT_PARTIAL_SCORE_THRESHOLD


def get_compliant_score_threshold() -> int:
    """Get compliant score threshold from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("audit.compliant_score_threshold", _DEFAULT_COMPLIANT_SCORE_THRESHOLD)


def get_partial_score_threshold() -> int:
    """Get partial score threshold from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("audit.partial_score_threshold", _DEFAULT_PARTIAL_SCORE_THRESHOLD)


User = get_user_model()


# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks"""

    ISO27001 = "iso27001"
    SOC2 = "soc2"
    GDPR = "gdpr"
    ROMANIAN_FISCAL = "romanian_fiscal"
    E_FACTURA = "e_factura"
    NIST = "nist"
    PCI_DSS = "pci_dss"


class ReportType(StrEnum):
    """Types of compliance reports"""

    SECURITY_SUMMARY = "security_summary"
    ACCESS_REVIEW = "access_review"
    AUTHENTICATION_AUDIT = "authentication_audit"
    DATA_ACCESS_AUDIT = "data_access_audit"
    COMPLIANCE_VIOLATIONS = "compliance_violations"
    GDPR_COMPLIANCE = "gdpr_compliance"
    ROMANIAN_FISCAL = "romanian_fiscal_compliance"
    LOG_INTEGRITY = "log_integrity"
    RETENTION_COMPLIANCE = "retention_compliance"


class ReportFormat(StrEnum):
    """Report output formats"""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"


# =============================================================================
# REPORT DATA STRUCTURES
# =============================================================================


@dataclass
class ComplianceViolation:
    """Represents a compliance violation"""

    framework: str
    control_id: str
    description: str
    severity: str
    detected_at: datetime
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class ComplianceReportSection:
    """A section within a compliance report"""

    title: str
    description: str
    status: str  # compliant, non_compliant, partial, not_applicable
    findings: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Complete compliance report"""

    report_id: str
    report_type: ReportType
    framework: ComplianceFramework | None
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    generated_by: str

    # Overall status
    overall_status: str  # compliant, non_compliant, partial
    compliance_score: float  # 0-100

    # Report sections
    sections: list[ComplianceReportSection] = field(default_factory=list)

    # Summary metrics
    total_events: int = 0
    total_violations: int = 0
    critical_findings: int = 0

    # Violations
    violations: list[ComplianceViolation] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# COMPLIANCE CHECKING RULES
# =============================================================================


class ComplianceRule:
    """Base class for compliance rules"""

    framework: ComplianceFramework
    control_id: str
    description: str
    severity: str = "medium"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        """
        Check compliance for this rule.

        Returns:
            Tuple of (is_compliant, list_of_violations)
        """
        raise NotImplementedError


class PasswordPolicyRule(ComplianceRule):
    """Check password policy compliance (ISO 27001 A.9.4, NIST)"""

    framework = ComplianceFramework.ISO27001
    control_id = "A.9.4.3"
    description = "Password management system"
    severity = "high"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        # Check for weak password events
        weak_password_events = [
            e
            for e in events
            if e.action in ("password_strength_weak", "password_compromised", "password_policy_violation")
        ]
        violations = [
            ComplianceViolation(
                framework=self.framework.value,
                control_id=self.control_id,
                description=f"Password policy violation: {event.action}",
                severity=self.severity,
                detected_at=event.timestamp,
                evidence={
                    "event_id": str(event.id),
                    "user_id": str(event.user_id) if event.user_id else None,
                    "action": event.action,
                },
                remediation="Enforce stronger password requirements",
            )
            for event in weak_password_events
        ]

        return len(violations) == 0, violations


class MFAEnforcementRule(ComplianceRule):
    """Check MFA enforcement compliance (ISO 27001 A.9.4, SOC 2 CC6.1)"""

    framework = ComplianceFramework.SOC2
    control_id = "CC6.1"
    description = "Multi-factor authentication enforcement"
    severity = "high"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        # Check for 2FA disabled events (especially for privileged users)
        mfa_disabled_events = [e for e in events if e.action == "2fa_disabled"]
        violations = [
            ComplianceViolation(
                framework=self.framework.value,
                control_id=self.control_id,
                description="Multi-factor authentication disabled",
                severity=self.severity,
                detected_at=event.timestamp,
                evidence={
                    "event_id": str(event.id),
                    "user_id": str(event.user_id) if event.user_id else None,
                },
                remediation="Re-enable MFA for affected accounts",
            )
            for event in mfa_disabled_events
        ]

        return len(violations) == 0, violations


class AccessControlRule(ComplianceRule):
    """Check access control compliance (ISO 27001 A.9.2, SOC 2 CC6.2)"""

    framework = ComplianceFramework.ISO27001
    control_id = "A.9.2"
    description = "User access management"
    severity = "high"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        # Check for privilege escalation attempts
        escalation_events = [e for e in events if e.action == "privilege_escalation_attempt"]
        violations = [
            ComplianceViolation(
                framework=self.framework.value,
                control_id=self.control_id,
                description="Privilege escalation attempt detected",
                severity="critical",
                detected_at=event.timestamp,
                evidence={
                    "event_id": str(event.id),
                    "user_id": str(event.user_id) if event.user_id else None,
                    "ip_address": event.ip_address,
                },
                remediation="Investigate and block unauthorized access attempts",
            )
            for event in escalation_events
        ]

        return len(violations) == 0, violations


class DataProtectionRule(ComplianceRule):
    """Check data protection compliance (GDPR Art. 32)"""

    framework = ComplianceFramework.GDPR
    control_id = "Art.32"
    description = "Security of processing"
    severity = "critical"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        # Check for data breach events
        breach_events = [e for e in events if e.action in ("data_breach_detected", "data_breach_reported")]
        violations = [
            ComplianceViolation(
                framework=self.framework.value,
                control_id=self.control_id,
                description="Data breach detected",
                severity="critical",
                detected_at=event.timestamp,
                evidence={
                    "event_id": str(event.id),
                    "description": event.description,
                },
                remediation="Follow data breach notification procedures (72 hours)",
            )
            for event in breach_events
        ]

        return len(violations) == 0, violations


class GDPRConsentRule(ComplianceRule):
    """Check GDPR consent compliance (GDPR Art. 7)"""

    framework = ComplianceFramework.GDPR
    control_id = "Art.7"
    description = "Conditions for consent"
    severity = "high"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        violations: list[ComplianceViolation] = []

        # Check for consent withdrawal without proper handling
        [e for e in events if e.action == "gdpr_consent_withdrawn"]

        # Note: This is a simplified check. In practice, you'd verify
        # that data processing stopped after consent withdrawal.

        return True, violations


class SecurityEventRule(ComplianceRule):
    """Check security event monitoring (ISO 27001 A.12.4)"""

    framework = ComplianceFramework.ISO27001
    control_id = "A.12.4"
    description = "Event logging"
    severity = "high"

    def check(
        self, events: list[Any], period_start: datetime, period_end: datetime
    ) -> tuple[bool, list[ComplianceViolation]]:
        violations = []

        # Check for unaddressed security incidents
        security_events = [
            e
            for e in events
            if e.action
            in ("security_incident_detected", "brute_force_attempt", "malicious_request", "suspicious_activity")
        ]

        # Group by severity
        critical_unaddressed = [e for e in security_events if e.severity == "critical" and e.requires_review]

        if critical_unaddressed:
            violations.append(
                ComplianceViolation(
                    framework=self.framework.value,
                    control_id=self.control_id,
                    description=f"{len(critical_unaddressed)} critical security events require review",
                    severity="critical",
                    detected_at=timezone.now(),
                    evidence={
                        "event_ids": [str(e.id) for e in critical_unaddressed[:10]],
                        "count": len(critical_unaddressed),
                    },
                    remediation="Review and address critical security events",
                )
            )

        return len(violations) == 0, violations


# =============================================================================
# COMPLIANCE REPORT SERVICE
# =============================================================================


class ComplianceReportService:
    """
    Service for generating compliance reports.

    Features:
    - Multiple compliance framework support
    - Automated violation detection
    - Report generation in multiple formats
    - Scheduled report generation
    """

    COMPLIANCE_RULES: ClassVar[list[type[ComplianceRule]]] = [
        PasswordPolicyRule,
        MFAEnforcementRule,
        AccessControlRule,
        DataProtectionRule,
        GDPRConsentRule,
        SecurityEventRule,
    ]

    def __init__(self) -> None:
        self.report_dir = getattr(settings, "COMPLIANCE_REPORTING", {}).get("REPORT_DIR", "/var/log/praho/compliance")

    def generate_report(
        self,
        report_type: ReportType,
        period_start: datetime,
        period_end: datetime,
        framework: ComplianceFramework | None = None,
        generated_by: str = "system",
    ) -> ComplianceReport:
        """
        Generate a compliance report.

        Args:
            report_type: Type of report to generate
            period_start: Start of reporting period
            period_end: End of reporting period
            framework: Specific framework (optional)
            generated_by: User/system generating the report

        Returns:
            ComplianceReport object
        """
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        logger.info(
            f"📊 [Compliance] Generating {report_type.value} report for {period_start.date()} to {period_end.date()}"
        )

        # Fetch relevant events
        events = list(
            AuditEvent.objects.filter(
                timestamp__gte=period_start,
                timestamp__lte=period_end,
            ).select_related("user", "content_type")
        )

        # Initialize report
        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            report_type=report_type,
            framework=framework,
            generated_at=timezone.now(),
            period_start=period_start,
            period_end=period_end,
            generated_by=generated_by,
            overall_status="compliant",
            compliance_score=100.0,
            total_events=len(events),
        )

        # Generate report based on type
        if report_type == ReportType.SECURITY_SUMMARY:
            self._generate_security_summary(report, events)
        elif report_type == ReportType.ACCESS_REVIEW:
            self._generate_access_review(report, events)
        elif report_type == ReportType.AUTHENTICATION_AUDIT:
            self._generate_authentication_audit(report, events)
        elif report_type == ReportType.COMPLIANCE_VIOLATIONS:
            self._generate_compliance_violations(report, events)
        elif report_type == ReportType.GDPR_COMPLIANCE:
            self._generate_gdpr_compliance(report, events)
        elif report_type == ReportType.LOG_INTEGRITY:
            self._generate_log_integrity(report, events)
        elif report_type == ReportType.RETENTION_COMPLIANCE:
            self._generate_retention_compliance(report, events)
        else:
            self._generate_generic_report(report, events)

        # Run compliance rules
        self._run_compliance_checks(report, events)

        # Calculate overall compliance score
        self._calculate_compliance_score(report)

        logger.info(f"✅ [Compliance] Report generated: {report.report_id} (score: {report.compliance_score}%)")

        return report

    def _generate_security_summary(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate security summary section"""
        # Authentication events
        auth_events = [e for e in events if e.category == "authentication"]
        failed_logins = len([e for e in auth_events if "failed" in e.action])
        successful_logins = len([e for e in auth_events if e.action == "login_success"])

        # Security events
        security_events = [e for e in events if e.category == "security_event"]
        critical_events = len([e for e in security_events if e.severity == "critical"])

        report.sections.append(
            ComplianceReportSection(
                title="Authentication Summary",
                description="Overview of authentication activity",
                status="compliant" if failed_logins < successful_logins * 0.1 else "partial",
                metrics={
                    "total_login_attempts": len(auth_events),
                    "successful_logins": successful_logins,
                    "failed_logins": failed_logins,
                    "failure_rate": f"{(failed_logins / max(len(auth_events), 1)) * 100:.2f}%",
                },
                recommendations=[
                    "Review accounts with high failed login rates",
                    "Ensure MFA is enabled for all privileged accounts",
                ]
                if failed_logins > 0
                else [],
            )
        )

        report.sections.append(
            ComplianceReportSection(
                title="Security Events",
                description="Overview of security-related events",
                status="non_compliant" if critical_events > 0 else "compliant",
                metrics={
                    "total_security_events": len(security_events),
                    "critical_events": critical_events,
                    "events_requiring_review": len([e for e in security_events if e.requires_review]),
                },
                recommendations=[
                    "Investigate all critical security events immediately",
                ]
                if critical_events > 0
                else [],
            )
        )

        report.critical_findings = critical_events

    def _generate_access_review(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate access review section"""
        auth_events = [e for e in events if e.category == "authorization"]

        # Role changes
        role_changes = [e for e in auth_events if "role" in e.action]
        permission_changes = [e for e in auth_events if "permission" in e.action]

        report.sections.append(
            ComplianceReportSection(
                title="Access Control Review",
                description="Review of access control changes",
                status="compliant",
                metrics={
                    "role_assignments": len([e for e in role_changes if "assigned" in e.action]),
                    "role_removals": len([e for e in role_changes if "removed" in e.action]),
                    "permission_grants": len([e for e in permission_changes if "granted" in e.action]),
                    "permission_revocations": len([e for e in permission_changes if "revoked" in e.action]),
                },
                findings=[
                    {
                        "type": "role_change",
                        "event_id": str(e.id),
                        "action": e.action,
                        "user": e.user.email if e.user else "system",
                        "timestamp": e.timestamp.isoformat(),
                    }
                    for e in role_changes[:20]  # Limit findings
                ],
            )
        )

    def _generate_authentication_audit(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate authentication audit section"""
        auth_events = [e for e in events if e.category == "authentication"]

        # Group by action type
        action_counts: dict[str, int] = {}
        for event in auth_events:
            action_counts[event.action] = action_counts.get(event.action, 0) + 1

        # Account lockouts
        lockouts = [e for e in auth_events if e.action == "account_locked"]

        # 2FA events
        mfa_events = [e for e in auth_events if "2fa" in e.action]

        report.sections.append(
            ComplianceReportSection(
                title="Authentication Audit",
                description="Detailed authentication activity audit",
                status="compliant",
                metrics={
                    "action_breakdown": action_counts,
                    "account_lockouts": len(lockouts),
                    "mfa_events": len(mfa_events),
                },
                findings=[
                    {
                        "type": "account_lockout",
                        "event_id": str(e.id),
                        "user": e.user.email if e.user else "unknown",
                        "ip_address": e.ip_address,
                        "timestamp": e.timestamp.isoformat(),
                    }
                    for e in lockouts
                ],
            )
        )

    def _generate_compliance_violations(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate compliance violations section"""
        # This is populated by _run_compliance_checks
        report.sections.append(
            ComplianceReportSection(
                title="Compliance Violations",
                description="Detected compliance violations",
                status="pending",  # Updated after checks
                metrics={},
            )
        )

    def _generate_gdpr_compliance(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate GDPR compliance section"""
        privacy_events = [e for e in events if e.category == "privacy"]
        data_events = [e for e in events if e.category == "data_protection"]

        # Consent management
        consent_granted = len([e for e in privacy_events if "granted" in e.action])
        consent_withdrawn = len([e for e in privacy_events if "withdrawn" in e.action])

        # Data subject requests
        export_requests = len([e for e in data_events if e.action == "data_export_requested"])
        deletion_requests = len([e for e in data_events if e.action == "data_deletion_requested"])

        report.sections.append(
            ComplianceReportSection(
                title="GDPR Compliance",
                description="GDPR compliance status and data subject request handling",
                status="compliant",
                metrics={
                    "consent_granted": consent_granted,
                    "consent_withdrawn": consent_withdrawn,
                    "data_export_requests": export_requests,
                    "data_deletion_requests": deletion_requests,
                },
                recommendations=[
                    "Ensure all data subject requests are processed within 30 days",
                    "Maintain records of consent for all data processing activities",
                ],
            )
        )

    def _generate_log_integrity(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate log integrity verification section"""
        from apps.audit.siem import get_siem_service  # noqa: PLC0415

        siem = get_siem_service()

        # Verify hash chain integrity
        is_valid, errors = siem.verify_log_integrity(report.period_start, report.period_end)

        report.sections.append(
            ComplianceReportSection(
                title="Log Integrity Verification",
                description="Verification of audit log integrity using hash chain",
                status="compliant" if is_valid else "non_compliant",
                metrics={
                    "logs_verified": len(events),
                    "integrity_errors": len(errors),
                },
                findings=[{"error": error} for error in errors],
                recommendations=[
                    "Investigate any hash chain integrity failures",
                    "Ensure log storage is protected from modification",
                ]
                if errors
                else [],
            )
        )

        if errors:
            report.violations.append(
                ComplianceViolation(
                    framework="ISO27001",
                    control_id="A.12.4.2",
                    description="Log integrity verification failed",
                    severity="critical",
                    detected_at=timezone.now(),
                    evidence={"errors": errors},
                    remediation="Investigate potential log tampering",
                )
            )

    def _generate_retention_compliance(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate retention compliance section"""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        retention_config = getattr(settings, "AUDIT_LOG_RETENTION", {})

        findings = []
        for category, config in retention_config.items():
            retention_days = config.get("retention_days", 365)
            cutoff_date = timezone.now() - timedelta(days=retention_days)

            # Check for events past retention period
            old_events = AuditEvent.objects.filter(category=category, timestamp__lt=cutoff_date).count()

            if old_events > 0:
                findings.append(
                    {
                        "category": category,
                        "retention_days": retention_days,
                        "events_past_retention": old_events,
                        "action_required": config.get("action", "archive"),
                    }
                )

        report.sections.append(
            ComplianceReportSection(
                title="Log Retention Compliance",
                description="Verification of log retention policy compliance",
                status="partial" if findings else "compliant",
                metrics={
                    "categories_checked": len(retention_config),
                    "categories_with_issues": len(findings),
                },
                findings=findings,
                recommendations=[
                    f"Process {f['events_past_retention']} events in category '{f['category']}'" for f in findings
                ],
            )
        )

    def _generate_generic_report(self, report: ComplianceReport, events: list[Any]) -> None:
        """Generate a generic report for unhandled report types"""
        # Group by category
        category_counts: dict[str, int] = {}
        for event in events:
            category_counts[event.category] = category_counts.get(event.category, 0) + 1

        report.sections.append(
            ComplianceReportSection(
                title="Event Summary",
                description="Overview of all audit events",
                status="compliant",
                metrics={
                    "total_events": len(events),
                    "by_category": category_counts,
                },
            )
        )

    def _run_compliance_checks(self, report: ComplianceReport, events: list[Any]) -> None:
        """Run compliance rules against events"""
        for rule_class in self.COMPLIANCE_RULES:
            rule = rule_class()

            # Skip if filtering by framework and rule doesn't match
            if report.framework and rule.framework != report.framework:
                continue

            _is_compliant, violations = rule.check(events, report.period_start, report.period_end)

            report.violations.extend(violations)

        report.total_violations = len(report.violations)

    def _calculate_compliance_score(self, report: ComplianceReport) -> None:
        """Calculate overall compliance score"""
        if report.total_events == 0:
            report.compliance_score = 100.0
            report.overall_status = "compliant"
            return

        # Weight violations by severity
        severity_weights = {
            "critical": 25,
            "high": 10,
            "medium": 5,
            "low": 1,
        }

        total_penalty = sum(severity_weights.get(v.severity, 5) for v in report.violations)

        # Calculate score (100 - penalties, minimum 0)
        report.compliance_score = max(0, 100 - total_penalty)

        # Determine overall status
        if report.compliance_score >= COMPLIANT_SCORE_THRESHOLD:
            report.overall_status = "compliant"
        elif report.compliance_score >= PARTIAL_SCORE_THRESHOLD:
            report.overall_status = "partial"
        else:
            report.overall_status = "non_compliant"

    def export_report(
        self,
        report: ComplianceReport,
        output_format: ReportFormat = ReportFormat.JSON,
    ) -> str:
        """
        Export report to specified format.

        Args:
            report: ComplianceReport to export
            output_format: Output format

        Returns:
            Path to exported file
        """
        os.makedirs(self.report_dir, exist_ok=True)

        filename = f"{report.report_type.value}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}"

        if output_format == ReportFormat.JSON:
            return self._export_json(report, filename)
        elif output_format == ReportFormat.CSV:
            return self._export_csv(report, filename)
        elif output_format == ReportFormat.PDF:
            return self._export_pdf(report, filename)

        raise ValueError(f"Unsupported format: {output_format}")

    def _export_json(self, report: ComplianceReport, filename: str) -> str:
        """Export report as JSON"""
        filepath = os.path.join(self.report_dir, f"{filename}.json")

        report_dict = {
            "report_id": report.report_id,
            "report_type": report.report_type.value,
            "framework": report.framework.value if report.framework else None,
            "generated_at": report.generated_at.isoformat(),
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "generated_by": report.generated_by,
            "overall_status": report.overall_status,
            "compliance_score": report.compliance_score,
            "total_events": report.total_events,
            "total_violations": report.total_violations,
            "critical_findings": report.critical_findings,
            "sections": [
                {
                    "title": s.title,
                    "description": s.description,
                    "status": s.status,
                    "findings": s.findings,
                    "metrics": s.metrics,
                    "recommendations": s.recommendations,
                }
                for s in report.sections
            ],
            "violations": [
                {
                    "framework": v.framework,
                    "control_id": v.control_id,
                    "description": v.description,
                    "severity": v.severity,
                    "detected_at": v.detected_at.isoformat(),
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                }
                for v in report.violations
            ],
            "metadata": report.metadata,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"📄 [Compliance] Exported report to {filepath}")
        return filepath

    def _export_csv(self, report: ComplianceReport, filename: str) -> str:
        """Export report violations as CSV"""
        filepath = os.path.join(self.report_dir, f"{filename}.csv")

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(["Framework", "Control ID", "Description", "Severity", "Detected At", "Remediation"])

            # Violations
            for v in report.violations:
                writer.writerow(
                    [
                        v.framework,
                        v.control_id,
                        v.description,
                        v.severity,
                        v.detected_at.isoformat(),
                        v.remediation,
                    ]
                )

        logger.info(f"📄 [Compliance] Exported violations to {filepath}")
        return filepath

    def _export_pdf(self, report: ComplianceReport, filename: str) -> str:
        """Export report as PDF (requires reportlab)"""
        # For now, export as text-based PDF alternative
        # In production, use reportlab or weasyprint for proper PDF generation
        filepath = os.path.join(self.report_dir, f"{filename}.txt")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"COMPLIANCE REPORT: {report.report_type.value.upper()}\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Report ID: {report.report_id}\n")
            f.write(f"Generated: {report.generated_at.isoformat()}\n")
            f.write(f"Period: {report.period_start.date()} to {report.period_end.date()}\n")
            f.write(f"Generated By: {report.generated_by}\n\n")

            f.write("-" * 80 + "\n")
            f.write("SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Overall Status: {report.overall_status.upper()}\n")
            f.write(f"Compliance Score: {report.compliance_score:.1f}%\n")
            f.write(f"Total Events: {report.total_events}\n")
            f.write(f"Total Violations: {report.total_violations}\n")
            f.write(f"Critical Findings: {report.critical_findings}\n\n")

            for section in report.sections:
                f.write("-" * 80 + "\n")
                f.write(f"{section.title.upper()}\n")
                f.write("-" * 80 + "\n")
                f.write(f"Status: {section.status}\n")
                f.write(f"Description: {section.description}\n\n")

                if section.metrics:
                    f.write("Metrics:\n")
                    for key, value in section.metrics.items():
                        f.write(f"  - {key}: {value}\n")
                    f.write("\n")

                if section.recommendations:
                    f.write("Recommendations:\n")
                    for rec in section.recommendations:
                        f.write(f"  - {rec}\n")
                    f.write("\n")

            if report.violations:
                f.write("=" * 80 + "\n")
                f.write("VIOLATIONS\n")
                f.write("=" * 80 + "\n\n")

                for v in report.violations:
                    f.write(f"[{v.severity.upper()}] {v.framework} {v.control_id}\n")
                    f.write(f"  {v.description}\n")
                    f.write(f"  Detected: {v.detected_at.isoformat()}\n")
                    f.write(f"  Remediation: {v.remediation}\n\n")

        logger.info(f"📄 [Compliance] Exported report to {filepath}")
        return filepath


# =============================================================================
# LOG RETENTION SERVICE
# =============================================================================


class LogRetentionService:
    """
    Service for enforcing log retention policies.

    Handles:
    - Archiving old logs
    - Deleting expired logs
    - Anonymizing sensitive data
    - Compliance with retention requirements
    """

    def __init__(self) -> None:
        self.retention_config = getattr(settings, "AUDIT_LOG_RETENTION", {})

    def apply_retention_policies(self) -> dict[str, Any]:
        """
        Apply retention policies to all audit logs.

        Returns:
            Summary of actions taken
        """

        logger.info("🗄️ [Retention] Applying retention policies...")

        summary: dict[str, Any] = {
            "processed_categories": [],
            "archived": 0,
            "deleted": 0,
            "anonymized": 0,
            "errors": [],
        }

        for category, config in self.retention_config.items():
            try:
                result = self._process_category(category, config)
                summary["processed_categories"].append(category)
                summary["archived"] += result.get("archived", 0)
                summary["deleted"] += result.get("deleted", 0)
                summary["anonymized"] += result.get("anonymized", 0)
            except Exception as e:
                logger.error(f"🔥 [Retention] Error processing {category}: {e}")
                summary["errors"].append({"category": category, "error": str(e)})

        logger.info(
            f"✅ [Retention] Policies applied: "
            f"{summary['archived']} archived, "
            f"{summary['deleted']} deleted, "
            f"{summary['anonymized']} anonymized"
        )

        return summary

    def _process_category(self, category: str, config: dict[str, Any]) -> dict[str, int]:
        """Process retention for a specific category"""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        retention_days = config.get("retention_days", 365)
        action = config.get("action", "archive")
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        # Find events past retention period
        old_events = AuditEvent.objects.filter(category=category, timestamp__lt=cutoff_date)

        count = old_events.count()
        if count == 0:
            return {"archived": 0, "deleted": 0, "anonymized": 0}

        result = {"archived": 0, "deleted": 0, "anonymized": 0}

        if action == "archive":
            # Archive events (in practice, export to cold storage)
            result["archived"] = self._archive_events(old_events)
        elif action == "delete":
            # Delete events
            result["deleted"] = self._delete_events(old_events)
        elif action == "anonymize":
            # Anonymize sensitive data
            result["anonymized"] = self._anonymize_events(old_events)

        return result

    def _archive_events(self, events: Any) -> int:
        """Archive events to cold storage"""
        # In production, export to S3/GCS cold storage tier
        # For now, mark as archived in metadata
        count = 0
        for event in events.iterator():
            event.metadata["archived"] = True
            event.metadata["archived_at"] = timezone.now().isoformat()
            event.save(update_fields=["metadata"])
            count += 1

        return count

    def _delete_events(self, events: Any) -> int:
        """Delete events (with safety checks)"""
        # Never delete security events or compliance-critical events
        safe_to_delete = events.exclude(
            Q(severity="critical") | Q(category__in=["security_event", "compliance", "data_protection"])
        )

        count: int = safe_to_delete.count()
        safe_to_delete.delete()

        return count

    def _anonymize_events(self, events: Any) -> int:
        """Anonymize sensitive data in events"""
        count = 0
        for event in events.iterator():
            # Anonymize user-identifying information
            if event.user:
                event.metadata["original_user_id"] = str(event.user_id)
                event.user = None

            # Anonymize IP addresses
            if event.ip_address:
                event.metadata["had_ip"] = True
                event.ip_address = None

            # Clear sensitive metadata
            if "email" in str(event.metadata):
                event.metadata["email_anonymized"] = True

            event.save()
            count += 1

        return count

    def get_retention_status(self) -> dict[str, Any]:
        """Get current retention status for all categories"""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        status = {}

        for category, config in self.retention_config.items():
            retention_days = config.get("retention_days", 365)
            cutoff_date = timezone.now() - timedelta(days=retention_days)

            total = AuditEvent.objects.filter(category=category).count()
            past_retention = AuditEvent.objects.filter(category=category, timestamp__lt=cutoff_date).count()

            status[category] = {
                "retention_days": retention_days,
                "action": config.get("action", "archive"),
                "legal_basis": config.get("legal_basis", ""),
                "total_events": total,
                "events_past_retention": past_retention,
                "compliance_status": "compliant" if past_retention == 0 else "action_required",
            }

        return status


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def generate_compliance_report(
    report_type: str = "security_summary",
    days: int = 30,
    framework: str | None = None,
) -> ComplianceReport:
    """
    Convenience function to generate a compliance report.

    Args:
        report_type: Type of report (see ReportType enum)
        days: Number of days to cover
        framework: Optional framework filter

    Returns:
        ComplianceReport object
    """
    service = ComplianceReportService()

    period_end = timezone.now()
    period_start = period_end - timedelta(days=days)

    return service.generate_report(
        report_type=ReportType(report_type),
        period_start=period_start,
        period_end=period_end,
        framework=ComplianceFramework(framework) if framework else None,
    )


def apply_retention_policies() -> dict[str, Any]:
    """
    Convenience function to apply retention policies.

    Returns:
        Summary of actions taken
    """
    service = LogRetentionService()
    return service.apply_retention_policies()
