"""
Comprehensive tests for apps.audit.compliance module.

Covers:
- All compliance rule classes (PasswordPolicyRule, MFAEnforcementRule, etc.)
- ComplianceReportService (generate_report, export, all report types)
- Convenience functions (generate_compliance_report)
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.compliance import (
    AccessControlRule,
    ComplianceFramework,
    ComplianceReport,
    ComplianceReportSection,
    ComplianceReportService,
    ComplianceViolation,
    DataProtectionRule,
    GDPRConsentRule,
    MFAEnforcementRule,
    PasswordPolicyRule,
    ReportFormat,
    ReportType,
    SecurityEventRule,
    generate_compliance_report,
)
from apps.audit.models import AuditEvent, audit_mutation_allowed
from apps.common.types import Err, Ok

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(**kwargs: Any) -> SimpleNamespace:
    """Create a lightweight mock event for rule-level tests."""
    defaults: dict[str, Any] = {
        "action": "login_success",
        "timestamp": timezone.now(),
        "id": uuid.uuid4(),
        "user_id": uuid.uuid4(),
        "severity": "info",
        "requires_review": False,
        "category": "authentication",
        "description": "Test event",
        "ip_address": "1.2.3.4",
        "user": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def make_period() -> tuple[Any, Any]:
    now = timezone.now()
    return now - timedelta(days=30), now


_DUMMY_OBJECT_ID = "00000000-0000-0000-0000-000000000001"


def get_user_content_type() -> ContentType:
    """Return a ContentType for the User model, used as a required FK on AuditEvent."""
    UserModel = get_user_model()  # noqa: N806
    return ContentType.objects.get_for_model(UserModel)


def make_report(**kwargs: Any) -> ComplianceReport:
    start, end = make_period()
    defaults: dict[str, Any] = {
        "report_id": str(uuid.uuid4()),
        "report_type": ReportType.SECURITY_SUMMARY,
        "framework": None,
        "generated_at": timezone.now(),
        "period_start": start,
        "period_end": end,
        "generated_by": "test",
        "overall_status": "compliant",
        "compliance_score": 100.0,
        "total_events": 0,
    }
    defaults.update(kwargs)
    return ComplianceReport(**defaults)


# ---------------------------------------------------------------------------
# Dataclass smoke tests
# ---------------------------------------------------------------------------


class TestDataclasses(TestCase):
    def test_compliance_violation_defaults(self) -> None:
        v = ComplianceViolation(
            framework="iso27001",
            control_id="A.9.4.3",
            description="desc",
            severity="high",
            detected_at=timezone.now(),
        )
        self.assertEqual(v.evidence, {})
        self.assertEqual(v.remediation, "")

    def test_compliance_report_section_defaults(self) -> None:
        s = ComplianceReportSection(title="T", description="D", status="compliant")
        self.assertEqual(s.findings, [])
        self.assertEqual(s.metrics, {})
        self.assertEqual(s.recommendations, [])

    def test_compliance_report_defaults(self) -> None:
        r = make_report()
        self.assertEqual(r.total_events, 0)
        self.assertEqual(r.violations, [])
        self.assertEqual(r.sections, [])


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestEnums(TestCase):
    def test_compliance_frameworks(self) -> None:
        self.assertEqual(ComplianceFramework.ISO27001, "iso27001")
        self.assertEqual(ComplianceFramework.GDPR, "gdpr")
        self.assertEqual(ComplianceFramework.PCI_DSS, "pci_dss")

    def test_report_types(self) -> None:
        self.assertEqual(ReportType.SECURITY_SUMMARY, "security_summary")
        self.assertEqual(ReportType.LOG_INTEGRITY, "log_integrity")

    def test_report_formats(self) -> None:
        self.assertEqual(ReportFormat.JSON, "json")
        self.assertEqual(ReportFormat.CSV, "csv")
        self.assertEqual(ReportFormat.PDF, "pdf")


# ---------------------------------------------------------------------------
# Compliance Rules
# ---------------------------------------------------------------------------


class TestPasswordPolicyRule(TestCase):
    def setUp(self) -> None:
        self.rule = PasswordPolicyRule()
        self.start, self.end = make_period()

    def test_no_events_is_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)
        self.assertEqual(_violations, [])

    def test_unrelated_events_are_compliant(self) -> None:
        events = [make_event(action="login_success")]
        compliant, violations = self.rule.check(events, self.start, self.end)
        self.assertTrue(compliant)
        self.assertEqual(violations, [])

    def test_password_strength_weak_triggers_violation(self) -> None:
        event = make_event(action="password_strength_weak")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.framework, "iso27001")
        self.assertEqual(v.control_id, "A.9.4.3")
        self.assertEqual(v.severity, "high")
        self.assertIn("password_strength_weak", v.description)
        self.assertEqual(v.evidence["action"], "password_strength_weak")

    def test_password_compromised_triggers_violation(self) -> None:
        event = make_event(action="password_compromised")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)

    def test_password_policy_violation_triggers_violation(self) -> None:
        event = make_event(action="password_policy_violation")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)

    def test_multiple_violations(self) -> None:
        events = [
            make_event(action="password_strength_weak"),
            make_event(action="password_compromised"),
        ]
        compliant, violations = self.rule.check(events, self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 2)

    def test_violation_evidence_with_no_user(self) -> None:
        event = make_event(action="password_strength_weak", user_id=None)
        _, violations = self.rule.check([event], self.start, self.end)
        self.assertIsNone(violations[0].evidence["user_id"])


class TestMFAEnforcementRule(TestCase):
    def setUp(self) -> None:
        self.rule = MFAEnforcementRule()
        self.start, self.end = make_period()

    def test_no_events_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)

    def test_2fa_disabled_triggers_violation(self) -> None:
        event = make_event(action="2fa_disabled")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].framework, "soc2")
        self.assertEqual(violations[0].control_id, "CC6.1")

    def test_2fa_enabled_does_not_trigger(self) -> None:
        event = make_event(action="2fa_enabled")
        compliant, _violations = self.rule.check([event], self.start, self.end)
        self.assertTrue(compliant)

    def test_violation_evidence_no_user(self) -> None:
        event = make_event(action="2fa_disabled", user_id=None)
        _, violations = self.rule.check([event], self.start, self.end)
        self.assertIsNone(violations[0].evidence["user_id"])


class TestAccessControlRule(TestCase):
    def setUp(self) -> None:
        self.rule = AccessControlRule()
        self.start, self.end = make_period()

    def test_no_events_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)

    def test_privilege_escalation_triggers_violation(self) -> None:
        event = make_event(action="privilege_escalation_attempt", ip_address="10.0.0.1")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.evidence["ip_address"], "10.0.0.1")

    def test_violation_includes_event_id(self) -> None:
        eid = uuid.uuid4()
        event = make_event(action="privilege_escalation_attempt", id=eid)
        _, violations = self.rule.check([event], self.start, self.end)
        self.assertEqual(violations[0].evidence["event_id"], str(eid))


class TestDataProtectionRule(TestCase):
    def setUp(self) -> None:
        self.rule = DataProtectionRule()
        self.start, self.end = make_period()

    def test_no_events_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)

    def test_data_breach_detected_triggers_violation(self) -> None:
        event = make_event(action="data_breach_detected", description="Leaked PII")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.framework, "gdpr")
        self.assertEqual(v.control_id, "Art.32")
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.evidence["description"], "Leaked PII")

    def test_data_breach_reported_triggers_violation(self) -> None:
        event = make_event(action="data_breach_reported", description="Reported breach")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)


class TestGDPRConsentRule(TestCase):
    def setUp(self) -> None:
        self.rule = GDPRConsentRule()
        self.start, self.end = make_period()

    def test_always_returns_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)
        self.assertEqual(_violations, [])

    def test_consent_withdrawn_still_compliant(self) -> None:
        event = make_event(action="gdpr_consent_withdrawn")
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertTrue(compliant)
        self.assertEqual(violations, [])


class TestSecurityEventRule(TestCase):
    def setUp(self) -> None:
        self.rule = SecurityEventRule()
        self.start, self.end = make_period()

    def test_no_events_compliant(self) -> None:
        compliant, _violations = self.rule.check([], self.start, self.end)
        self.assertTrue(compliant)

    def test_non_critical_security_event_compliant(self) -> None:
        event = make_event(action="brute_force_attempt", severity="medium", requires_review=False)
        compliant, _violations = self.rule.check([event], self.start, self.end)
        self.assertTrue(compliant)

    def test_critical_not_requiring_review_compliant(self) -> None:
        event = make_event(action="security_incident_detected", severity="critical", requires_review=False)
        compliant, _violations = self.rule.check([event], self.start, self.end)
        self.assertTrue(compliant)

    def test_critical_requiring_review_triggers_violation(self) -> None:
        event = make_event(action="brute_force_attempt", severity="critical", requires_review=True)
        compliant, violations = self.rule.check([event], self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.evidence["count"], 1)

    def test_multiple_critical_events_single_violation(self) -> None:
        events = [
            make_event(action="malicious_request", severity="critical", requires_review=True),
            make_event(action="suspicious_activity", severity="critical", requires_review=True),
        ]
        compliant, violations = self.rule.check(events, self.start, self.end)
        self.assertFalse(compliant)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].evidence["count"], 2)

    def test_unrelated_action_not_flagged(self) -> None:
        event = make_event(action="login_success", severity="critical", requires_review=True)
        compliant, _violations = self.rule.check([event], self.start, self.end)
        self.assertTrue(compliant)

    def test_event_ids_capped_at_10(self) -> None:
        events = [
            make_event(action="brute_force_attempt", severity="critical", requires_review=True) for _ in range(15)
        ]
        _, violations = self.rule.check(events, self.start, self.end)
        self.assertLessEqual(len(violations[0].evidence["event_ids"]), 10)


# ---------------------------------------------------------------------------
# ComplianceReportService — generate_report with DB events
# ---------------------------------------------------------------------------


class TestComplianceReportServiceGenerateReport(TestCase):
    """Integration-level tests that hit the real DB via AuditEvent."""

    def _create_event(self, **kwargs: Any) -> AuditEvent:
        ct = get_user_content_type()
        defaults: dict[str, Any] = {
            "action": "login_success",
            "category": "authentication",
            "severity": "info",
            "description": "Test event",
            "content_type": ct,
            "object_id": _DUMMY_OBJECT_ID,
        }
        defaults.update(kwargs)
        return AuditEvent.objects.create(**defaults)

    def _service(self, tmpdir: str) -> ComplianceReportService:
        svc = ComplianceReportService()
        svc.report_dir = tmpdir
        return svc

    def test_generate_security_summary_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.SECURITY_SUMMARY, start, end)
            self.assertIsInstance(report, ComplianceReport)
            self.assertEqual(report.report_type, ReportType.SECURITY_SUMMARY)
            self.assertGreaterEqual(len(report.sections), 2)

    def test_generate_security_summary_with_auth_events(self) -> None:
        self._create_event(action="login_failed", category="authentication", severity="medium")
        self._create_event(action="login_success", category="authentication", severity="info")
        self._create_event(
            action="brute_force_attempt", category="security_event", severity="critical", requires_review=False
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.SECURITY_SUMMARY, start, end)
            titles = [s.title for s in report.sections]
            self.assertIn("Authentication Summary", titles)
            self.assertIn("Security Events", titles)

    def test_gdpr_report_counts_marketing_consent_from_both_sources(self) -> None:
        """Issue #182: Customer marketing consent is now a ComplianceLog record, not an
        AuditEvent. The GDPR report must count those canonical ComplianceLog records in
        addition to the AuditEvent privacy consent events (User/gdpr/cookie), without
        double-counting either source.
        """
        from apps.audit.models import ComplianceLog  # noqa: PLC0415

        # User-path consent still writes an AuditEvent (privacy category) — must still count.
        self._create_event(action="marketing_consent_granted", category="privacy", severity="info")
        # Customer-path consent writes the canonical ComplianceLog (issue #182).
        ComplianceLog.objects.create(
            compliance_type="marketing_consent",
            reference_id="customer_a",
            status="success",
            description="Marketing consent granted via preference_center",
            evidence={"new_consent": True, "old_consent": False},
        )
        ComplianceLog.objects.create(
            compliance_type="marketing_consent",
            reference_id="customer_b",
            status="success",
            description="Marketing consent withdrawn via unsubscribe_link",
            evidence={"new_consent": False, "old_consent": True},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.GDPR_COMPLIANCE, start, end)

        gdpr = next(s for s in report.sections if s.title == "GDPR Compliance")
        # 1 AuditEvent granted + 1 ComplianceLog granted; 1 ComplianceLog withdrawn.
        self.assertEqual(gdpr.metrics["consent_granted"], 2)
        self.assertEqual(gdpr.metrics["consent_withdrawn"], 1)

    def test_generate_access_review(self) -> None:
        self._create_event(action="role_assigned", category="authorization", severity="info")
        self._create_event(action="permission_granted", category="authorization", severity="info")

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.ACCESS_REVIEW, start, end)
            titles = [s.title for s in report.sections]
            self.assertIn("Access Control Review", titles)

    def test_generate_authentication_audit(self) -> None:
        self._create_event(action="account_locked", category="authentication", severity="high")
        self._create_event(action="2fa_enabled", category="authentication", severity="info")

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.AUTHENTICATION_AUDIT, start, end)
            titles = [s.title for s in report.sections]
            self.assertIn("Authentication Audit", titles)
            # Verify metrics
            auth_section = next(s for s in report.sections if s.title == "Authentication Audit")
            self.assertIn("account_lockouts", auth_section.metrics)
            self.assertIn("mfa_events", auth_section.metrics)

    def test_generate_compliance_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.COMPLIANCE_VIOLATIONS, start, end)
            titles = [s.title for s in report.sections]
            self.assertIn("Compliance Violations", titles)

    def test_generate_gdpr_compliance(self) -> None:
        self._create_event(action="consent_granted", category="privacy", severity="info")
        self._create_event(action="gdpr_consent_withdrawn", category="privacy", severity="info")
        self._create_event(action="data_export_requested", category="data_protection", severity="info")
        self._create_event(action="data_deletion_requested", category="data_protection", severity="info")

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.GDPR_COMPLIANCE, start, end)
            gdpr_section = next(s for s in report.sections if s.title == "GDPR Compliance")
            self.assertEqual(gdpr_section.metrics["consent_granted"], 1)
            self.assertEqual(gdpr_section.metrics["consent_withdrawn"], 1)
            self.assertEqual(gdpr_section.metrics["data_export_requests"], 1)
            self.assertEqual(gdpr_section.metrics["data_deletion_requests"], 1)

    @staticmethod
    def _integrity_check(**overrides: Any) -> SimpleNamespace:
        defaults: dict[str, Any] = {"status": "healthy", "records_checked": 10, "issues_found": 0, "findings": []}
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_generate_log_integrity_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            with patch(
                "apps.audit.services.AuditIntegrityService.verify_audit_integrity",
                return_value=Ok(self._integrity_check()),
            ):
                report = svc.generate_report(ReportType.LOG_INTEGRITY, start, end)
            section = next(s for s in report.sections if s.title == "Log Integrity Verification")
            self.assertEqual(section.status, "compliant")
            self.assertEqual(section.metrics["integrity_issues"], 0)
            self.assertEqual(section.metrics["logs_verified"], 10)
            self.assertEqual(len(report.violations), 0)

    def test_generate_log_integrity_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            check = self._integrity_check(
                status="compromised",
                issues_found=1,
                findings=[{"type": "hash_mismatch", "description": "hash mismatch at event 42"}],
            )
            with patch(
                "apps.audit.services.AuditIntegrityService.verify_audit_integrity",
                return_value=Ok(check),
            ):
                report = svc.generate_report(ReportType.LOG_INTEGRITY, start, end)
            section = next(s for s in report.sections if s.title == "Log Integrity Verification")
            self.assertEqual(section.status, "non_compliant")
            self.assertEqual(section.metrics["integrity_issues"], 1)
            integrity_violations = [v for v in report.violations if v.control_id == "A.12.4.2"]
            self.assertGreaterEqual(len(integrity_violations), 1)

    def test_generate_log_integrity_error_is_non_compliant(self) -> None:
        """A verifier that fails to run must surface as non-compliance, never silent success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            with patch(
                "apps.audit.services.AuditIntegrityService.verify_audit_integrity",
                return_value=Err("db unavailable"),
            ):
                report = svc.generate_report(ReportType.LOG_INTEGRITY, start, end)
            section = next(s for s in report.sections if s.title == "Log Integrity Verification")
            self.assertEqual(section.status, "non_compliant")
            self.assertIn("failed to run", str(section.findings))
            integrity_violations = [v for v in report.violations if v.control_id == "A.12.4.2"]
            self.assertGreaterEqual(len(integrity_violations), 1)

    @override_settings(
        AUDIT_LOG_RETENTION={
            "authentication": {"retention_days": 365, "action": "archive"},
        }
    )
    def test_generate_retention_compliance_no_old_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.RETENTION_COMPLIANCE, start, end)
            section = next(s for s in report.sections if s.title == "Log Retention Compliance")
            self.assertEqual(section.status, "compliant")
            self.assertEqual(section.metrics["categories_checked"], 1)
            self.assertEqual(section.metrics["categories_with_issues"], 0)

    @override_settings(
        AUDIT_LOG_RETENTION={
            "authentication": {"retention_days": 1, "action": "archive"},
        }
    )
    def test_generate_retention_compliance_with_old_events(self) -> None:
        ct = get_user_content_type()
        event = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="info",
            description="Old event",
            content_type=ct,
            object_id=_DUMMY_OBJECT_ID,
        )
        # Force old timestamp since auto_now_add ignores the value at create time
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=timezone.now() - timedelta(days=5))

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.RETENTION_COMPLIANCE, start, end)
            section = next(s for s in report.sections if s.title == "Log Retention Compliance")
            self.assertEqual(section.status, "partial")
            self.assertGreater(section.metrics["categories_with_issues"], 0)

    def test_generate_generic_report_for_data_access_audit(self) -> None:
        self._create_event(category="business_operation")
        self._create_event(category="authorization")

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.DATA_ACCESS_AUDIT, start, end)
            titles = [s.title for s in report.sections]
            self.assertIn("Event Summary", titles)

    def test_report_has_report_id_and_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.SECURITY_SUMMARY, start, end, generated_by="tester")
            self.assertIsNotNone(report.report_id)
            self.assertEqual(report.generated_by, "tester")
            self.assertEqual(report.period_start, start)
            self.assertEqual(report.period_end, end)

    def test_total_events_count(self) -> None:
        self._create_event()
        self._create_event()

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._service(tmpdir)
            start, end = make_period()
            report = svc.generate_report(ReportType.SECURITY_SUMMARY, start, end)
            self.assertGreaterEqual(report.total_events, 2)


# ---------------------------------------------------------------------------
# ComplianceReportService — run_compliance_checks and calculate_score
# ---------------------------------------------------------------------------


class TestComplianceChecksAndScore(TestCase):
    def _service(self) -> ComplianceReportService:
        return ComplianceReportService()

    def test_run_compliance_checks_no_framework_filter(self) -> None:
        svc = self._service()
        report = make_report(framework=None, total_events=1)
        events = [make_event(action="password_strength_weak")]
        svc._run_compliance_checks(report, events)
        self.assertGreater(report.total_violations, 0)

    def test_run_compliance_checks_framework_filter_matches(self) -> None:
        svc = self._service()
        # ISO27001 framework — PasswordPolicyRule matches
        report = make_report(framework=ComplianceFramework.ISO27001, total_events=1)
        events = [make_event(action="password_strength_weak")]
        svc._run_compliance_checks(report, events)
        self.assertGreater(report.total_violations, 0)

    def test_run_compliance_checks_framework_filter_skips_non_matching(self) -> None:
        svc = self._service()
        # ROMANIAN_FISCAL — no rules match this framework so violations should be 0
        report = make_report(framework=ComplianceFramework.ROMANIAN_FISCAL, total_events=1)
        events = [make_event(action="password_strength_weak")]
        svc._run_compliance_checks(report, events)
        self.assertEqual(report.total_violations, 0)

    def test_calculate_compliance_score_no_events(self) -> None:
        svc = self._service()
        report = make_report(total_events=0)
        svc._calculate_compliance_score(report)
        self.assertEqual(report.compliance_score, 100.0)
        self.assertEqual(report.overall_status, "compliant")

    def test_calculate_compliance_score_with_no_violations(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        svc._calculate_compliance_score(report)
        self.assertEqual(report.compliance_score, 100.0)
        self.assertEqual(report.overall_status, "compliant")

    def test_calculate_compliance_score_with_critical_violation(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        report.violations.append(
            ComplianceViolation(
                framework="iso27001",
                control_id="X.1",
                description="Critical",
                severity="critical",
                detected_at=timezone.now(),
            )
        )
        report.total_violations = 1
        svc._calculate_compliance_score(report)
        # 100 - 25 = 75 → partial
        self.assertEqual(report.compliance_score, 75.0)
        self.assertEqual(report.overall_status, "partial")

    def test_calculate_compliance_score_non_compliant(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        # Add enough violations to drop below 70
        for _ in range(5):
            report.violations.append(
                ComplianceViolation(
                    framework="iso27001",
                    control_id="X.1",
                    description="Critical",
                    severity="critical",
                    detected_at=timezone.now(),
                )
            )
        report.total_violations = 5
        svc._calculate_compliance_score(report)
        # 100 - 5*25 = -25 → clamped to 0 → non_compliant
        self.assertEqual(report.compliance_score, 0.0)
        self.assertEqual(report.overall_status, "non_compliant")

    def test_calculate_compliance_score_high_severity(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        report.violations.append(
            ComplianceViolation(
                framework="iso27001",
                control_id="X.1",
                description="High",
                severity="high",
                detected_at=timezone.now(),
            )
        )
        svc._calculate_compliance_score(report)
        self.assertEqual(report.compliance_score, 90.0)
        self.assertEqual(report.overall_status, "compliant")

    def test_calculate_compliance_score_medium_severity(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        report.violations.append(
            ComplianceViolation(
                framework="iso27001",
                control_id="X.1",
                description="Medium",
                severity="medium",
                detected_at=timezone.now(),
            )
        )
        svc._calculate_compliance_score(report)
        self.assertEqual(report.compliance_score, 95.0)

    def test_calculate_compliance_score_unknown_severity(self) -> None:
        svc = self._service()
        report = make_report(total_events=5)
        report.violations.append(
            ComplianceViolation(
                framework="iso27001",
                control_id="X.1",
                description="Unknown",
                severity="unknown_sev",
                detected_at=timezone.now(),
            )
        )
        svc._calculate_compliance_score(report)
        # Default weight 5
        self.assertEqual(report.compliance_score, 95.0)


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------


class TestExportReport(TestCase):
    def _make_service_with_dir(self, tmpdir: str) -> ComplianceReportService:
        svc = ComplianceReportService()
        svc.report_dir = tmpdir
        return svc

    def _make_report_with_violation(self) -> ComplianceReport:
        report = make_report(total_events=10, total_violations=1)
        report.violations.append(
            ComplianceViolation(
                framework="iso27001",
                control_id="A.9.4.3",
                description="Weak password",
                severity="high",
                detected_at=timezone.now(),
                remediation="Enforce stronger passwords",
            )
        )
        report.sections.append(
            ComplianceReportSection(
                title="Test Section",
                description="A test section",
                status="partial",
                metrics={"total": 1},
                recommendations=["Fix something"],
            )
        )
        return report

    def test_export_json_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.JSON)
            self.assertTrue(os.path.exists(filepath))
            self.assertTrue(filepath.endswith(".json"))

    def test_export_json_valid_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.JSON)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["report_id"], report.report_id)
            self.assertEqual(data["overall_status"], report.overall_status)
            self.assertIn("sections", data)
            self.assertIn("violations", data)
            self.assertEqual(len(data["violations"]), 1)
            self.assertIsNone(data["framework"])

    def test_export_json_with_framework(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = make_report(framework=ComplianceFramework.GDPR)
            filepath = svc.export_report(report, ReportFormat.JSON)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["framework"], "gdpr")

    def test_export_csv_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.CSV)
            self.assertTrue(os.path.exists(filepath))
            self.assertTrue(filepath.endswith(".csv"))

    def test_export_csv_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.CSV)
            with open(filepath, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
            # Header + 1 violation row
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0][0], "Framework")
            self.assertEqual(rows[1][0], "iso27001")
            self.assertEqual(rows[1][1], "A.9.4.3")
            self.assertEqual(rows[1][3], "high")

    def test_export_csv_empty_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = make_report()
            filepath = svc.export_report(report, ReportFormat.CSV)
            with open(filepath, newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
            self.assertEqual(len(rows), 1)  # Header only

    def test_export_pdf_creates_txt_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.PDF)
            self.assertTrue(os.path.exists(filepath))
            self.assertTrue(filepath.endswith(".txt"))

    def test_export_pdf_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = self._make_report_with_violation()
            filepath = svc.export_report(report, ReportFormat.PDF)
            with open(filepath, encoding="utf-8") as f:
                content = f.read()
            self.assertIn(report.report_id, content)
            self.assertIn("COMPLIANCE REPORT", content)
            self.assertIn("VIOLATIONS", content)
            self.assertIn("Weak password", content)
            self.assertIn("TEST SECTION", content.upper())

    def test_export_pdf_no_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = self._make_service_with_dir(tmpdir)
            report = make_report()
            filepath = svc.export_report(report, ReportFormat.PDF)
            with open(filepath, encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("VIOLATIONS", content)


# ---------------------------------------------------------------------------
# Security summary edge cases
# ---------------------------------------------------------------------------


class TestSecuritySummaryEdgeCases(TestCase):
    def _service(self) -> ComplianceReportService:
        return ComplianceReportService()

    def test_high_failure_rate_is_partial(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        # Create events: many failed, few successful
        events = [
            make_event(action="login_failed", category="authentication"),
        ] * 20 + [
            make_event(action="login_success", category="authentication"),
        ]
        svc._generate_security_summary(report, events)
        auth_section = report.sections[0]
        self.assertEqual(auth_section.status, "partial")

    def test_no_failures_is_compliant(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        events = [make_event(action="login_success", category="authentication")] * 5
        svc._generate_security_summary(report, events)
        auth_section = report.sections[0]
        self.assertEqual(auth_section.status, "compliant")
        self.assertEqual(auth_section.recommendations, [])

    def test_critical_security_events_non_compliant(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        events = [make_event(action="brute_force_attempt", category="security_event", severity="critical")]
        svc._generate_security_summary(report, events)
        security_section = report.sections[1]
        self.assertEqual(security_section.status, "non_compliant")
        self.assertEqual(report.critical_findings, 1)


# ---------------------------------------------------------------------------
# Access review edge cases
# ---------------------------------------------------------------------------


class TestAccessReviewEdgeCases(TestCase):
    def _service(self) -> ComplianceReportService:
        return ComplianceReportService()

    def test_role_changes_appear_in_findings(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        mock_user = SimpleNamespace(email="admin@test.com")
        event = make_event(action="role_assigned", category="authorization", user=mock_user)
        svc._generate_access_review(report, [event])
        section = report.sections[0]
        self.assertEqual(len(section.findings), 1)
        self.assertEqual(section.findings[0]["user"], "admin@test.com")

    def test_no_user_on_role_change(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        event = make_event(action="role_removed", category="authorization", user=None)
        svc._generate_access_review(report, [event])
        section = report.sections[0]
        self.assertEqual(section.findings[0]["user"], "system")

    def test_metrics_counts(self) -> None:
        svc = self._service()
        start, end = make_period()
        report = make_report(period_start=start, period_end=end)
        events = [
            make_event(action="role_assigned", category="authorization"),
            make_event(action="role_removed", category="authorization"),
            make_event(action="permission_granted", category="authorization"),
            make_event(action="permission_revoked", category="authorization"),
        ]
        svc._generate_access_review(report, events)
        m = report.sections[0].metrics
        self.assertEqual(m["role_assignments"], 1)
        self.assertEqual(m["role_removals"], 1)
        self.assertEqual(m["permission_grants"], 1)
        self.assertEqual(m["permission_revocations"], 1)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


class TestConvenienceFunctions(TestCase):
    def test_generate_compliance_report_returns_report(self) -> None:
        report = generate_compliance_report(report_type="security_summary", days=7)
        self.assertIsInstance(report, ComplianceReport)
        self.assertEqual(report.report_type, ReportType.SECURITY_SUMMARY)

    def test_generate_compliance_report_with_framework(self) -> None:
        report = generate_compliance_report(
            report_type="security_summary",
            days=7,
            framework="gdpr",
        )
        self.assertEqual(report.framework, ComplianceFramework.GDPR)

    def test_generate_compliance_report_no_framework(self) -> None:
        report = generate_compliance_report(report_type="access_review", days=14)
        self.assertIsNone(report.framework)
