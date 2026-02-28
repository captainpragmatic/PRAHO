"""
Tests for audit management commands:
- audit_compliance
- generate_audit_events
- run_integrity_check
"""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

User = get_user_model()


# ============================================================================
# Helpers / Fixtures
# ============================================================================

def _make_violation(framework="gdpr", control_id="GDPR-1", description="Test violation",
                    severity="high", remediation="Fix it"):
    """Create a mock ComplianceViolation-like object."""
    v = MagicMock()
    v.framework = framework
    v.control_id = control_id
    v.description = description
    v.severity = severity
    v.remediation = remediation
    return v


def _make_report(overall_status="compliant", compliance_score=95.0, total_events=100,  # noqa: PLR0913
                 total_violations=0, critical_findings=0, violations=None,
                 report_type_value="security_summary"):
    """Create a mock ComplianceReport-like object."""
    report = MagicMock()
    report.report_id = "test-report-123"
    report.report_type.value = report_type_value
    report.overall_status = overall_status
    report.compliance_score = compliance_score
    report.total_events = total_events
    report.total_violations = total_violations
    report.critical_findings = critical_findings
    report.violations = violations or []
    return report


# ============================================================================
# audit_compliance tests
# ============================================================================

class TestAuditComplianceCommand(TestCase):
    """Tests for the audit_compliance management command."""

    def _call(self, *args, **kwargs):
        out = StringIO()
        err = StringIO()
        kwargs.setdefault("stdout", out)
        kwargs.setdefault("stderr", err)
        call_command("audit_compliance", *args, **kwargs)
        return out.getvalue(), err.getvalue()

    def test_no_subcommand_prints_help(self):
        """When no subcommand given, prints help without error."""
        _out, _ = self._call()
        # help output or empty — no crash
        # The command calls print_help which writes to stdout

    # --- report subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_report_default(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        report = _make_report()
        mock_svc.generate_report.return_value = report
        mock_svc.export_report.return_value = "/tmp/report.json"  # noqa: S108

        out, _ = self._call("report")
        assert "COMPLIANCE REPORT GENERATED" in out
        assert "test-report-123" in out
        assert "/tmp/report.json" in out  # noqa: S108
        assert "95.0%" in out

        mock_svc.generate_report.assert_called_once()
        call_kwargs = mock_svc.generate_report.call_args
        assert call_kwargs.kwargs.get("generated_by") == "management_command"

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_report_with_violations(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        violations = [_make_violation(severity="critical"), _make_violation(severity="high")]
        report = _make_report(total_violations=2, violations=violations)
        mock_svc.generate_report.return_value = report
        mock_svc.export_report.return_value = "/tmp/report.json"  # noqa: S108

        out, _ = self._call("report")
        assert "VIOLATIONS:" in out

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_report_more_violations_than_max(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        violations = [_make_violation() for _ in range(15)]
        report = _make_report(total_violations=15, violations=violations)
        mock_svc.generate_report.return_value = report
        mock_svc.export_report.return_value = "/tmp/r.json"  # noqa: S108

        out, _ = self._call("report")
        assert "... and 5 more" in out

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_report_with_framework_and_format(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        report = _make_report()
        mock_svc.generate_report.return_value = report
        mock_svc.export_report.return_value = "/tmp/r.csv"  # noqa: S108

        _out, _ = self._call("report", "--type=access_review", "--framework=gdpr",
                            "--format=csv", "--days=7")
        mock_svc.generate_report.assert_called_once()
        call_kwargs = mock_svc.generate_report.call_args
        # framework should be ComplianceFramework.GDPR
        assert call_kwargs.kwargs.get("framework") is not None

    # --- verify-integrity subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.get_siem_service")
    def test_verify_integrity_valid(self, mock_get_siem):
        mock_siem = mock_get_siem.return_value
        mock_siem.verify_log_integrity.return_value = (True, [])

        out, _ = self._call("verify-integrity")
        assert "VERIFIED" in out

    @patch("apps.audit.management.commands.audit_compliance.get_siem_service")
    def test_verify_integrity_failed(self, mock_get_siem):
        mock_siem = mock_get_siem.return_value
        mock_siem.verify_log_integrity.return_value = (False, ["gap at seq 42", "hash mismatch"])

        out, _ = self._call("verify-integrity", "--days=3")
        assert "FAILED" in out
        assert "gap at seq 42" in out
        assert "2 integrity issues" in out

    # --- apply-retention subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_apply_retention_dry_run(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        mock_svc.get_retention_status.return_value = {
            "authentication": {
                "events_past_retention": 5,
                "retention_days": 365,
                "action": "archive",
            },
            "security_event": {
                "events_past_retention": 0,
                "retention_days": 730,
                "action": "archive",
            },
        }

        out, _ = self._call("apply-retention", "--dry-run")
        assert "DRY RUN" in out
        assert "authentication" in out
        # security_event has 0 past retention, should not be printed
        assert "security_event" not in out

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_apply_retention_real(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        mock_svc.apply_retention_policies.return_value = {
            "archived": 10,
            "deleted": 3,
            "anonymized": 2,
            "errors": [],
        }

        out, _ = self._call("apply-retention")
        assert "Archived: 10" in out
        assert "Deleted: 3" in out
        assert "Anonymized: 2" in out

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_apply_retention_with_errors(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        mock_svc.apply_retention_policies.return_value = {
            "archived": 0,
            "deleted": 0,
            "anonymized": 0,
            "errors": [{"category": "auth", "error": "DB locked"}],
        }

        out, _ = self._call("apply-retention")
        assert "Errors: 1" in out
        assert "DB locked" in out

    # --- retention-status subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_retention_status_text(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        mock_svc.get_retention_status.return_value = {
            "authentication": {
                "retention_days": 365,
                "action": "archive",
                "legal_basis": "GDPR Art 6",
                "total_events": 100,
                "events_past_retention": 5,
                "compliance_status": "compliant",
            },
        }

        out, _ = self._call("retention-status")
        assert "LOG RETENTION STATUS" in out
        assert "AUTHENTICATION" in out
        assert "365" in out

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_retention_status_json(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        status_data = {
            "auth": {"retention_days": 365, "compliance_status": "compliant"},
        }
        mock_svc.get_retention_status.return_value = status_data

        out, _ = self._call("retention-status", "--json")
        parsed = json.loads(out)
        assert parsed == status_data

    @patch("apps.audit.management.commands.audit_compliance.LogRetentionService")
    def test_retention_status_non_compliant(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        mock_svc.get_retention_status.return_value = {
            "data_protection": {
                "retention_days": 90,
                "action": "delete",
                "legal_basis": "GDPR",
                "total_events": 50,
                "events_past_retention": 20,
                "compliance_status": "non_compliant",
            },
        }

        out, _ = self._call("retention-status")
        assert "non_compliant" in out

    # --- export-siem subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.get_siem_service")
    def test_export_siem(self, mock_get_siem):
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        mock_siem = mock_get_siem.return_value
        mock_entry = MagicMock()
        mock_siem._create_log_entry.return_value = mock_entry

        from django.contrib.contenttypes.models import ContentType  # noqa: PLC0415

        # Create a real event for DB query
        user = User.objects.create_user(email="siem@test.com", password="testpass123")
        ct = ContentType.objects.get_for_model(User)
        AuditEvent.objects.create(
            user=user,
            action="login_success",
            severity="high",
            description="Test event",
            ip_address="1.2.3.4",
            content_type=ct,
            object_id=str(user.pk),
        )

        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            out, _ = self._call("export-siem", f"--output={tmp_path}", "--format=json",
                                "--min-severity=low", "--days=1")
            assert "Exported" in out
            assert "events" in out
            assert tmp_path in out
        finally:
            os.unlink(tmp_path)

    @patch("apps.audit.management.commands.audit_compliance.get_siem_service")
    def test_export_siem_severity_filter(self, mock_get_siem):
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        mock_siem = mock_get_siem.return_value
        mock_siem._create_log_entry.return_value = MagicMock()

        from django.contrib.contenttypes.models import ContentType  # noqa: PLC0415

        user = User.objects.create_user(email="siem2@test.com", password="testpass123")
        ct = ContentType.objects.get_for_model(User)
        AuditEvent.objects.create(user=user, action="view", severity="low", description="Low",
                                  content_type=ct, object_id=str(user.pk))
        AuditEvent.objects.create(user=user, action="delete", severity="critical", description="Crit",
                                  content_type=ct, object_id=str(user.pk))

        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            out, _ = self._call("export-siem", f"--output={tmp_path}", "--min-severity=critical")
            assert "1 events" in out
        finally:
            os.unlink(tmp_path)

    # --- check subcommand ---

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_check_no_violations(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        report = _make_report(overall_status="compliant", violations=[])
        mock_svc.generate_report.return_value = report

        out, _ = self._call("check")
        assert "COMPLIANCE CHECK RESULTS" in out
        assert "No compliance violations found" in out
        assert "All" in out  # framework = All

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_check_with_violations(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        v1 = _make_violation(framework="gdpr", control_id="GDPR-1", severity="critical", remediation="Fix")
        v2 = _make_violation(framework="iso27001", control_id="ISO-5", severity="medium", remediation="")
        report = _make_report(overall_status="non_compliant", violations=[v1, v2])
        mock_svc.generate_report.return_value = report

        out, _ = self._call("check", "--framework=gdpr", "--days=7")
        assert "2 violations" in out
        assert "GDPR" in out
        assert "Remediation: Fix" in out

    @patch("apps.audit.management.commands.audit_compliance.ComplianceReportService")
    def test_check_with_framework(self, mock_svc_cls):
        mock_svc = mock_svc_cls.return_value
        report = _make_report(overall_status="compliant", violations=[])
        mock_svc.generate_report.return_value = report

        out, _ = self._call("check", "--framework=iso27001")
        assert "iso27001" in out

    # --- _colorize_status / _get_severity_style ---

    def test_colorize_status(self):
        from apps.audit.management.commands.audit_compliance import Command  # noqa: PLC0415
        cmd = Command(stdout=StringIO())
        assert "COMPLIANT" in cmd._colorize_status("compliant")
        assert "PARTIAL" in cmd._colorize_status("partial")
        assert "FAILED" in cmd._colorize_status("failed")

    def test_get_severity_style(self):
        from apps.audit.management.commands.audit_compliance import Command  # noqa: PLC0415
        cmd = Command(stdout=StringIO())
        assert "CRITICAL" in cmd._get_severity_style("critical")
        assert "HIGH" in cmd._get_severity_style("high")
        assert "MEDIUM" in cmd._get_severity_style("medium")
        assert cmd._get_severity_style("low") == "LOW"


# ============================================================================
# generate_audit_events tests
# ============================================================================

class TestGenerateAuditEventsCommand(TestCase):
    """Tests for the generate_audit_events management command."""

    def _call(self, *args, **kwargs):
        out = StringIO()
        kwargs.setdefault("stdout", out)
        call_command("generate_audit_events", *args, **kwargs)
        return out.getvalue()

    def test_default_count(self):
        """Default generates 30 events."""
        from apps.audit.models import AuditEvent  # noqa: PLC0415
        initial = AuditEvent.objects.count()
        out = self._call()
        assert AuditEvent.objects.count() >= initial + 25  # Allow some failures
        assert "Successfully generated" in out

    def test_custom_count(self):
        from apps.audit.models import AuditEvent  # noqa: PLC0415
        out = self._call("--count=5")
        assert AuditEvent.objects.count() >= 5
        assert "5" in out

    def test_creates_test_user_when_none(self):
        """When no users exist, creates a test user."""
        User.objects.all().delete()
        out = self._call("--count=3")
        assert "No users found" in out or "Successfully generated" in out
        assert User.objects.filter(email="test@example.com").exists()

    def test_with_existing_users(self):
        User.objects.create_user(email="existing@test.com", password="testpass123")
        out = self._call("--count=5")
        assert "Successfully generated" in out

    def test_pagination_info(self):
        from apps.audit.models import AuditEvent  # noqa: PLC0415
        out = self._call("--count=55")
        assert "Total audit events" in out
        total = AuditEvent.objects.count()
        if total > 50:
            assert "Pagination" in out

    def test_progress_indicator(self):
        out = self._call("--count=20")
        assert "Created 10/" in out or "Created 20/" in out


# ============================================================================
# run_integrity_check tests
# ============================================================================

class TestRunIntegrityCheckCommand(TestCase):
    """Tests for the run_integrity_check management command."""

    def _call(self, *args, **kwargs):
        out = StringIO()
        err = StringIO()
        kwargs.setdefault("stdout", out)
        kwargs.setdefault("stderr", err)
        call_command("run_integrity_check", *args, **kwargs)
        return out.getvalue(), err.getvalue()

    # --- Basic execution ---

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_default_all_checks(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 42
        check.issues_found = 0
        check.findings = []
        check.id = "check-123"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call()
        assert "PRAHO Audit Integrity Check" in out
        assert "INTEGRITY CHECK SUMMARY" in out
        assert "HEALTHY" in out
        assert "All integrity checks passed" in out
        # Should be called 3 times (hash_verification, sequence_check, gdpr_compliance)
        assert mock_svc.verify_audit_integrity.call_count == 3

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_specific_check_type(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 10
        check.issues_found = 0
        check.findings = []
        check.id = "c-1"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        _out, _ = self._call("--type=hash_verification")
        assert mock_svc.verify_audit_integrity.call_count == 1

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_warning_status(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "warning"
        check.records_checked = 50
        check.issues_found = 3
        check.findings = []
        check.id = "c-2"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=sequence_check")
        assert "WARNING" in out
        assert "3 issues require attention" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_compromised_status(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "compromised"
        check.records_checked = 100
        check.issues_found = 10
        check.findings = []
        check.id = "c-3"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification")
        assert "COMPROMISED" in out
        assert "CRITICAL" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_compromised_with_alerts(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "compromised"
        check.records_checked = 100
        check.issues_found = 5
        check.findings = []
        check.id = "c-4"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification", "--alert")
        assert "Alerts have been sent" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_error_result(self, mock_svc):
        from apps.common.types import Err  # noqa: PLC0415
        mock_svc.verify_audit_integrity.return_value = Err("DB connection failed")

        out, _ = self._call("--type=hash_verification")
        assert "DB connection failed" in out

    # --- verbose output ---

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_verbose_shows_findings(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "warning"
        check.records_checked = 20
        check.issues_found = 1
        check.findings = [{"severity": "high", "description": "Gap at seq 42"}]
        check.id = "c-5"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=sequence_check", "--verbose")
        assert "Gap at seq 42" in out
        assert "Findings:" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_verbose_limits_findings_to_10(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "warning"
        check.records_checked = 20
        check.issues_found = 15
        check.findings = [{"severity": "low", "description": f"Issue {i}"} for i in range(15)]
        check.id = "c-6"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification", "--verbose")
        # Should show only first 10
        assert "Issue 9" in out
        assert "Issue 10" not in out

    # --- period parsing ---

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_period_map_values(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 0
        check.issues_found = 0
        check.findings = []
        check.id = "c-7"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification", "--period=7d")
        assert "HEALTHY" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_period_custom_hours(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 0
        check.issues_found = 0
        check.findings = []
        check.id = "c-8"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification", "--period=48h")
        assert "HEALTHY" in out

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_period_custom_days(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 0
        check.issues_found = 0
        check.findings = []
        check.id = "c-8b"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification", "--period=15d")
        assert "HEALTHY" in out

    def test_period_invalid_format(self):
        with pytest.raises(SystemExit):
            self._call("--type=hash_verification", "--period=abc")

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_start_end_override(self, mock_svc):
        from apps.common.types import Ok  # noqa: PLC0415
        check = MagicMock()
        check.status = "healthy"
        check.records_checked = 0
        check.issues_found = 0
        check.findings = []
        check.id = "c-9"
        mock_svc.verify_audit_integrity.return_value = Ok(check)

        out, _ = self._call("--type=hash_verification",
                            "--start=2026-01-01T00:00:00+00:00",
                            "--end=2026-01-02T00:00:00+00:00")
        assert "2026-01-01" in out

    def test_invalid_start_end(self):
        with pytest.raises(SystemExit):
            self._call("--type=hash_verification", "--start=bad", "--end=bad")

    # --- schedule ---

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_schedule_without_django_q(self, mock_svc):
        """When django_q not installed, prints error."""
        with patch.dict("sys.modules", {"django_q": None, "django_q.models": None}):
            # Force reimport to trigger ImportError
            import apps.audit.management.commands.run_integrity_check as mod  # noqa: PLC0415
            # The _setup_scheduled_tasks catches ImportError
            out = StringIO()
            err = StringIO()
            cmd = mod.Command(stdout=out, stderr=err)
            # Simulate the import error path
            with patch("builtins.__import__", side_effect=ImportError("No django_q")):
                cmd._setup_scheduled_tasks()
            assert "not installed" in err.getvalue()

    def test_schedule_with_exception(self):
        """When schedule setup fails with generic exception."""
        import apps.audit.management.commands.run_integrity_check as mod  # noqa: PLC0415
        out = StringIO()
        err = StringIO()
        cmd = mod.Command(stdout=out, stderr=err)

        with patch("builtins.__import__", side_effect=RuntimeError("boom")):
            cmd._setup_scheduled_tasks()
        assert "Failed to setup" in err.getvalue()

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_schedule_flag_calls_setup(self, mock_svc):
        """--schedule flag triggers _setup_scheduled_tasks."""
        import apps.audit.management.commands.run_integrity_check as mod  # noqa: PLC0415
        with patch.object(mod.Command, "_setup_scheduled_tasks") as mock_setup:
            out = StringIO()
            call_command("run_integrity_check", "--schedule", stdout=out)
            mock_setup.assert_called_once()

    # --- summary edge cases ---

    @patch("apps.audit.management.commands.run_integrity_check.AuditIntegrityService")
    def test_mixed_results_summary(self, mock_svc):
        from apps.common.types import Err, Ok  # noqa: PLC0415
        healthy_check = MagicMock()
        healthy_check.status = "healthy"
        healthy_check.records_checked = 10
        healthy_check.issues_found = 0
        healthy_check.findings = []
        healthy_check.id = "c-10"

        warning_check = MagicMock()
        warning_check.status = "warning"
        warning_check.records_checked = 10
        warning_check.issues_found = 2
        warning_check.findings = []
        warning_check.id = "c-11"

        mock_svc.verify_audit_integrity.side_effect = [
            Ok(healthy_check),
            Ok(warning_check),
            Err("timeout"),
        ]

        out, _ = self._call()
        assert "HEALTHY" in out
        assert "WARNING" in out
        assert "ERROR" in out
        assert "2 issues require attention" in out
