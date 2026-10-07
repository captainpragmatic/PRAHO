"""Call-time effects and query budgets for the eight WP18 audit settings."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from io import StringIO
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django.utils.translation import override

from apps.audit.compliance import ComplianceReport, ComplianceReportService, ComplianceViolation, ReportType
from apps.audit.management.commands.audit_compliance import Command
from apps.audit.models import AuditAlert, AuditEvent
from apps.audit.services import AuditContext, AuditEventData, AuditSearchService, AuditService, IntegrationsAuditService
from apps.audit.tasks import _create_file_integrity_alert
from apps.integrations.models import WebhookEvent
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE

AUDIT_DEFAULTS = {
    "audit.compliant_score_threshold": 90,
    "audit.high_complexity_filter_threshold": 5,
    "audit.max_files_displayed": 5,
    "audit.max_violations_displayed": 10,
    "audit.partial_score_threshold": 70,
    "audit.webhook_healthy_response_threshold": 300,
    "audit.webhook_max_retry_threshold": 5,
    "audit.webhook_suspicious_retry_threshold": 3,
}
HOT_VALUES = {
    "audit.high_complexity_filter_threshold": 2,
    "audit.webhook_healthy_response_threshold": 250,
    "audit.webhook_max_retry_threshold": 1,
    "audit.webhook_suspicious_retry_threshold": 1,
}


def _report(score: int) -> ComplianceReport:
    now = timezone.now()
    violations = [
        ComplianceViolation("iso27001", f"CONTROL-{index}", "Violation", "low", now) for index in range(100 - score)
    ]
    return ComplianceReport(
        report_id="audit-settings-effect",
        report_type=ReportType.SECURITY_SUMMARY,
        framework=None,
        generated_at=now,
        period_start=now,
        period_end=now,
        generated_by="settings-test",
        overall_status="unknown",
        compliance_score=0,
        total_events=1,
        total_violations=len(violations),
        violations=violations,
    )


def _webhook(retry_count: int = 0) -> WebhookEvent:
    webhook = WebhookEvent(
        source="stripe",
        event_id=f"evt-{uuid.uuid4().hex}",
        event_type="payment.succeeded",
        payload={},
        retry_count=retry_count,
    )
    # The current audit consumer expects this transient attribute, rather than signature_hash.
    webhook.__dict__["signature"] = ""
    return webhook


def _metadata(event: AuditEvent, section: str) -> dict[str, object]:
    return cast("dict[str, object]", event.metadata[section])


def _query_info() -> dict[str, object]:
    return {
        "filters_applied": ["user_filter", "action_filter", "category_filter"],
        "performance_hints": [],
        "estimated_cost": "low",
    }


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class AuditSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_compliant_score_threshold_changes_classification(self) -> None:
        self.set_value("audit.compliant_score_threshold", 80)
        service = ComplianceReportService()
        report = _report(85)
        service._calculate_compliance_score(report)
        self.assertEqual(report.overall_status, "compliant")
        for score, expected in ((79, "partial"), (80, "compliant"), (81, "compliant")):
            with self.subTest(score=score):
                report = _report(score)
                service._calculate_compliance_score(report)
                self.assertEqual(report.overall_status, expected)
        self.set_value("audit.compliant_score_threshold", 95)
        report = _report(85)
        service._calculate_compliance_score(report)
        self.assertEqual(report.overall_status, "partial")

    def test_partial_score_threshold_changes_classification(self) -> None:
        self.set_value("audit.partial_score_threshold", 60)
        service = ComplianceReportService()
        report = _report(65)
        service._calculate_compliance_score(report)
        self.assertEqual(report.overall_status, "partial")
        for score, expected in ((59, "non_compliant"), (60, "partial"), (61, "partial")):
            with self.subTest(score=score):
                report = _report(score)
                service._calculate_compliance_score(report)
                self.assertEqual(report.overall_status, expected)
        self.set_value("audit.partial_score_threshold", 80)
        report = _report(65)
        service._calculate_compliance_score(report)
        self.assertEqual(report.overall_status, "non_compliant")

    def test_high_complexity_filter_threshold_changes_cost(self) -> None:
        self.set_value("audit.high_complexity_filter_threshold", 2)
        info = _query_info()
        AuditSearchService._add_performance_hints(info)
        self.assertEqual(info["estimated_cost"], "high")
        for count, expected in ((1, "low"), (2, "low"), (3, "high")):
            with self.subTest(count=count):
                info = _query_info()
                info["filters_applied"] = ["user_filter"] * count
                AuditSearchService._add_performance_hints(info)
                self.assertEqual(info["estimated_cost"], expected)
        self.set_value("audit.high_complexity_filter_threshold", 4)
        info = _query_info()
        AuditSearchService._add_performance_hints(info)
        self.assertEqual(info["estimated_cost"], "low")

    def test_max_files_displayed_limits_alert_description(self) -> None:
        self.set_value("audit.max_files_displayed", 1)
        results: dict[str, object] = {
            "changes_detected": [{"path": path} for path in ("first.py", "second.py", "third.py")]
        }
        with patch("apps.notifications.services.NotificationService.send_admin_alert"), override("en"):
            _create_file_integrity_alert(results)
        alert = AuditAlert.objects.get(metadata__source="file_integrity_monitoring")
        self.assertNotIn("second.py", alert.description)
        self.assertIn("first.py", alert.description)
        self.assertIn("2 more", alert.description)
        self.assertEqual(alert.evidence["changes"], results["changes_detected"])

    def test_max_violations_displayed_limits_command_output(self) -> None:
        self.set_value("audit.max_violations_displayed", 1)
        output = StringIO()
        report = _report(97)
        with (
            patch.object(ComplianceReportService, "generate_report", return_value=report),
            patch.object(ComplianceReportService, "export_report", return_value="report.json"),
            override("en"),
        ):
            Command(stdout=output, no_color=True).handle_report(
                {"days": 1, "type": "security_summary", "format": "json"}
            )
        self.assertNotIn("CONTROL-1", output.getvalue())
        self.assertIn("CONTROL-0", output.getvalue())
        self.assertIn("2 more", output.getvalue())

    def test_webhook_healthy_response_threshold_changes_persisted_health(self) -> None:
        self.set_value("audit.webhook_healthy_response_threshold", 250)
        webhook = _webhook()
        webhook.save()
        event = IntegrationsAuditService.log_webhook_success(webhook, 100, response_status=275)
        event.refresh_from_db()
        self.assertIs(_metadata(event, "service_health")["endpoint_healthy"], False)
        for status, expected in ((249, True), (250, False), (251, False)):
            with self.subTest(status=status):
                event = IntegrationsAuditService.log_webhook_success(webhook, 100, response_status=status)
                event.refresh_from_db()
                self.assertIs(_metadata(event, "service_health")["endpoint_healthy"], expected)

    def test_webhook_max_retry_threshold_changes_failure_and_exhaustion(self) -> None:
        self.set_value("audit.webhook_max_retry_threshold", 1)
        webhook = _webhook(1)
        webhook.save()
        failure = IntegrationsAuditService.log_webhook_failure(webhook, {"error_type": "server_error"})
        failure.refresh_from_db()
        self.assertEqual(_metadata(failure, "failure_analysis")["failure_severity"], "high")
        self.assertIs(_metadata(failure, "failure_analysis")["retry_exhausted"], True)
        exhausted = IntegrationsAuditService.log_webhook_retry_exhausted(webhook, 1, "unavailable")
        exhausted.refresh_from_db()
        self.assertIs(_metadata(exhausted, "alerting_context")["escalation_needed"], True)
        webhook.retry_count = 0
        failure = IntegrationsAuditService.log_webhook_failure(webhook, {"error_type": "server_error"})
        self.assertEqual(_metadata(failure, "failure_analysis")["failure_severity"], "medium")
        self.assertIs(_metadata(failure, "failure_analysis")["retry_exhausted"], False)
        exhausted = IntegrationsAuditService.log_webhook_retry_exhausted(webhook, 0, "unavailable")
        self.assertIs(_metadata(exhausted, "alerting_context")["escalation_needed"], False)

    def test_webhook_suspicious_retry_threshold_preserves_explicit_flags(self) -> None:
        self.set_value("audit.webhook_suspicious_retry_threshold", 1)
        webhook = _webhook(2)
        webhook.save()
        event = IntegrationsAuditService.log_webhook_failure(webhook, {"error_type": "server_error"})
        event.refresh_from_db()
        self.assertIs(_metadata(event, "security_indicators")["repeated_failures"], True)
        for count, expected in ((0, False), (1, False), (2, True)):
            with self.subTest(count=count):
                webhook.retry_count = count
                event = IntegrationsAuditService.log_webhook_failure(webhook, {"error_type": "server_error"})
                self.assertIs(_metadata(event, "security_indicators")["repeated_failures"], expected)
        webhook.retry_count = 2
        for flags in ({}, {"repeated_failures": False}):
            with self.subTest(flags=flags):
                event = IntegrationsAuditService.log_webhook_failure(
                    webhook, {"error_type": "server_error"}, security_flags=flags
                )
                event.refresh_from_db()
                self.assertEqual(event.metadata["security_indicators"], flags)

    def test_activation_preserves_defaults_and_warns_once_for_retained_values(self) -> None:
        retained = {"audit.high_complexity_filter_threshold": 2, "audit.webhook_max_retry_threshold": 1}
        missing = {"audit.max_files_displayed", "audit.max_violations_displayed"}
        seeded = {"audit.compliant_score_threshold", "audit.webhook_suspicious_retry_threshold"}
        for key, default in AUDIT_DEFAULTS.items():
            if key in seeded:
                SystemSetting.objects.create(key=key, value=default, **sync._row_defaults(CATALOG_BY_KEY[key]))
            elif key not in missing:
                self.set_value(key, retained.get(key, default))
        metadata_row = SystemSetting.objects.get(key="audit.partial_score_threshold")
        previous_timestamp = metadata_row.updated_at
        SystemSetting.objects.filter(pk=metadata_row.pk).update(name="stale metadata")
        definitions = tuple(CATALOG_BY_KEY[key] for key in AUDIT_DEFAULTS)
        with (
            patch.object(
                sync, "CATALOG", tuple(definition for definition in definitions if definition.key not in missing)
            ),
            patch.object(sync, "DEFAULT_VALUE_MIGRATIONS", {}),
            self.captureOnCommitCallbacks(execute=True),
        ):
            call_command("setup_default_settings", stdout=StringIO())
        metadata_row.refresh_from_db()
        self.assertGreater(metadata_row.updated_at, previous_timestamp)
        output = StringIO()
        with patch.object(sync, "CATALOG", definitions), self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=output)
        alerts = AuditAlert.objects.filter(metadata__activation_version=sync.ACTIVATION_VERSION)
        self.assertEqual(alerts.count(), 1)
        alert = alerts.get()
        self.assertEqual(alert.evidence["retained_values"], retained)
        self.assertEqual(alert.evidence["previous_enforced_values"], {key: AUDIT_DEFAULTS[key] for key in retained})
        self.assertEqual((alert.alert_type, alert.status), ("data_integrity", "active"))
        self.assertEqual(set(alert.metadata["keys"]), set(retained))
        receipts = SettingActivation.objects.filter(key__in=AUDIT_DEFAULTS, completed_at__isnull=False)
        self.assertEqual(receipts.count(), 8)
        for key, default in AUDIT_DEFAULTS.items():
            row = SystemSetting.objects.get(key=key)
            self.assertEqual(row.value, retained.get(key, default))
            self.assertEqual(row.default_value, default)
            if key in retained:
                self.assertIn(key, output.getvalue())
                self.assertIn(key, alert.description)
        self.set_value("audit.webhook_max_retry_threshold", 5)
        with patch.object(sync, "CATALOG", definitions), self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(alerts.count(), 1)
        self.assertEqual(SystemSetting.objects.get(key="audit.webhook_max_retry_threshold").value, 5)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class AuditSettingsQueryTests(SimpleTestCase):
    """Use actual cache/autocommit modes; isolate metadata construction from audit persistence."""

    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @staticmethod
    def capture_event(data: AuditEventData, context: AuditContext) -> AuditEvent:
        return AuditEvent(action=data.event_type, metadata=context.metadata)

    def assert_query_budgets(self, *, warm: bool) -> None:
        webhook = _webhook(2)
        info = _query_info()

        def search() -> object:
            AuditSearchService._add_performance_hints(info)
            return info["estimated_cost"]

        def success() -> object:
            event = IntegrationsAuditService.log_webhook_success(webhook, 100, response_status=275)
            return _metadata(event, "service_health")["endpoint_healthy"]

        def failure() -> object:
            event = IntegrationsAuditService.log_webhook_failure(webhook, {"error_type": "server_error"})
            return (
                _metadata(event, "failure_analysis")["failure_severity"],
                _metadata(event, "failure_analysis")["retry_exhausted"],
                _metadata(event, "security_indicators")["repeated_failures"],
            )

        def exhaustion() -> object:
            event = IntegrationsAuditService.log_webhook_retry_exhausted(webhook, 2, "unavailable")
            return _metadata(event, "alerting_context")["escalation_needed"]

        cases: tuple[tuple[str, Callable[[], object], int, object], ...] = (
            ("search", search, 1, "high"),
            ("success", success, 1, False),
            ("failure", failure, 2, ("high", True, True)),
            ("exhaustion", exhaustion, 1, True),
        )
        with patch.object(AuditService, "log_event", side_effect=self.capture_event):
            for name, operation, reads, expected in cases:
                with self.subTest(operation=name):
                    with CaptureQueriesContext(connection) as queries:
                        observed = operation()
                    self.assertEqual(len(queries), 0 if warm else reads, name)
                    self.assertEqual(observed, expected, name)

    def test_warm_cache_has_zero_queries_and_configured_effects(self) -> None:
        self.assertTrue(connection.get_autocommit())
        # Seed the real warm cache without committing fixtures from SimpleTestCase.
        for key, value in HOT_VALUES.items():
            cache.set(SettingsService._get_cache_key(key), value, version=SettingsService.CACHE_VERSION)
        self.assert_query_budgets(warm=True)

    def test_atomic_reads_each_threshold_once_and_ignores_warm_cache(self) -> None:
        with transaction.atomic():
            for key, value in HOT_VALUES.items():
                result = SettingsService.update_setting(key, value)
                self.assertTrue(result.is_ok(), result)
                cache.set(
                    SettingsService._get_cache_key(key), AUDIT_DEFAULTS[key], version=SettingsService.CACHE_VERSION
                )
            try:
                self.assertFalse(connection.get_autocommit())
                self.assert_query_budgets(warm=False)
            finally:
                transaction.set_rollback(True)
