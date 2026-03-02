"""
Tests for apps.audit.logging_formatters

Coverage target: 90%+

These are pure Python tests with no database access.
Uses Django SimpleTestCase to avoid DB overhead.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.audit.logging_formatters import (
    AuditContextFilter,
    AuditLogFormatter,
    ComplianceLogFormatter,
    RequestIDFilter,
    SIEMJSONFormatter,
    clear_audit_context,
    get_audit_context,
    set_audit_context,
)

# =============================================================================
# HELPERS
# =============================================================================


def make_record(
    name: str = "apps.some.views",
    level: int = logging.INFO,
    msg: str = "Test message",
    func_name: str = "test_func",
    exc_info: Any = None,
    **kwargs: Any,
) -> logging.LogRecord:
    """Create a LogRecord and optionally attach extra attributes."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=(),
        exc_info=exc_info,
    )
    record.funcName = func_name
    for key, value in kwargs.items():
        setattr(record, key, value)
    return record


# =============================================================================
# THREAD-LOCAL AUDIT CONTEXT
# =============================================================================


class TestSetGetAuditContext(SimpleTestCase):
    """Tests for set_audit_context / get_audit_context."""

    def tearDown(self) -> None:
        clear_audit_context()

    def test_get_all_none_when_nothing_set(self) -> None:
        ctx = get_audit_context()
        for key in ("request_id", "user_id", "user_email", "ip_address", "session_id", "customer_id"):
            self.assertIsNone(ctx[key])

    def test_set_then_get_returns_values(self) -> None:
        set_audit_context(request_id="req-1", user_id=42, user_email="a@b.com")
        ctx = get_audit_context()
        self.assertEqual(ctx["request_id"], "req-1")
        self.assertEqual(ctx["user_id"], 42)
        self.assertEqual(ctx["user_email"], "a@b.com")

    def test_partial_set_leaves_others_none(self) -> None:
        set_audit_context(ip_address="1.2.3.4")
        ctx = get_audit_context()
        self.assertEqual(ctx["ip_address"], "1.2.3.4")
        self.assertIsNone(ctx["user_id"])
        self.assertIsNone(ctx["session_id"])

    def test_set_all_fields(self) -> None:
        set_audit_context(
            request_id="r",
            user_id=1,
            user_email="x@y.com",
            ip_address="10.0.0.1",
            session_id="sess-abc",
            customer_id=99,
        )
        ctx = get_audit_context()
        self.assertEqual(ctx["request_id"], "r")
        self.assertEqual(ctx["user_id"], 1)
        self.assertEqual(ctx["user_email"], "x@y.com")
        self.assertEqual(ctx["ip_address"], "10.0.0.1")
        self.assertEqual(ctx["session_id"], "sess-abc")
        self.assertEqual(ctx["customer_id"], 99)

    def test_overwrite_existing_value(self) -> None:
        set_audit_context(user_id=1)
        set_audit_context(user_id=2)
        self.assertEqual(get_audit_context()["user_id"], 2)

    def test_context_is_thread_local(self) -> None:
        """Values set in another thread are not visible in the current thread."""
        set_audit_context(request_id="main-thread")

        results: dict[str, Any] = {}

        def worker() -> None:
            results["worker_ctx"] = get_audit_context()

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        # Worker should see None because it's a different thread
        self.assertIsNone(results["worker_ctx"]["request_id"])


class TestClearAuditContext(SimpleTestCase):
    """Tests for clear_audit_context."""

    def tearDown(self) -> None:
        clear_audit_context()

    def test_clear_removes_set_values(self) -> None:
        set_audit_context(request_id="x", user_id=5, ip_address="127.0.0.1")
        clear_audit_context()
        ctx = get_audit_context()
        for value in ctx.values():
            self.assertIsNone(value)

    def test_clear_when_nothing_set_does_not_raise(self) -> None:
        # Should be idempotent - clear on clean state
        clear_audit_context()
        clear_audit_context()
        ctx = get_audit_context()
        self.assertIsNone(ctx["user_id"])

    def test_clear_partial_context(self) -> None:
        set_audit_context(session_id="s1")
        clear_audit_context()
        self.assertIsNone(get_audit_context()["session_id"])


# =============================================================================
# AuditContextFilter
# =============================================================================


class TestAuditContextFilter(SimpleTestCase):
    """Tests for AuditContextFilter.filter()."""

    def setUp(self) -> None:
        self.filter = AuditContextFilter()

    def tearDown(self) -> None:
        clear_audit_context()

    def test_filter_always_returns_true(self) -> None:
        record = make_record()
        result = self.filter.filter(record)
        self.assertTrue(result)

    def test_filter_adds_all_context_fields(self) -> None:
        set_audit_context(
            request_id="req-xyz",
            user_id=7,
            user_email="u@example.com",
            ip_address="192.168.1.1",
            session_id="sess-99",
            customer_id=3,
        )
        record = make_record()
        self.filter.filter(record)

        self.assertEqual(record.request_id, "req-xyz")
        self.assertEqual(record.user_id, 7)
        self.assertEqual(record.user_email, "u@example.com")
        self.assertEqual(record.ip_address, "192.168.1.1")
        self.assertEqual(record.session_id, "sess-99")
        self.assertEqual(record.customer_id, 3)

    def test_filter_uses_dash_for_missing_context(self) -> None:
        """When context is empty, filter should use 36-dash placeholder as fallback."""
        record = make_record()
        self.filter.filter(record)
        self.assertEqual(record.request_id, "-" * 36)

    def test_filter_adds_hostname(self) -> None:
        record = make_record()
        self.filter.filter(record)
        self.assertTrue(hasattr(record, "hostname"))
        self.assertIsInstance(record.hostname, str)
        self.assertGreater(len(record.hostname), 0)

    def test_filter_adds_environment(self) -> None:
        record = make_record()
        self.filter.filter(record)
        self.assertTrue(hasattr(record, "environment"))

    def test_filter_environment_from_settings(self) -> None:
        with patch("apps.audit.logging_formatters.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "staging"
            record = make_record()
            self.filter.filter(record)
            self.assertEqual(record.environment, "staging")

    def test_filter_environment_default_production(self) -> None:
        with patch("apps.audit.logging_formatters.settings") as mock_settings:
            del mock_settings.ENVIRONMENT  # simulate missing attribute
            mock_settings.__spec__ = None
            # Use getattr default path
            record = make_record()
            self.filter.filter(record)
            # environment should be set (default "production")
            self.assertTrue(hasattr(record, "environment"))


# =============================================================================
# RequestIDFilter
# =============================================================================


class TestRequestIDFilter(SimpleTestCase):
    """Tests for RequestIDFilter.filter()."""

    def setUp(self) -> None:
        self.filter = RequestIDFilter()

    def tearDown(self) -> None:
        clear_audit_context()

    def test_filter_always_returns_true(self) -> None:
        record = make_record()
        self.assertTrue(self.filter.filter(record))

    def test_adds_request_id_when_absent(self) -> None:
        set_audit_context(request_id="req-from-context")
        record = make_record()
        # Ensure record does NOT already have request_id
        self.assertFalse(hasattr(record, "request_id"))
        self.filter.filter(record)
        self.assertEqual(record.request_id, "req-from-context")

    def test_does_not_overwrite_existing_request_id(self) -> None:
        set_audit_context(request_id="context-id")
        record = make_record(request_id="existing-id")
        self.filter.filter(record)
        self.assertEqual(record.request_id, "existing-id")

    def test_request_id_dash_when_context_empty(self) -> None:
        record = make_record()
        self.filter.filter(record)
        self.assertEqual(record.request_id, "-" * 36)


# =============================================================================
# SIEMJSONFormatter
# =============================================================================


class TestSIEMJSONFormatterFormat(SimpleTestCase):
    """Tests for SIEMJSONFormatter.format()."""

    def setUp(self) -> None:
        self.formatter = SIEMJSONFormatter()

    def _format_and_parse(self, record: logging.LogRecord) -> dict[str, Any]:
        output = self.formatter.format(record)
        return json.loads(output)

    def test_output_is_valid_json(self) -> None:
        record = make_record()
        output = self.formatter.format(record)
        data = json.loads(output)
        self.assertIsInstance(data, dict)

    def test_required_top_level_keys(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        for key in ("@timestamp", "event", "log", "host", "service", "message", "process"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_message_matches_record_message(self) -> None:
        record = make_record(msg="Hello world")
        data = self._format_and_parse(record)
        self.assertEqual(data["message"], "Hello world")

    def test_log_level_is_lowercase(self) -> None:
        record = make_record(level=logging.WARNING)
        data = self._format_and_parse(record)
        self.assertEqual(data["log"]["level"], "warning")

    def test_timestamp_ends_with_z(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        self.assertTrue(data["@timestamp"].endswith("Z"))

    def test_service_name_is_praho_platform(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        self.assertEqual(data["service"]["name"], "praho-platform")
        self.assertEqual(data["service"]["type"], "django")

    def test_error_key_absent_when_no_exc_info(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        self.assertNotIn("error", data)

    def test_error_key_present_with_exc_info(self) -> None:
        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()

        record = make_record(exc_info=exc_info)
        data = self._format_and_parse(record)
        self.assertIn("error", data)
        self.assertEqual(data["error"]["type"], "ValueError")
        self.assertEqual(data["error"]["message"], "boom")
        self.assertIn("ValueError", data["error"]["stack_trace"])


class TestSIEMJSONFormatterEventCategory(SimpleTestCase):
    """Tests for SIEMJSONFormatter._get_event_category()."""

    def setUp(self) -> None:
        self.formatter = SIEMJSONFormatter()

    def _category(self, logger_name: str) -> str:
        record = make_record(name=logger_name)
        return self.formatter._get_event_category(record)

    def test_auth_logger(self) -> None:
        self.assertEqual(self._category("apps.auth.views"), "authentication")

    def test_user_logger(self) -> None:
        self.assertEqual(self._category("apps.users.services"), "authentication")

    def test_login_logger(self) -> None:
        self.assertEqual(self._category("apps.login.handler"), "authentication")

    def test_security_logger(self) -> None:
        self.assertEqual(self._category("apps.security.monitor"), "security")

    def test_audit_logger(self) -> None:
        self.assertEqual(self._category("apps.audit.trail"), "audit")

    def test_database_logger(self) -> None:
        self.assertEqual(self._category("django.database.query"), "database")

    def test_db_shorthand_logger(self) -> None:
        self.assertEqual(self._category("apps.db.cache"), "database")

    def test_web_logger(self) -> None:
        self.assertEqual(self._category("apps.web.frontend"), "web")

    def test_request_logger(self) -> None:
        self.assertEqual(self._category("django.request"), "web")

    def test_file_logger(self) -> None:
        self.assertEqual(self._category("apps.file.storage"), "file")

    def test_network_logger(self) -> None:
        self.assertEqual(self._category("apps.network.client"), "network")

    def test_default_category(self) -> None:
        self.assertEqual(self._category("apps.billing.services"), "process")


class TestSIEMJSONFormatterEventType(SimpleTestCase):
    """Tests for SIEMJSONFormatter._get_event_type()."""

    def setUp(self) -> None:
        self.formatter = SIEMJSONFormatter()

    def _event_type(self, level: int) -> str:
        record = make_record(level=level)
        return self.formatter._get_event_type(record)

    def test_error_level(self) -> None:
        self.assertEqual(self._event_type(logging.ERROR), "error")

    def test_critical_level(self) -> None:
        self.assertEqual(self._event_type(logging.CRITICAL), "error")

    def test_warning_level(self) -> None:
        self.assertEqual(self._event_type(logging.WARNING), "info")

    def test_info_level(self) -> None:
        self.assertEqual(self._event_type(logging.INFO), "info")

    def test_debug_level(self) -> None:
        self.assertEqual(self._event_type(logging.DEBUG), "info")


class TestSIEMJSONFormatterFormatException(SimpleTestCase):
    """Tests for SIEMJSONFormatter._format_exception()."""

    def setUp(self) -> None:
        self.formatter = SIEMJSONFormatter()

    def test_no_exc_info_returns_empty_dict(self) -> None:
        record = make_record()
        result = self.formatter._format_exception(record)
        self.assertEqual(result, {})

    def test_exc_info_none_type_returns_empty_dict(self) -> None:
        record = make_record(exc_info=(None, None, None))
        result = self.formatter._format_exception(record)
        self.assertEqual(result, {})

    def test_exc_info_with_exception(self) -> None:
        try:
            raise RuntimeError("test error")
        except RuntimeError:
            exc_info = sys.exc_info()

        record = make_record(exc_info=exc_info)
        result = self.formatter._format_exception(record)
        self.assertEqual(result["type"], "RuntimeError")
        self.assertEqual(result["message"], "test error")
        self.assertIn("RuntimeError", result["stack_trace"])

    def test_exc_info_without_traceback(self) -> None:
        """exc_info tuple with type and value but no traceback."""
        exc_type = ValueError
        exc_value = ValueError("no tb")
        record = make_record(exc_info=(exc_type, exc_value, None))
        result = self.formatter._format_exception(record)
        self.assertEqual(result["type"], "ValueError")
        self.assertEqual(result["message"], "no tb")
        self.assertEqual(result["stack_trace"], "")


class TestSIEMJSONFormatterExtractExtraFields(SimpleTestCase):
    """Tests for SIEMJSONFormatter._extract_extra_fields()."""

    def setUp(self) -> None:
        self.formatter = SIEMJSONFormatter()

    def test_no_extra_fields_returns_empty_dict(self) -> None:
        record = make_record()
        result = self.formatter._extract_extra_fields(record)
        self.assertEqual(result, {})

    def test_custom_attribute_included_in_extra(self) -> None:
        record = make_record(order_id=123, action="payment")
        result = self.formatter._extract_extra_fields(record)
        self.assertIn("extra", result)
        self.assertEqual(result["extra"]["order_id"], 123)
        self.assertEqual(result["extra"]["action"], "payment")

    def test_private_attributes_excluded(self) -> None:
        record = make_record()
        record.__dict__["_private"] = "secret"
        result = self.formatter._extract_extra_fields(record)
        extra = result.get("extra", {})
        self.assertNotIn("_private", extra)

    def test_standard_attrs_not_in_extra(self) -> None:
        record = make_record()
        result = self.formatter._extract_extra_fields(record)
        # Standard attributes should not leak into extra
        extra = result.get("extra", {})
        for standard in ("name", "msg", "levelname", "lineno", "process"):
            self.assertNotIn(standard, extra)

    def test_format_includes_extra_in_json(self) -> None:
        record = make_record(invoice_id="INV-001")
        output = self.formatter.format(record)
        data = json.loads(output)
        self.assertIn("extra", data)
        self.assertEqual(data["extra"]["invoice_id"], "INV-001")


# =============================================================================
# AuditLogFormatter
# =============================================================================


class TestAuditLogFormatterFormat(SimpleTestCase):
    """Tests for AuditLogFormatter.format()."""

    def setUp(self) -> None:
        self.formatter = AuditLogFormatter()

    def _format_and_parse(self, record: logging.LogRecord) -> dict[str, Any]:
        output = self.formatter.format(record)
        return json.loads(output)

    def test_output_is_valid_json(self) -> None:
        record = make_record()
        output = self.formatter.format(record)
        self.assertIsInstance(json.loads(output), dict)

    def test_required_keys_present(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        for key in ("@timestamp", "sequence", "event", "message", "log", "host", "integrity"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_integrity_hash_present(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        self.assertIn("hash", data["integrity"])
        self.assertIsInstance(data["integrity"]["hash"], str)
        self.assertEqual(len(data["integrity"]["hash"]), 64)  # SHA-256 hex digest

    def test_sequence_increments(self) -> None:
        r1 = make_record(msg="first")
        r2 = make_record(msg="second")
        d1 = self._format_and_parse(r1)
        d2 = self._format_and_parse(r2)
        self.assertEqual(d1["sequence"], 1)
        self.assertEqual(d2["sequence"], 2)

    def test_hash_chain_second_record_uses_first_hash(self) -> None:
        r1 = make_record(msg="first")
        r2 = make_record(msg="second")
        d1 = self._format_and_parse(r1)
        d2 = self._format_and_parse(r2)
        self.assertEqual(d2["integrity"]["previous_hash"], d1["integrity"]["hash"])

    def test_first_record_previous_hash_is_empty(self) -> None:
        formatter = AuditLogFormatter()  # fresh instance
        record = make_record()
        data = json.loads(formatter.format(record))
        self.assertEqual(data["integrity"]["previous_hash"], "")

    def test_outcome_success_for_info(self) -> None:
        record = make_record(level=logging.INFO)
        data = self._format_and_parse(record)
        self.assertEqual(data["event"]["outcome"], "success")

    def test_outcome_failure_for_error(self) -> None:
        record = make_record(level=logging.ERROR)
        data = self._format_and_parse(record)
        self.assertEqual(data["event"]["outcome"], "failure")


class TestAuditLogFormatterDetermineCategory(SimpleTestCase):
    """Tests for AuditLogFormatter._determine_category()."""

    def setUp(self) -> None:
        self.formatter = AuditLogFormatter()

    def _category(self, msg: str) -> str:
        return self.formatter._determine_category(make_record(msg=msg))

    def test_login_message(self) -> None:
        self.assertEqual(self._category("User login successful"), "authentication")

    def test_logout_message(self) -> None:
        self.assertEqual(self._category("User logout event"), "authentication")

    def test_auth_message(self) -> None:
        self.assertEqual(self._category("auth token validated"), "authentication")

    def test_permission_message(self) -> None:
        self.assertEqual(self._category("permission denied"), "authorization")

    def test_role_message(self) -> None:
        self.assertEqual(self._category("role assigned to user"), "authorization")

    def test_access_message(self) -> None:
        self.assertEqual(self._category("access granted"), "authorization")

    def test_create_message(self) -> None:
        self.assertEqual(self._category("create invoice"), "data_modification")

    def test_update_message(self) -> None:
        self.assertEqual(self._category("update customer profile"), "data_modification")

    def test_delete_message(self) -> None:
        self.assertEqual(self._category("delete record"), "data_modification")

    def test_security_message(self) -> None:
        self.assertEqual(self._category("security alert raised"), "security_event")

    def test_breach_message(self) -> None:
        self.assertEqual(self._category("breach detected"), "security_event")

    def test_attack_message(self) -> None:
        self.assertEqual(self._category("attack pattern found"), "security_event")

    def test_export_message(self) -> None:
        self.assertEqual(self._category("data export completed"), "data_access")

    def test_download_message(self) -> None:
        self.assertEqual(self._category("file download started"), "data_access")

    def test_config_message(self) -> None:
        self.assertEqual(self._category("config changed"), "configuration")

    def test_setting_message(self) -> None:
        # "update" would match data_modification first, use a message without it
        self.assertEqual(self._category("setting changed for module"), "configuration")

    def test_default_category(self) -> None:
        self.assertEqual(self._category("something unrelated happened"), "general")


# =============================================================================
# ComplianceLogFormatter
# =============================================================================


class TestComplianceLogFormatterFormat(SimpleTestCase):
    """Tests for ComplianceLogFormatter.format()."""

    def setUp(self) -> None:
        self.formatter = ComplianceLogFormatter()

    def _format_and_parse(self, record: logging.LogRecord) -> dict[str, Any]:
        output = self.formatter.format(record)
        return json.loads(output)

    def test_output_is_valid_json(self) -> None:
        record = make_record()
        output = self.formatter.format(record)
        self.assertIsInstance(json.loads(output), dict)

    def test_required_top_level_keys(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        for key in ("@timestamp", "compliance", "event", "message", "log", "user", "source", "trace"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_compliance_block_structure(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        comp = data["compliance"]
        self.assertIn("frameworks", comp)
        self.assertIn("category", comp)
        self.assertIn("retention_required", comp)
        self.assertIn("sensitive_data", comp)
        self.assertTrue(comp["retention_required"])

    def test_timestamp_ends_with_z(self) -> None:
        record = make_record()
        data = self._format_and_parse(record)
        self.assertTrue(data["@timestamp"].endswith("Z"))

    def test_authentication_frameworks(self) -> None:
        record = make_record(msg="User login attempt")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("ISO27001-A.9.4", frameworks)
        self.assertIn("SOC2-CC6.1", frameworks)
        self.assertIn("GDPR-Art32", frameworks)

    def test_authorization_frameworks(self) -> None:
        record = make_record(msg="Permission check for role")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("ISO27001-A.9.2", frameworks)
        self.assertIn("SOC2-CC6.2", frameworks)

    def test_data_modification_frameworks(self) -> None:
        record = make_record(msg="create new record")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("GDPR-Art30", frameworks)
        self.assertIn("ISO27001-A.12.4", frameworks)

    def test_security_event_frameworks(self) -> None:
        record = make_record(msg="security breach detected")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("ISO27001-A.16", frameworks)
        self.assertIn("SOC2-CC7.2", frameworks)

    def test_data_access_frameworks(self) -> None:
        record = make_record(msg="data export completed")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("GDPR-Art15", frameworks)

    def test_configuration_frameworks(self) -> None:
        # Avoid "update" which matches data_modification first
        record = make_record(msg="config saved for module")
        data = self._format_and_parse(record)
        frameworks = data["compliance"]["frameworks"]
        self.assertIn("ISO27001-A.12.1", frameworks)
        self.assertIn("SOC2-CC6.6", frameworks)

    def test_general_category_empty_frameworks(self) -> None:
        record = make_record(msg="something happened")
        data = self._format_and_parse(record)
        self.assertEqual(data["compliance"]["frameworks"], [])

    def test_outcome_success_for_non_error(self) -> None:
        record = make_record(level=logging.INFO)
        data = self._format_and_parse(record)
        self.assertEqual(data["event"]["outcome"], "success")

    def test_outcome_failure_for_error(self) -> None:
        record = make_record(level=logging.ERROR)
        data = self._format_and_parse(record)
        self.assertEqual(data["event"]["outcome"], "failure")


class TestComplianceLogFormatterDetermineCategory(SimpleTestCase):
    """Tests for ComplianceLogFormatter._determine_category()."""

    def setUp(self) -> None:
        self.formatter = ComplianceLogFormatter()

    def _category(self, msg: str) -> str:
        return self.formatter._determine_category(make_record(msg=msg))

    def test_login(self) -> None:
        self.assertEqual(self._category("login attempt"), "authentication")

    def test_logout(self) -> None:
        self.assertEqual(self._category("logout event"), "authentication")

    def test_auth(self) -> None:
        self.assertEqual(self._category("auth failed"), "authentication")

    def test_permission(self) -> None:
        self.assertEqual(self._category("permission denied"), "authorization")

    def test_role(self) -> None:
        self.assertEqual(self._category("role changed"), "authorization")

    def test_access(self) -> None:
        self.assertEqual(self._category("access revoked"), "authorization")

    def test_create(self) -> None:
        self.assertEqual(self._category("create entity"), "data_modification")

    def test_update(self) -> None:
        self.assertEqual(self._category("update entity"), "data_modification")

    def test_delete(self) -> None:
        self.assertEqual(self._category("delete entity"), "data_modification")

    def test_security(self) -> None:
        self.assertEqual(self._category("security event"), "security_event")

    def test_breach(self) -> None:
        self.assertEqual(self._category("breach occurred"), "security_event")

    def test_export(self) -> None:
        self.assertEqual(self._category("export data"), "data_access")

    def test_download(self) -> None:
        self.assertEqual(self._category("download report"), "data_access")

    def test_config(self) -> None:
        self.assertEqual(self._category("config saved"), "configuration")

    def test_setting(self) -> None:
        self.assertEqual(self._category("setting changed"), "configuration")

    def test_general_default(self) -> None:
        self.assertEqual(self._category("routine check"), "general")


class TestComplianceLogFormatterContainsSensitiveData(SimpleTestCase):
    """Tests for ComplianceLogFormatter._contains_sensitive_data()."""

    def setUp(self) -> None:
        self.formatter = ComplianceLogFormatter()

    def _sensitive(self, msg: str) -> bool:
        return self.formatter._contains_sensitive_data(make_record(msg=msg))

    def test_password_indicator(self) -> None:
        self.assertTrue(self._sensitive("Reset password for user"))

    def test_credit_indicator(self) -> None:
        self.assertTrue(self._sensitive("credit card number"))

    def test_card_indicator(self) -> None:
        self.assertTrue(self._sensitive("card details updated"))

    def test_ssn_indicator(self) -> None:
        self.assertTrue(self._sensitive("SSN provided"))

    def test_tax_indicator(self) -> None:
        self.assertTrue(self._sensitive("tax ID validation"))

    def test_cui_indicator(self) -> None:
        self.assertTrue(self._sensitive("CUI lookup for RO12345678"))

    def test_bank_indicator(self) -> None:
        self.assertTrue(self._sensitive("bank details saved"))

    def test_account_indicator(self) -> None:
        self.assertTrue(self._sensitive("account number changed"))

    def test_secret_indicator(self) -> None:
        self.assertTrue(self._sensitive("secret key rotated"))

    def test_token_indicator(self) -> None:
        self.assertTrue(self._sensitive("token generated"))

    def test_key_indicator(self) -> None:
        self.assertTrue(self._sensitive("api key issued"))

    def test_credential_indicator(self) -> None:
        self.assertTrue(self._sensitive("credential stored"))

    def test_normal_message_not_sensitive(self) -> None:
        self.assertFalse(self._sensitive("User login successful"))

    def test_empty_message_not_sensitive(self) -> None:
        self.assertFalse(self._sensitive(""))

    def test_unrelated_message_not_sensitive(self) -> None:
        self.assertFalse(self._sensitive("Invoice generated for customer"))

    def test_case_insensitive_detection(self) -> None:
        self.assertTrue(self._sensitive("PASSWORD must be changed"))
        self.assertTrue(self._sensitive("User TOKEN expired"))
