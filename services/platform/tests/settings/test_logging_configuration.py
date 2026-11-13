"""
Tests for LOGGING configuration structure across platform environments.

Validates that formatters, filters, handlers, and loggers are wired correctly
in each settings module — catching misconfiguration that would only surface at
runtime (e.g. handler referencing a non-existent formatter).
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import logging.config
import os
import sys
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

# Prod/staging settings run secret validation at import time.
# We provide dummy env vars so the import succeeds.
_PROD_ENV = {
    "DJANGO_SECRET_KEY": "test-only-secret-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "DB_PASSWORD": "test-only-db-password-for-logging-tests",
    "HMAC_SECRET": "test-only-hmac-secret-for-logging-tests",
    "DJANGO_ENCRYPTION_KEY": "dGVzdC1vbmx5LWVuY3J5cHRpb24ta2V5LTMyYnl0ZXM=",
    "ALLOWED_HOSTS": "localhost,127.0.0.1",
    "PORTAL_DOMAIN": "portal.test.local",
    "PLATFORM_DOMAIN": "platform.test.local",
    "PLATFORM_API_SECRET": "dGVzdC1vbmx5LXNlY3JldC1rZXktZm9yLWxvZ2dpbmctdGVzdHM=",
    "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "test-only-webhook-secret-for-logging-tests",
    "CREDENTIAL_VAULT_MASTER_KEY": "dGVzdC1vbmx5LXZhdWx0LWtleS1mb3ItbG9nZ2luZy10ZXN0cw==",
    "SENTRY_DSN": "",  # Disable Sentry during test imports (placeholder in .env triggers BadDsn)
    "REDIS_URL": "",  # Prod refuses a set REDIS_URL (ADR-0020); a host export must not leak in
    "PLATFORM_LOG_DIR": "/var/log/praho",  # The deployed default; empty would mean console only.
    "COMPANY_NAME": "Test Hosting SRL",  # Prod refuses a blank seller identity
    "COMPANY_CUI": "RO12345674",
    "COMPANY_COUNTRY_CODE": "RO",
}


def _get_logging(module_path: str) -> dict[str, Any]:
    """Import a settings module and return its LOGGING dict.

    Prod/staging modules validate secrets at import time. Since base.py
    hardcodes an insecure SECRET_KEY (not from env), we must bypass
    validate_production_secret_key() during import.
    """
    with (
        patch.dict(os.environ, _PROD_ENV),
        patch("config.settings.base.validate_production_secret_key"),
    ):
        mod = importlib.import_module(module_path)
    return mod.LOGGING


class _LoggingStructureMixin:
    """Shared assertions for LOGGING dict validation."""

    logging_config: dict[str, Any]

    def assert_formatters_exist(self, names: list[str]) -> None:
        formatters = self.logging_config.get("formatters", {})
        for name in names:
            assert name in formatters, f"Missing formatter: {name}"

    def assert_filters_exist(self, names: list[str]) -> None:
        filters = self.logging_config.get("filters", {})
        for name in names:
            assert name in filters, f"Missing filter: {name}"

    def assert_handlers_exist(self, names: list[str]) -> None:
        handlers = self.logging_config.get("handlers", {})
        for name in names:
            assert name in handlers, f"Missing handler: {name}"

    def assert_handler_wiring(self) -> None:
        """Every handler references an existing formatter and existing filters."""
        formatters = set(self.logging_config.get("formatters", {}).keys())
        filters = set(self.logging_config.get("filters", {}).keys())
        handlers = self.logging_config.get("handlers", {})

        for name, handler in handlers.items():
            if "formatter" in handler:
                assert handler["formatter"] in formatters, (
                    f"Handler '{name}' references unknown formatter '{handler['formatter']}'"
                )
            for f in handler.get("filters", []):
                assert f in filters, f"Handler '{name}' references unknown filter '{f}'"

    def assert_logger_wiring(self) -> None:
        """Every logger references existing handlers."""
        handlers = set(self.logging_config.get("handlers", {}).keys())
        loggers = self.logging_config.get("loggers", {})

        for name, logger_cfg in loggers.items():
            for h in logger_cfg.get("handlers", []):
                assert h in handlers, f"Logger '{name}' references unknown handler '{h}'"

    def assert_loggers_exist(self, names: list[str]) -> None:
        loggers = self.logging_config.get("loggers", {})
        for name in names:
            assert name in loggers, f"Missing logger: {name}"


class TestDevLoggingConfiguration(_LoggingStructureMixin, SimpleTestCase):
    """Validate platform dev LOGGING configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.logging_config = _get_logging("config.settings.dev")

    def test_has_colorlog_formatter(self) -> None:
        self.assert_formatters_exist(["unified"])
        fmt = self.logging_config["formatters"]["unified"]
        self.assertEqual(fmt["()"], "colorlog.ColoredFormatter")

    def test_format_contains_service_name(self) -> None:
        fmt = self.logging_config["formatters"]["unified"]
        self.assertIn("{service_name}", fmt["format"])

    def test_has_required_filters(self) -> None:
        self.assert_filters_exist(["add_request_id", "add_service_name"])

    def test_service_name_is_plat(self) -> None:
        filter_cfg = self.logging_config["filters"]["add_service_name"]
        self.assertEqual(filter_cfg["service_name"], "PLAT")

    def test_handler_wiring(self) -> None:
        self.assert_handler_wiring()

    def test_logger_wiring(self) -> None:
        self.assert_logger_wiring()

    def test_has_required_loggers(self) -> None:
        self.assert_loggers_exist(["django", "django.server", "apps"])


class TestProdLoggingConfiguration(_LoggingStructureMixin, SimpleTestCase):
    """Validate platform prod LOGGING configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.logging_config = _get_logging("config.settings.prod")

    def test_has_siem_json_formatter(self) -> None:
        self.assert_formatters_exist(["json", "verbose", "audit"])
        self.assertEqual(
            self.logging_config["formatters"]["json"]["()"],
            "apps.audit.logging_formatters.SIEMJSONFormatter",
        )

    def test_has_required_filters(self) -> None:
        self.assert_filters_exist(["add_request_id", "add_audit_context"])

    def test_has_required_handlers(self) -> None:
        self.assert_handlers_exist(["console", "file", "security_file", "audit_file", "error_file"])

    def test_console_has_both_filters(self) -> None:
        console = self.logging_config["handlers"]["console"]
        self.assertIn("add_request_id", console["filters"])
        self.assertIn("add_audit_context", console["filters"])

    def test_handler_wiring(self) -> None:
        self.assert_handler_wiring()

    def test_logger_wiring(self) -> None:
        self.assert_logger_wiring()

    def test_has_required_loggers(self) -> None:
        self.assert_loggers_exist(["django", "django.security", "django.request", "apps"])


class TestStagingLoggingConfiguration(_LoggingStructureMixin, SimpleTestCase):
    """Validate platform staging LOGGING configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.logging_config = _get_logging("config.settings.staging")

    def test_mirrors_prod_formatters(self) -> None:
        self.assert_formatters_exist(["json", "verbose", "audit"])

    def test_mirrors_prod_filters(self) -> None:
        self.assert_filters_exist(["add_request_id", "add_audit_context"])

    def test_mirrors_prod_handlers(self) -> None:
        self.assert_handlers_exist(["console", "file", "security_file", "audit_file", "error_file"])

    def test_handler_wiring(self) -> None:
        self.assert_handler_wiring()

    def test_logger_wiring(self) -> None:
        self.assert_logger_wiring()

    def test_has_required_loggers(self) -> None:
        self.assert_loggers_exist(["django", "django.security", "django.request", "apps"])

    def test_retention_is_left_to_logrotate(self) -> None:
        # Several processes write these files, so neither environment rotates them in process (one
        # process renaming a file under the others drops records); the native role's logrotate
        # policy sets retention, and the handlers reopen a moved file (config/settings/log_files.py).
        prod = _get_logging("config.settings.prod")
        for config in (self.logging_config, prod):
            for name in ("file", "security_file", "audit_file", "error_file"):
                handler = config["handlers"][name]
                self.assertEqual(handler["class"], "logging.handlers.WatchedFileHandler")
                self.assertNotIn("maxBytes", handler)
                self.assertNotIn("backupCount", handler)


class SecretURLFilterWiringTests(SimpleTestCase):
    """Production and staging install the secret-URL filter on every handler (#751 follow-up, M6b)."""

    def test_every_deployed_handler_redacts_secret_urls(self) -> None:
        for module in ("config.settings.prod", "config.settings.staging"):
            with self.subTest(module=module):
                config = _get_logging(module)
                self.assertEqual(config["filters"]["secret_urls"]["()"], "apps.common.secret_urls.SecretURLFilter")
                self.assertTrue(config["handlers"], "handlers are configured")
                for name, handler in config["handlers"].items():
                    self.assertIn("secret_urls", handler.get("filters", []), f"{module}: handler {name}")


SENSITIVE_VALUES = (
    "Hunter2-pw",
    "RO76543210",
    "76543217",
    "4111111111111111",
    "first-secret",
    "second-secret",
    "nested-secret",
    "tuple-secret",
    "quote-secret",
    "horse battery",
    "extra-secret",
    "key-secret",
)


def _deployed_handler_output(config: dict[str, Any], handler_name: str, record: logging.LogRecord) -> str:
    """What one configured handler writes for a record: its own filters and formatter, a stream instead of a file.

    The filters and formatter are built the way dictConfig builds them, without dictConfig itself, which would
    replace the test run's own logging.
    """
    spec = config["handlers"][handler_name]
    configurator = logging.config.DictConfigurator(config)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    for name in spec.get("filters", []):
        handler.addFilter(configurator.configure_filter(dict(config["filters"][name])))
    if "formatter" in spec:
        handler.setFormatter(configurator.configure_formatter(dict(config["formatters"][spec["formatter"]])))
    handler.handle(record)
    return stream.getvalue()


def _records() -> dict[str, logging.LogRecord]:
    def record(message: str, args: tuple[object, ...] = (), exc_info: Any = None) -> logging.LogRecord:
        return logging.LogRecord("apps.users", logging.ERROR, __file__, 1, message, args, exc_info)

    try:
        raise ValueError("charge failed card_number=4111111111111111 password=Hunter2-pw")
    except ValueError:
        failure = sys.exc_info()
    extras = record("update")
    extras.password = "extra-secret"
    extras.query = {"card_number": ["4111111111111111"], "page": "2", "password=key-secret": 1}
    extras.session_note = "visible-note"
    return {
        "key=value": record("login failed password=Hunter2-pw vat_number=RO76543210 cui=76543217"),
        "list value": record("{'password': ['first-secret', 'second-secret']}"),
        "nested dict value": record("{'token': {'value': 'nested-secret'}}"),
        "tuple value": record("{'password': ('tuple-secret-1', 'tuple-secret-2')}"),
        "escaped quote": record('password="has\\"quote-secret"'),
        "structured args": record("profile %s", ({"password": ["first-secret"], "token": {"value": "nested-secret"}},)),
        "spaced value": record("password: correct horse battery"),
        "database detail": record("Key (vat_number)=(RO76543210) already exists."),
        "extras": extras,
        "dict-like text": record("{'password': 'Hunter2-pw', \"card_number\": \"4111111111111111\", 'cui': 76543217}"),
        "record.args": record("profile %s", ({"vat_number": "RO76543210", "password": "Hunter2-pw"},)),
        "exception text": record("payment error", (), failure),
    }


class SensitiveDataRedactionTests(SimpleTestCase):
    """Every configured handler, in every environment, writes a sensitive key's value as [REDACTED]."""

    def test_every_handler_redacts_sensitive_values(self) -> None:
        for module in ("config.settings.dev", "config.settings.staging", "config.settings.prod"):
            config = _get_logging(module)
            for handler_name in config["handlers"]:
                for shape, record in _records().items():
                    with self.subTest(module=module, handler=handler_name, shape=shape):
                        output = _deployed_handler_output(config, handler_name, record)
                        # A formatter may write no exception, or no extras; where it writes them, they're redacted.
                        written = {"exception text": "ValueError", "extras": "visible-note"}.get(shape)
                        if written is None or written in output:
                            self.assertIn("[REDACTED]", output)
                        if output.startswith("{"):
                            json.loads(output)  # still one valid JSON line
                        for value in SENSITIVE_VALUES:
                            self.assertNotIn(value, output)

    def test_ordinary_words_are_left_alone(self) -> None:
        config = _get_logging("config.settings.prod")
        record = logging.LogRecord("apps.users", logging.INFO, __file__, 1, "Password changed for %s", ("ana",), None)
        output = _deployed_handler_output(config, "console", record)
        self.assertIn("Password changed for ana", output)
        self.assertNotIn("[REDACTED]", output)

    def test_audit_middleware_query_parameters_are_redacted(self) -> None:
        """AuditMiddleware logs a request's query as an extra (a dict of lists); production writes none of its secrets."""
        from django.contrib.auth.models import AnonymousUser  # noqa: PLC0415
        from django.http import HttpResponse  # noqa: PLC0415
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.common.middleware import AuditMiddleware  # noqa: PLC0415

        request = RequestFactory().get(
            "/customers/", {"token": "tok-secret", "card_number": "4111111111111111", "q": "ana"}
        )
        request.user = AnonymousUser()
        with self.assertLogs("apps.common.middleware", level="INFO") as captured:
            AuditMiddleware(lambda _request: HttpResponse("ok"))(request)
        record = next(record for record in captured.records if getattr(record, "event", "") == "request")
        output = _deployed_handler_output(_get_logging("config.settings.prod"), "console", record)
        self.assertNotIn("tok-secret", output)
        self.assertNotIn("4111111111111111", output)
        self.assertIn('"q": ["ana"]', output)
