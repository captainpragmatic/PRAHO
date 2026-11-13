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
    "bearer-secret",
    "tkeepsecret",
    "beta-secret",
    "byte-secret",
    "object-secret",
    "byte-key-secret",
    "spaced-bearer-secret",
    "whole-secret",
    "nested-json-secret",
    "stack-secret",
    "cached-exc-secret",
    "cli-secret",
    "suffix-secret",
)


class _Labelled:
    """An object a formatter can only write as text, which carries a secret when it does."""

    def __str__(self) -> str:
        return "password=object-secret"


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
    stack = record("lookup failed")
    stack.stack_info = "Stack (most recent call last):\n  check(password=stack-secret)"
    stack.exc_text = "Traceback: cached password=cached-exc-secret"
    extras = record("update")
    extras.password = "extra-secret"
    extras.query = {"card_number": ["4111111111111111"], "page": "2", "password=key-secret": 1}
    extras.session_note = "visible-note"
    extras.payload = b"password=byte-secret"
    extras.label = _Labelled()
    extras.headers = {b"password": "byte-key-secret"}
    return {
        "key=value": record("login failed password=Hunter2-pw vat_number=RO76543210 cui=76543217"),
        "list value": record("{'password': ['first-secret', 'second-secret']}"),
        "nested dict value": record("{'token': {'value': 'nested-secret'}}"),
        "tuple value": record("{'password': ('tuple-secret-1', 'tuple-secret-2')}"),
        "escaped quote": record('password="has\\"quote-secret"'),
        "structured args": record("profile %s", ({"password": ["first-secret"], "token": {"value": "nested-secret"}},)),
        "spaced value": record("password: correct horse battery"),
        "database detail": record("Key (vat_number)=(RO76543210) already exists."),
        "authorization scheme": record("upstream refused Authorization=Bearer bearer-secret retry=1"),
        "apostrophe": record("password=can'tkeepsecret"),
        "authorization spacing": record("Authorization=Bearer \t  spaced-bearer-secret next=1"),
        "colon list": record("password: alpha,beta-secret"),
        "leading delimiter": record("password=;whole-secret"),
        "spaced equals": record("password=correct horse battery"),
        "nested json": record(json.dumps({"error": json.dumps({"password": "nested-json-secret"})})),
        "command line": record("ran tool --password=cli-secret --verbose; also {'--token': 'cli-secret'}"),
        "nested json inner quote": record(json.dumps({"error": json.dumps({"password": 'prefix"suffix-secret'})})),
        "stack and cached exception": stack,
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
                        # The record itself is clean too, whatever this formatter happens to write (exc_info keeps the
                        # original exception object for formatters that need it; its text lives in exc_text).
                        attributes = repr({k: v for k, v in vars(record).items() if k != "exc_info"})
                        self.assertEqual([value for value in SENSITIVE_VALUES if value in attributes], [])
                        # A formatter may write no exception, or no extras; where it writes them, they're redacted.
                        written = {
                            "exception text": "ValueError",
                            "extras": "visible-note",
                            "stack and cached exception": "most recent call last",
                        }.get(shape)
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

    def test_a_failed_redaction_withholds_every_extra(self) -> None:
        """When walking one extra fails, no later extra may reach a handler unredacted."""

        class Exploding(dict):
            def items(self) -> Any:
                raise RuntimeError("changed during iteration")

        record = logging.LogRecord("apps.users", logging.ERROR, __file__, 1, "update", (), None)
        record.broken = Exploding(a=1)
        record.note = "token=exploding-secret"
        for module in ("config.settings.staging", "config.settings.prod"):
            config = _get_logging(module)
            for handler_name in config["handlers"]:
                with self.subTest(module=module, handler=handler_name):
                    probe = logging.makeLogRecord(dict(vars(record)))
                    probe.broken, probe.note = Exploding(a=1), "token=exploding-secret"
                    output = _deployed_handler_output(config, handler_name, probe)
                    self.assertIn("[log record withheld: redaction failed]", output)  # written, not dropped
                    self.assertNotIn("exploding-secret", output)
                    self.assertEqual(probe.note, "[REDACTED]")  # withheld on the record, not just unwritten

    def test_keys_redacted_alike_keep_both_entries(self) -> None:
        from apps.common.logging import redact_sensitive_data  # noqa: PLC0415

        for pair in (
            {"password=one": {"result": "success"}, "password=two": {"result": "failure"}},
            {"password=one": {"result": "success"}, "password=[REDACTED]": {"result": "failure"}},
            {"password=[REDACTED]": {"result": "success"}, "password=one": {"result": "failure"}},
            {
                "password=[REDACTED] (2)": {"result": "success"},
                "password=a": {"result": "x"},
                "password=b": {"result": "failure"},
            },
        ):
            with self.subTest(keys=list(pair)):
                redacted = redact_sensitive_data(pair)
                # Every entry survives; a key naming a password is itself sensitive, so its value is redacted too.
                self.assertEqual(len(redacted), len(pair), redacted)
                self.assertEqual(list(redacted.values()), ["[REDACTED]"] * len(pair))
                for secret in ("one", "two", "=a", "=b"):
                    self.assertNotIn(secret, "".join(redacted))

    def test_sentry_receives_no_sensitive_value(self) -> None:
        """Production's Sentry options, on the real SentryHandler, with an in-memory transport instead of the network."""
        import sentry_sdk  # noqa: PLC0415
        from sentry_sdk.integrations.logging import SentryHandler  # noqa: PLC0415
        from sentry_sdk.transport import Transport  # noqa: PLC0415

        from config.settings.sentry import sentry_options  # noqa: PLC0415

        sent: list[object] = []

        class Memory(Transport):
            def capture_envelope(self, envelope: Any) -> None:
                sent.extend(item.payload.json for item in envelope.items if item.payload.json is not None)

        options = {**sentry_options("https://key@sentry.example.test/1", release="test"), "transport": Memory}
        client = sentry_sdk.Client(default_integrations=False, **options)
        with sentry_sdk.isolation_scope() as scope:
            scope.set_client(client)
            for record in _records().values():
                SentryHandler().handle(record)
            client.flush()
        self.assertTrue(sent, "the handler sent events")
        payload = json.dumps(sent)
        for value in SENSITIVE_VALUES:
            self.assertNotIn(value, payload)

    def test_long_text_is_redacted_in_linear_time(self) -> None:
        """A long unbroken word (a base64 blob, a token) must not stall the worker that logs it."""
        import time  # noqa: PLC0415

        from apps.common.logging import redact_sensitive_text  # noqa: PLC0415

        # Big enough that a scan retried at every character (seconds) fails, small enough that it fails quickly.
        for text in ("a" * 20_000, "password=" + "x " * 10_000, "a=" * 10_000, ", " * 10_000, "a" + " " * 20_000):
            with self.subTest(text=text[:12]):
                started = time.perf_counter()
                redact_sensitive_text(text)
                self.assertLess(time.perf_counter() - started, 1.0)

    def test_a_value_ending_in_a_backslash_keeps_the_text_after_it(self) -> None:
        """Inside JSON nested in JSON, the value's closing quote is found by escape depth, not swallowed with the rest."""
        from apps.common.logging import redact_sensitive_text  # noqa: PLC0415

        for secret in ("secret-bs\\", "secret-bs\\\\", 'secret-bs\\"'):
            with self.subTest(secret=secret):
                text = json.dumps(
                    {"error": json.dumps({"password": secret, "after": "kept-inner"}), "next": "kept-outer"}
                )
                redacted = redact_sensitive_text(text)
                self.assertNotIn("secret-bs", redacted)
                self.assertIn("kept-inner", redacted)
                self.assertIn("kept-outer", redacted)
                json.loads(redacted)  # still valid JSON at both levels
                json.loads(json.loads(redacted)["error"])
