"""
Tests for LOGGING configuration structure across portal environments.

Validates that formatters, filters, handlers, and loggers are wired correctly.
"""

from __future__ import annotations

import importlib
import io
import logging
import logging.config
import os
import sys
from typing import Any
from unittest.mock import patch

import pytest

# Prod/staging settings require these env vars at import time.
_PROD_ENV = {
    "DJANGO_SECRET_KEY": "logging-config-tests-only-key-xxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "PLATFORM_API_SECRET": "dGVzdC1zZWNyZXQtZm9yLWxvZ2dpbmctY29uZmlnLXRlc3Rz",
    "PLATFORM_API_ALLOW_INSECURE_HTTP": "true",
    "ALLOWED_HOSTS": "portal.pragmatichost.com",
    "PORTAL_DOMAIN": "portal.pragmatichost.com",
    "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "test-webhook-secret-for-logging-config-tests",
    "PORTAL_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
    # The deployed default: files on. Empty (as the Docker image sets) means console only.
    "PORTAL_LOG_DIR": "/var/log/praho/portal",
}


def _get_logging(module_path: str) -> dict[str, Any]:
    """Import a settings module and return its LOGGING dict.

    Prod/staging modules validate SECRET_KEY / PLATFORM_API_SECRET at import
    time, so we inject dummy env vars for the import only.
    """
    with (
        patch.dict(os.environ, _PROD_ENV),
        patch("config.settings.base.IPWARE_TRUSTED_PROXY_LIST", ["127.0.0.1/32"]),
    ):
        mod = importlib.import_module(module_path)
    return mod.LOGGING


def _assert_handler_wiring(config: dict[str, Any]) -> None:
    """Every handler references an existing formatter and existing filters."""
    formatters = set(config.get("formatters", {}).keys())
    filters = set(config.get("filters", {}).keys())

    for name, handler in config.get("handlers", {}).items():
        if "formatter" in handler:
            assert handler["formatter"] in formatters, (
                f"Handler '{name}' references unknown formatter '{handler['formatter']}'"
            )
        for f in handler.get("filters", []):
            assert f in filters, f"Handler '{name}' references unknown filter '{f}'"


def _assert_logger_wiring(config: dict[str, Any]) -> None:
    """Every logger references existing handlers."""
    handlers = set(config.get("handlers", {}).keys())
    for name, logger_cfg in config.get("loggers", {}).items():
        for h in logger_cfg.get("handlers", []):
            assert h in handlers, f"Logger '{name}' references unknown handler '{h}'"


# =============================================================================
# Base / Dev config
# =============================================================================


class TestBaseLoggingConfiguration:
    """Validate portal base (dev) LOGGING configuration."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.config = _get_logging("config.settings.base")

    def test_has_colorlog_formatter(self) -> None:
        assert "unified" in self.config["formatters"]
        assert self.config["formatters"]["unified"]["()"] == "colorlog.ColoredFormatter"

    def test_format_contains_service_name(self) -> None:
        assert "{service_name}" in self.config["formatters"]["unified"]["format"]

    def test_has_service_name_filter(self) -> None:
        assert "add_service_name" in self.config["filters"]

    def test_service_name_is_port(self) -> None:
        assert self.config["filters"]["add_service_name"]["service_name"] == "PORT"

    def test_has_request_id_filter(self) -> None:
        assert "add_request_id" in self.config["filters"]

    def test_handler_wiring(self) -> None:
        _assert_handler_wiring(self.config)

    def test_logger_wiring(self) -> None:
        _assert_logger_wiring(self.config)

    def test_has_required_loggers(self) -> None:
        for name in ("django", "django.server", "apps"):
            assert name in self.config["loggers"], f"Missing logger: {name}"


# =============================================================================
# Prod config
# =============================================================================


class TestProdLoggingConfiguration:
    """Validate portal prod LOGGING configuration."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.config = _get_logging("config.settings.prod")

    def test_has_json_formatter(self) -> None:
        assert "json" in self.config["formatters"]
        assert self.config["formatters"]["json"]["()"] == "apps.common.logging.PortalJSONFormatter"

    def test_has_request_id_filter(self) -> None:
        assert "add_request_id" in self.config["filters"]

    def test_has_required_handlers(self) -> None:
        for name in ("console", "file", "error_file"):
            assert name in self.config["handlers"], f"Missing handler: {name}"

    def test_handler_wiring(self) -> None:
        _assert_handler_wiring(self.config)

    def test_logger_wiring(self) -> None:
        _assert_logger_wiring(self.config)

    def test_has_required_loggers(self) -> None:
        for name in ("django", "django.security", "django.request", "apps"):
            assert name in self.config["loggers"], f"Missing logger: {name}"


# =============================================================================
# Staging config
# =============================================================================


class TestStagingLoggingConfiguration:
    """Validate portal staging LOGGING configuration."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.config = _get_logging("config.settings.staging")

    def test_has_json_formatter(self) -> None:
        assert "json" in self.config["formatters"]

    def test_has_request_id_filter(self) -> None:
        assert "add_request_id" in self.config["filters"]

    def test_has_required_handlers(self) -> None:
        for name in ("console", "file", "error_file"):
            assert name in self.config["handlers"]

    def test_handler_wiring(self) -> None:
        _assert_handler_wiring(self.config)

    def test_logger_wiring(self) -> None:
        _assert_logger_wiring(self.config)

    def test_apps_logger_is_debug(self) -> None:
        assert self.config["loggers"]["apps"]["level"] == "DEBUG"

    def test_retention_is_left_to_logrotate(self) -> None:
        # Several portal processes write these files, so neither environment rotates them in
        # process (one process renaming a file under the others loses their lines); the native
        # role's logrotate policy sets retention, and the handlers reopen a moved file.
        prod = _get_logging("config.settings.prod")
        for config in (self.config, prod):
            for name in ("file", "error_file"):
                handler = config["handlers"][name]
                assert handler["class"] == "logging.handlers.WatchedFileHandler"
                assert "maxBytes" not in handler
                assert "backupCount" not in handler


class TestSecretURLFilterWiring:
    """Every portal environment installs the secret-URL filter on every handler (#751 follow-up, M6b)."""

    @pytest.mark.parametrize("module", ["config.settings.base", "config.settings.prod", "config.settings.staging"])
    def test_every_handler_redacts_secret_urls(self, module: str) -> None:
        config = _get_logging(module)

        assert config["filters"]["secret_urls"]["()"] == "apps.common.secret_urls.SecretURLFilter"
        assert config["handlers"], "handlers are configured"
        for name, handler in config["handlers"].items():
            assert "secret_urls" in handler.get("filters", []), f"{module}: handler {name}"


SENSITIVE_VALUES = ("Hunter2-pw", "RO76543210", "76543217", "4111111111111111")
_REDACTION_MODULES = ("config.settings.dev", "config.settings.staging", "config.settings.prod")


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
    return {
        "key=value": record("login failed password=Hunter2-pw vat_number=RO76543210 cui=76543217"),
        "dict-like text": record("{'password': 'Hunter2-pw', \"card_number\": \"4111111111111111\", 'cui': 76543217}"),
        "record.args": record("profile %s", ({"vat_number": "RO76543210", "password": "Hunter2-pw"},)),
        "exception text": record("payment error", (), failure),
    }


class TestSensitiveDataRedaction:
    """Every configured Portal handler, in every environment, writes a sensitive key's value as [REDACTED]."""

    @pytest.mark.parametrize("module", _REDACTION_MODULES)
    def test_every_handler_redacts_sensitive_values(self, module: str) -> None:
        config = _get_logging(module)
        failures = []
        for handler_name in config["handlers"]:
            for shape, record in _records().items():
                output = _deployed_handler_output(config, handler_name, record)
                leaked = [value for value in SENSITIVE_VALUES if value in output]
                # A handler that writes no exception (the CrowdSec event sink writes only the message) can't leak one.
                marked = "[REDACTED]" in output or (shape == "exception text" and "ValueError" not in output)
                if leaked or not marked:
                    failures.append((handler_name, shape, leaked, output[:160]))
        assert failures == []

    def test_ordinary_words_are_left_alone(self) -> None:
        config = _get_logging("config.settings.prod")
        record = logging.LogRecord("apps.users", logging.INFO, __file__, 1, "Password changed for %s", ("ana",), None)
        output = _deployed_handler_output(config, "console", record)
        assert "Password changed for ana" in output
        assert "[REDACTED]" not in output

    def test_a_crowdsec_event_line_passes_unchanged(self) -> None:
        config = _get_logging("config.settings.prod")
        line = (
            '{"account":"acct_3f2a","event":"password_reset_failed","ip":"203.0.113.9",'
            '"reason":"invalid_token","schema":1,"timestamp":"2026-11-13T05:00:00Z"}'
        )
        record = logging.LogRecord("praho.crowdsec.auth", logging.INFO, __file__, 1, line, (), None)
        assert _deployed_handler_output(config, "crowdsec_auth", record) == line + "\n"
