"""
Tests for LOGGING configuration structure across platform environments.

Validates that formatters, filters, handlers, and loggers are wired correctly
in each settings module — catching misconfiguration that would only surface at
runtime (e.g. handler referencing a non-existent formatter).
"""

from __future__ import annotations

import importlib
import os
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

# Prod/staging settings run secret validation at import time.
# We provide dummy env vars so the import succeeds.
_PROD_ENV = {
    "SECRET_KEY": "test-only-secret-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "PLATFORM_API_SECRET": "dGVzdC1vbmx5LXNlY3JldC1rZXktZm9yLWxvZ2dpbmctdGVzdHM=",
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

    def test_smaller_retention_than_prod(self) -> None:
        prod = _get_logging("config.settings.prod")
        staging = self.logging_config
        self.assertLess(
            staging["handlers"]["file"]["maxBytes"],
            prod["handlers"]["file"]["maxBytes"],
        )
