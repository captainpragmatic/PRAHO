"""
Tests for LOGGING configuration structure across portal environments.

Validates that formatters, filters, handlers, and loggers are wired correctly.
"""

from __future__ import annotations

import importlib
import os
from typing import Any
from unittest.mock import patch

import pytest

# Prod/staging settings require these env vars at import time.
_PROD_ENV = {
    "SECRET_KEY": "test-secret-key-for-logging-config-tests-only-not-real",
    "PLATFORM_API_SECRET": "dGVzdC1zZWNyZXQtZm9yLWxvZ2dpbmctY29uZmlnLXRlc3Rz",
    "PLATFORM_API_ALLOW_INSECURE_HTTP": "true",
}


def _get_logging(module_path: str) -> dict[str, Any]:
    """Import a settings module and return its LOGGING dict.

    Prod/staging modules validate SECRET_KEY / PLATFORM_API_SECRET at import
    time, so we inject dummy env vars for the import only.
    """
    with patch.dict(os.environ, _PROD_ENV):
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

    def test_smaller_retention_than_prod(self) -> None:
        prod = _get_logging("config.settings.prod")
        assert self.config["handlers"]["file"]["maxBytes"] < prod["handlers"]["file"]["maxBytes"]
