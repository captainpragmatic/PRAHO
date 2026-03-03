"""
Unit tests for the ServerLogScanner and log parsing utilities.

Tests cover log line parsing (standard, ANSI-coded, portal, garbage input),
file position tracking, and entry filtering (errors, request IDs, uncorrelated).
"""

from __future__ import annotations

import pathlib

from tests.e2e.helpers.server_logs import (
    NO_REQUEST_ID,
    LogEntry,
    ServerLogScanner,
    parse_log_line,
    strip_ansi,
)

# ---------------------------------------------------------------------------
# Sample log lines for reuse across tests
# ---------------------------------------------------------------------------
SAMPLE_ERROR_LINE = (
    "2026-03-03 12:53:41 ERROR    PLAT apps.customers.views"
    "                  Something went wrong [a1b2c3d4-e5f6-7890-abcd-ef1234567890]"
)

SAMPLE_INFO_LINE = (
    "2026-03-03 12:53:42 INFO     PLAT apps.orders.services"
    "                   Order created successfully [a1b2c3d4-e5f6-7890-abcd-ef1234567890]"
)

SAMPLE_PORTAL_LINE = (
    "2026-03-03 12:53:43 WARNING  PORT apps.api_client.services"
    "              Slow upstream response [b2c3d4e5-f6a7-8901-bcde-f12345678901]"
)

SAMPLE_CRITICAL_LINE = (
    "2026-03-03 12:53:44 CRITICAL PLAT apps.billing.services"
    "                 Database connection lost [c3d4e5f6-a7b8-9012-cdef-123456789012]"
)

SAMPLE_NO_REQUEST_LINE = (
    "2026-03-03 12:53:45 ERROR    PLAT apps.common.middleware"
    f"                Startup check failed [{NO_REQUEST_ID}]"
)


class TestStripAnsi:
    """Tests for ANSI escape code stripping."""

    def test_removes_color_codes(self) -> None:
        """ANSI color codes around level name are removed."""
        text = "\x1b[31mERROR\x1b[0m"
        assert strip_ansi(text) == "ERROR"

    def test_plain_text_unchanged(self) -> None:
        """Text without ANSI codes passes through unchanged."""
        text = "plain text"
        assert strip_ansi(text) == "plain text"


class TestParseLogLine:
    """Tests for parse_log_line()."""

    def test_parse_log_line_standard(self) -> None:
        """Parse a standard ERROR log line into a LogEntry."""
        entry = parse_log_line(SAMPLE_ERROR_LINE, source_file="/logs/platform.log")
        assert entry is not None
        assert entry.timestamp == "2026-03-03 12:53:41"
        assert entry.level == "ERROR"
        assert entry.service == "PLAT"
        assert entry.logger == "apps.customers.views"
        assert "Something went wrong" in entry.message
        assert entry.request_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert entry.source_file == "/logs/platform.log"

    def test_parse_log_line_with_ansi_codes(self) -> None:
        """ANSI escape codes from colorlog are stripped before parsing."""
        ansi_line = (
            "2026-03-03 12:53:41 \x1b[31mERROR\x1b[0m    PLAT apps.customers.views"
            "                  Oops [a1b2c3d4-e5f6-7890-abcd-ef1234567890]"
        )
        entry = parse_log_line(ansi_line, source_file="test.log")
        assert entry is not None
        assert entry.level == "ERROR"

    def test_parse_log_line_no_match(self) -> None:
        """Garbage input returns None."""
        assert parse_log_line("not a log line at all", source_file="x") is None
        assert parse_log_line("", source_file="x") is None
        assert parse_log_line("   ", source_file="x") is None

    def test_parse_log_line_portal(self) -> None:
        """Portal (PORT) service lines are parsed correctly."""
        entry = parse_log_line(SAMPLE_PORTAL_LINE, source_file="portal.log")
        assert entry is not None
        assert entry.service == "PORT"
        assert entry.level == "WARNING"
        assert entry.logger == "apps.api_client.services"

    def test_parse_log_line_info_level(self) -> None:
        """INFO level lines are parsed correctly."""
        entry = parse_log_line(SAMPLE_INFO_LINE, source_file="test.log")
        assert entry is not None
        assert entry.level == "INFO"
        assert "Order created" in entry.message


    def test_parse_log_line_hyphen_logger(self) -> None:
        """Logger names with hyphens (e.g., django-q) are parsed correctly."""
        line = (
            "2026-03-03 12:53:41 ERROR    PLAT django-q"
            "                                 Task failed [a1b2c3d4-e5f6-7890-abcd-ef1234567890]"
        )
        entry = parse_log_line(line, source_file="test.log")
        assert entry is not None
        assert entry.logger == "django-q"
        assert entry.level == "ERROR"

    def test_parse_log_line_no_request_id_fallback(self) -> None:
        """Lines without [request_id] (e.g., django-q task failures) use fallback pattern."""
        line = (
            "2026-03-03 12:53:41 ERROR    PLAT django-q"
            "                                 Failed 'tasks.sync_providers' - not defined :"
        )
        entry = parse_log_line(line, source_file="test.log")
        assert entry is not None
        assert entry.level == "ERROR"
        assert entry.logger == "django-q"
        assert "Failed" in entry.message
        assert entry.request_id == NO_REQUEST_ID  # fallback assigns NO_REQUEST_ID


class TestServerLogScannerFileOps:
    """Tests for ServerLogScanner file operations."""

    def test_mark_and_read_new_entries(self, tmp_path: pathlib.Path) -> None:
        """Mark position, write new entries, and read only the new ones."""
        log_file = tmp_path / "test.log"
        # Write initial content
        log_file.write_text(SAMPLE_INFO_LINE + "\n")

        scanner = ServerLogScanner([log_file])
        assert scanner.available is True

        # Mark position at current EOF
        scanner.mark_position()

        # Append new content after the mark
        with open(log_file, "a") as f:
            f.write(SAMPLE_ERROR_LINE + "\n")
            f.write(SAMPLE_CRITICAL_LINE + "\n")

        entries = scanner.get_new_entries()
        assert len(entries) == 2
        assert entries[0].level == "ERROR"
        assert entries[1].level == "CRITICAL"

    def test_graceful_degradation_no_log_file(self, tmp_path: pathlib.Path) -> None:
        """Scanner with nonexistent paths is unavailable but does not raise."""
        nonexistent = tmp_path / "does_not_exist.log"
        scanner = ServerLogScanner([nonexistent])
        assert scanner.available is False

        # These should not raise
        scanner.mark_position()
        entries = scanner.get_new_entries()
        assert entries == []


class TestServerLogScannerFiltering:
    """Tests for entry filtering methods."""

    def _make_entries(self) -> list[LogEntry]:
        """Build a mixed list of LogEntry objects for filter tests."""
        lines = [
            SAMPLE_ERROR_LINE,
            SAMPLE_INFO_LINE,
            SAMPLE_PORTAL_LINE,
            SAMPLE_CRITICAL_LINE,
            SAMPLE_NO_REQUEST_LINE,
        ]
        entries = []
        for line in lines:
            entry = parse_log_line(line, source_file="test.log")
            if entry:
                entries.append(entry)
        return entries

    def test_filter_errors(self) -> None:
        """filter_errors returns only ERROR and CRITICAL entries."""
        entries = self._make_entries()
        scanner = ServerLogScanner([])
        errors = scanner.filter_errors(entries)
        levels = {e.level for e in errors}
        assert levels == {"ERROR", "CRITICAL"}
        assert len(errors) == 3  # 2 ERROR + 1 CRITICAL

    def test_filter_by_request_ids(self) -> None:
        """filter_by_request_ids returns only entries with matching IDs."""
        entries = self._make_entries()
        scanner = ServerLogScanner([])
        target_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        filtered = scanner.filter_by_request_ids(entries, {target_id})
        assert all(e.request_id == target_id for e in filtered)
        assert len(filtered) >= 2  # ERROR + INFO lines share this ID

    def test_filter_uncorrelated_skips_no_request_context(self) -> None:
        """Entries with NO_REQUEST_ID (36 dashes) are excluded from uncorrelated errors."""
        entries = self._make_entries()
        scanner = ServerLogScanner([])
        # Pass an empty set so nothing matches by request ID
        uncorrelated = scanner.filter_uncorrelated_errors(entries, set())
        request_ids = {e.request_id for e in uncorrelated}
        assert NO_REQUEST_ID not in request_ids
        # All uncorrelated entries should be ERROR or CRITICAL
        assert all(e.level in ("ERROR", "CRITICAL") for e in uncorrelated)

    def test_expected_pattern_filters(self) -> None:
        """Filtering by request IDs correctly excludes known test requests."""
        entries = self._make_entries()
        scanner = ServerLogScanner([])

        known_ids = {
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        }
        # filter_uncorrelated_errors should exclude entries matching known IDs
        uncorrelated = scanner.filter_uncorrelated_errors(entries, known_ids)
        for entry in uncorrelated:
            assert entry.request_id not in known_ids
            assert entry.request_id != NO_REQUEST_ID
