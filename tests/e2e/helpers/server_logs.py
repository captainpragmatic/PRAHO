"""
E2E Server Log Scanner — parse and filter platform/portal log files.

Reads log files written by Django's colorlog handler, strips ANSI codes,
and correlates entries to test requests via X-Request-ID headers.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

# ANSI escape code pattern (colorlog wraps level names in color codes)
_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")

# 36 dashes: RequestIDMiddleware default when no request context
NO_REQUEST_ID = "-" * 36

# Log line format from colorlog:
# "2026-03-03 12:53:41 ERROR    PLAT apps.customers.views                  message here [uuid-here]"
# After ANSI stripping, level is padded to 8 chars, logger to 40 chars.
# Primary pattern: standard log lines ending with [request_id]
LOG_LINE_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\w+)\s+"  # level (trailing spaces from padding)
    r"(\w{4})\s+"  # service tag (PLAT/PORT)
    r"([\w.\-]+)\s+"  # logger name — allows hyphens for django-q
    r"(.*?)\s*"  # message (non-greedy)
    r"\[([^\]]+)\]$"  # [request_id]
)

# Fallback pattern: log lines WITHOUT [request_id] (e.g., django-q task failures ending with ":")
LOG_LINE_PATTERN_NO_REQID = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\w+)\s+"  # level
    r"(\w{4})\s+"  # service tag
    r"([\w.\-]+)\s+"  # logger name
    r"(.+)$"  # message (greedy, no trailing [request_id])
)


@dataclass
class LogEntry:
    """A single parsed log line."""

    timestamp: str
    level: str  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    service: str  # PLAT or PORT
    logger: str  # e.g., apps.customers.views
    message: str
    request_id: str  # UUID or NO_REQUEST_ID
    raw_line: str
    source_file: str  # which log file this came from


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_PATTERN.sub("", text)


def parse_log_line(raw_line: str, source_file: str) -> LogEntry | None:
    """Parse a single log line into a LogEntry, or None if it doesn't match.

    Tries the standard pattern first (with [request_id]), then falls back to
    a pattern without request_id for django-q task failure lines.
    """
    cleaned = strip_ansi(raw_line)
    match = LOG_LINE_PATTERN.match(cleaned)
    if match:
        timestamp, level, service, logger, message, request_id = match.groups()
        return LogEntry(
            timestamp=timestamp,
            level=level,
            service=service,
            logger=logger,
            message=message.strip(),
            request_id=request_id,
            raw_line=raw_line,
            source_file=source_file,
        )
    # Fallback: lines without [request_id] (e.g., django-q task failures)
    match = LOG_LINE_PATTERN_NO_REQID.match(cleaned)
    if match:
        timestamp, level, service, logger, message = match.groups()
        return LogEntry(
            timestamp=timestamp,
            level=level,
            service=service,
            logger=logger,
            message=message.strip(),
            request_id=NO_REQUEST_ID,
            raw_line=raw_line,
            source_file=source_file,
        )
    return None


class ServerLogScanner:
    """Scans platform/portal log files for errors correlated to E2E test requests."""

    def __init__(self, log_paths: list[pathlib.Path]) -> None:
        self.log_paths = [p for p in log_paths if p.exists()]
        self._positions: dict[str, int] = {}
        self._available = len(self.log_paths) > 0

    @property
    def available(self) -> bool:
        """Whether any log files exist and can be scanned."""
        return self._available

    def mark_position(self) -> None:
        """Record current EOF position for each log file."""
        for path in self.log_paths:
            try:
                self._positions[str(path)] = path.stat().st_size
            except OSError:
                self._positions[str(path)] = 0

    def get_new_entries(self) -> list[LogEntry]:
        """Read log lines written since mark_position() was called."""
        entries: list[LogEntry] = []
        for path in self.log_paths:
            start = self._positions.get(str(path), 0)
            try:
                with open(path) as f:
                    f.seek(start)
                    for line in f:
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        entry = parse_log_line(line, source_file=str(path))
                        if entry:
                            entries.append(entry)
            except OSError:
                continue
        return entries

    def filter_errors(self, entries: list[LogEntry]) -> list[LogEntry]:
        """Return only ERROR and CRITICAL entries."""
        return [e for e in entries if e.level in ("ERROR", "CRITICAL")]

    def filter_by_request_ids(self, entries: list[LogEntry], request_ids: set[str]) -> list[LogEntry]:
        """Return entries matching any of the given request IDs."""
        return [e for e in entries if e.request_id in request_ids]

    def filter_uncorrelated_errors(self, entries: list[LogEntry], request_ids: set[str]) -> list[LogEntry]:
        """Return ERROR/CRITICAL entries NOT matching any known request ID."""
        return [
            e
            for e in entries
            if e.level in ("ERROR", "CRITICAL")
            and e.request_id not in request_ids
            and e.request_id != NO_REQUEST_ID
        ]
