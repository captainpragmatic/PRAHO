"""
Logging utilities for PRAHO Portal Service.

Provides a lightweight JSON formatter for structured logging in prod/staging,
since portal cannot import platform's SIEMJSONFormatter (cross-service import
forbidden) and python-json-logger is not a dependency.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime


class PortalJSONFormatter(logging.Formatter):
    """Structured JSON log formatter for portal prod/staging environments."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-" * 36),
            "service": "portal",
        }
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)
