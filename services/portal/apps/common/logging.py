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

from apps.common.secret_urls import redact_text, redact_urls


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
        # Redacted as data, then encoded: redacting the encoded text could swallow the backslash of an
        # escaped quote after a secret and break the JSON. Values json cannot encode are redacted as text.
        return json.dumps(redact_urls(log_entry), default=lambda value: redact_text(str(value)))
