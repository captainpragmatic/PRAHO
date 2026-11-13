"""
Logging utilities for PRAHO Portal Service.

Provides a lightweight JSON formatter for structured logging in prod/staging,
since portal cannot import platform's SIEMJSONFormatter (cross-service import
forbidden) and python-json-logger is not a dependency, and the sensitive-data
filter, a copy of the Platform's for the same reason.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, ClassVar

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
            # A sensitive-data filter on the handler leaves the redacted traceback in exc_text; use it when it's there.
            log_entry["exception"] = record.exc_text or self.formatException(record.exc_info)
        # Redacted as data, then encoded: redacting the encoded text could swallow the backslash of an
        # escaped quote after a secret and break the JSON. Values json cannot encode are redacted as text.
        return json.dumps(redact_urls(log_entry), default=lambda value: redact_text(str(value)))


_SENSITIVE_KEYS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
    "cui",  # Romanian tax ID
    "vat_number",
)
# A sensitive key written as key=value, key: value or a quoted dict/JSON key, and the value that follows it:
# a quoted string, or everything up to a separator. The key and the separator stay; the value goes.
_SENSITIVE_VALUE = re.compile(
    r"(?P<key>[\"']?[\w-]*(?:" + "|".join(_SENSITIVE_KEYS) + r")[\w-]*[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&}\])]+)",
    re.IGNORECASE,
)
REDACTION_TEXT = "[REDACTED]"


def redact_sensitive_text(value: str) -> str:
    """Replace the value of every sensitive key in a piece of log text, keeping the key so the line still reads."""

    def replace(match: re.Match[str]) -> str:
        found = match["value"]
        quote = found[0] if found[:1] in ("'", '"') and found[-1:] == found[:1] else ""
        return f"{match['key']}{quote}{REDACTION_TEXT}{quote}"

    return _SENSITIVE_VALUE.sub(replace, value)


class SensitiveDataFilter(logging.Filter):
    """Redact the values of sensitive keys (passwords, tokens, card numbers, CUI and VAT numbers) from log records.

    It covers the message rendered with its arguments and the exception text; formatters that render the
    exception themselves read the redacted exc_text it leaves. A logging filter must never raise, so a record
    it cannot redact is withheld instead of emitted.
    """

    SENSITIVE_KEYS: ClassVar[tuple[str, ...]] = _SENSITIVE_KEYS
    REDACTION_TEXT = REDACTION_TEXT

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:  # A logging filter must never raise into the code that logs
            record.msg = "[log record withheld: redaction failed]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        rendered = record.getMessage()
        redacted = redact_sensitive_text(rendered)
        if redacted != rendered:
            record.msg, record.args = redacted, ()
        if record.exc_info:
            text = record.exc_text or logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact_sensitive_text(text)


def with_sensitive_data_redaction(config: dict[str, Any]) -> dict[str, Any]:
    """A LOGGING dict whose every handler runs SensitiveDataFilter, last: the secret-URL filter rebuilds exc_text."""
    result = copy.deepcopy(config)
    result.setdefault("filters", {})["sensitive_data"] = {"()": "apps.common.logging.SensitiveDataFilter"}
    for handler in result.get("handlers", {}).values():
        handler.setdefault("filters", []).append("sensitive_data")
    return result
