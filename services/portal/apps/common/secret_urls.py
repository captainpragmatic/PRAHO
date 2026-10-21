"""Redact bearer link segments only at logging and telemetry boundaries."""

from __future__ import annotations

import copy
import logging
import re
from typing import Any

# Both services use these links. Ordinary UUIDs, settings keys and query values stay intact.
_SEPARATOR = r"(?:/|%2f)"
_SEGMENT = r"(?:(?!/|%2f)[^\s?\"'<>#])+"


def _literal_route(value: str) -> str:
    # Match equivalent encoded route bytes without decoding or changing the request.
    return "".join(f"(?:{re.escape(char)}|%{ord(char):02x})" for char in value)


_CONFIRM_ROUTES = (
    _literal_route("auth") + _SEPARATOR + _literal_route("password-reset-confirm"),
    _literal_route("password-reset") + _SEPARATOR + _literal_route("confirm"),
    _literal_route("register") + _SEPARATOR + _literal_route("confirm"),
)
_ROUTE = (
    rf"(?P<prefix>{_SEPARATOR}(?:{'|'.join(_CONFIRM_ROUTES)}){_SEPARATOR}{_SEGMENT}{_SEPARATOR}"
    rf"|{_SEPARATOR}{_literal_route('notifications')}{_SEPARATOR}{_literal_route('unsubscribe')}{_SEPARATOR})"
    rf"(?P<secret>{_SEGMENT})"
)
SECRET_URL_PATTERN = re.compile(_ROUTE, re.IGNORECASE)


def redact_text(value: str) -> str:
    """Keep the route and replace its credential, including percent-encoded values."""
    return SECRET_URL_PATTERN.sub(lambda match: match["prefix"] + "[REDACTED]", value)


def redact_urls(value: Any) -> Any:
    """Return a scrubbed copy; never change a request used for authentication."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_urls(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_urls(item) for item in value]
    return value


def scrub_sentry_event(event: Any, hint: Any) -> Any:
    """Use for both error and transaction callbacks (including spans and breadcrumbs)."""
    return redact_urls(event)


class SecretURLFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        for name, value in tuple(vars(record).items()):
            if isinstance(value, (str, dict, list)):
                setattr(record, name, redact_urls(value))
        if record.exc_info:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
        return True


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def secure_logging_config(config: dict[str, Any]) -> dict[str, Any]:
    """Install handler-level filtering and cover plain-text exception formatters."""
    result = copy.deepcopy(config)
    result.setdefault("filters", {})["secret_urls"] = {"()": "apps.common.secret_urls.SecretURLFilter"}
    for handler in result.get("handlers", {}).values():
        handler.setdefault("filters", []).append("secret_urls")
    for formatter in result.get("formatters", {}).values():
        if "()" not in formatter and "class" not in formatter:
            formatter["()"] = "apps.common.secret_urls.RedactingFormatter"
    return result
