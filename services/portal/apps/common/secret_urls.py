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


# How deep redaction walks nested containers; deeper (or cyclic) values are replaced, never recursed into.
_MAX_DEPTH = 32
_CYCLE = "[cycle]"


def redact_urls(value: Any, _path: frozenset[int] = frozenset(), _depth: int = 0) -> Any:
    """Return a scrubbed copy; never change a request used for authentication.

    Tuples stay tuples. A container met again on its own path (a cycle), or nested past the depth bound,
    is replaced by a placeholder rather than recursed into.
    """
    if isinstance(value, str):
        return redact_text(value)
    if not isinstance(value, (dict, list, tuple)):
        return value
    if id(value) in _path or _depth >= _MAX_DEPTH:
        return _CYCLE
    path = _path | {id(value)}
    if isinstance(value, dict):  # Keys too: a link can be a key (results keyed by URL)
        scrubbed: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = redact_text(key) if isinstance(key, str) else key
            if new_key != key and new_key in scrubbed:  # Two links redacted alike: keep both entries
                count = 2
                while f"{new_key} ({count})" in scrubbed:
                    count += 1
                new_key = f"{new_key} ({count})"
            scrubbed[new_key] = redact_urls(item, path, _depth + 1)
        return scrubbed
    items = [redact_urls(item, path, _depth + 1) for item in value]
    return tuple(items) if isinstance(value, tuple) else items


def scrub_sentry_event(event: Any, hint: Any) -> Any:
    """Use for both error and transaction callbacks (including spans and breadcrumbs)."""
    return redact_urls(event)


class SecretURLFilter(logging.Filter):
    """Redact secrets in a record before any handler formats it.

    Filters run outside the handler's error handling, so this never raises. The message is rendered once,
    and the lazy message and arguments are replaced only when redaction changed the text, or when the
    arguments do not fit the message (logging would otherwise print them raw).
    """

    _SKIPPED = frozenset({"msg", "args", "exc_info"})

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:  # A logging filter must never raise into the code that logs
            # Redaction itself failed: withhold the record's text rather than emit what may hold a secret
            record.msg = "[log record withheld: redaction failed]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        try:
            rendered = record.getMessage()
        except Exception:
            # Arguments the message cannot format: logging would print them raw to stderr. The record
            # carries a redacted, already formatted message instead, its arguments listed after it.
            record.msg = redact_text(f"{record.msg} (arguments: {redact_urls(record.args)!r})")
            record.args = ()
        else:
            redacted = redact_text(rendered)
            if redacted != rendered:
                record.msg, record.args = redacted, ()
        for name, value in tuple(vars(record).items()):
            if name in self._SKIPPED:
                continue
            if isinstance(value, str):
                cleaned = redact_text(value)
                if cleaned != value:
                    setattr(record, name, cleaned)
            elif isinstance(value, (dict, list, tuple)):
                setattr(record, name, redact_urls(value))  # A copy: never compared, it may be cyclic
        if record.exc_info:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))


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
