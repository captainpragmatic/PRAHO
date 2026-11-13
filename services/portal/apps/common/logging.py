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
        return json.dumps(redact_urls(log_entry), default=lambda value: redact_sensitive_text(redact_text(str(value))))


_SENSITIVE_KEYS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
    "cui",  # Romanian tax ID
    "vat_number",
)
# A key is sensitive when one of the words above is a whole part of it ("new_password1", "csrf_token", "customer_cui"),
# not merely a substring ("circuit").
_SENSITIVE_KEY_NAME = re.compile(r"(?:^|[_.\-])(?:" + "|".join(_SENSITIVE_KEYS) + r")(?:$|[_.\-\d])", re.IGNORECASE)
# Where a key=value or key: value may start in free text: an optional quote or parenthesis around a name, then = or :.
_KEY_CANDIDATE = re.compile(r"""(["'(]?)([A-Za-z_][\w.\-]*)(["')]?)[ \t]*([=:])[ \t]*""")
_CLOSING = {"[": "]", "{": "}", "(": ")"}
# An unquoted value ends at a line break, ";" or a closing bracket; after "=" also at whitespace, unless the value so
# far is an authorization scheme (Bearer, Basic...) whose credential follows. A comma or "&" ends it only before another
# key, and a quote only when no letter follows it ("can't" stays one value). Ambiguous text is redacted, not kept.
_VALUE_END = frozenset("\r\n;)]}")
_NEXT_KEY = re.compile(r"""\s*["']?[A-Za-z_][\w.\-]*["']?\s*[=:]""")
_AUTH_SCHEMES = frozenset({"basic", "bearer", "digest", "negotiate", "token"})
REDACTION_TEXT = "[REDACTED]"
# How deep structured redaction walks; deeper (or cyclic) values are replaced, never recursed into.
_MAX_DEPTH = 32


def _is_sensitive_key(name: object) -> bool:
    return isinstance(name, str) and _SENSITIVE_KEY_NAME.search(name) is not None


def _quoted_end(text: str, start: int) -> int:
    """The index after the quote that closes the one at `start`; a backslash escapes the next character."""
    quote, index = text[start], start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return len(text)


def _bracketed_end(text: str, start: int) -> int:
    """The index after the bracket that matches the one at `start`, skipping quoted text inside."""
    stack, index = [_CLOSING[text[start]]], start + 1
    while index < len(text) and stack:
        char = text[index]
        if char in "\"'":
            index = _quoted_end(text, index)
            continue
        if char in _CLOSING:
            stack.append(_CLOSING[char])
        elif char == stack[-1]:
            stack.pop()
        index += 1
    return index


def _unquoted_end(text: str, start: int, separator: str) -> int:
    index = start
    while index < len(text):
        char = text[index]
        if char in _VALUE_END:
            break
        if char in " \t" and separator == "=" and text[start:index].lower() not in _AUTH_SCHEMES:
            break
        if char in ",&" and _NEXT_KEY.match(text, index + 1):
            break
        if char in "\"'" and not (index + 1 < len(text) and text[index + 1].isalnum()):
            break
        index += 1
    return start + len(text[start:index].rstrip())


def _value_end(text: str, start: int, separator: str) -> int:
    if start >= len(text):
        return start
    if text[start] in "\"'":
        return _quoted_end(text, start)
    if text[start] in _CLOSING:
        return _bracketed_end(text, start)
    return _unquoted_end(text, start, separator)


def redact_sensitive_text(value: str) -> str:
    """Replace the value after every sensitive key in a piece of log text, keeping the key so the line still reads.

    The value is a quoted string (escapes honoured), a bracketed list, dict or tuple (to its matching bracket), or
    an unquoted token. A non-sensitive key's value is read on, so a sensitive key inside it is found too.
    """
    parts: list[str] = []
    position = 0
    while (match := _KEY_CANDIDATE.search(value, position)) is not None:
        if not _is_sensitive_key(match[2]):
            parts.append(value[position : match.end()])
            position = match.end()
            continue
        end = _value_end(value, match.end(), match[4])
        found = value[match.end() : end]
        quote = found[0] if found[:1] in ("'", '"') else ""
        parts.append(value[position : match.end()] + (f"{quote}{REDACTION_TEXT}{quote}" if found else ""))
        position = end
    parts.append(value[position:])
    return "".join(parts)


def redact_sensitive_data(value: Any, _path: frozenset[int] = frozenset(), _depth: int = 0) -> Any:
    """A copy of a structured value with every sensitive key's value replaced, and its text redacted.

    Walks dicts, lists and tuples (dict keys included); other values are returned as they are.
    """
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, (bytes, bytearray)):  # A formatter would write it as text: redact that text now
        return redact_sensitive_text(bytes(value).decode("utf-8", "replace"))
    if not isinstance(value, (dict, list, tuple)):
        return value
    if id(value) in _path or _depth >= _MAX_DEPTH:
        return REDACTION_TEXT
    path = _path | {id(value)}
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = redact_sensitive_data(key, path, _depth + 1)
            if new_key != key and new_key in redacted:  # Two keys redacted alike: keep both entries
                count = 2
                while f"{new_key} ({count})" in redacted:
                    count += 1
                new_key = f"{new_key} ({count})"
            redacted[new_key] = (
                REDACTION_TEXT if _is_sensitive_key(key) else redact_sensitive_data(item, path, _depth + 1)
            )
        return redacted
    items = [redact_sensitive_data(item, path, _depth + 1) for item in value]
    return items if isinstance(value, list) else tuple(items)


# The attributes every LogRecord has; anything else on a record came from `extra=` or a filter.
_STANDARD_RECORD_ATTRIBUTES = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}


class SensitiveDataFilter(logging.Filter):
    """Redact the values of sensitive keys (passwords, tokens, card numbers, CUI and VAT numbers) from log records.

    Structured arguments and `extra=` attributes are redacted by key before anything is rendered, then the
    message as rendered and the exception text are redacted as text; formatters that render the exception
    themselves read the redacted exc_text it leaves. A logging filter must never raise, so a record it cannot
    redact is withheld instead of emitted.
    """

    SENSITIVE_KEYS: ClassVar[tuple[str, ...]] = _SENSITIVE_KEYS
    REDACTION_TEXT = REDACTION_TEXT

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:  # A logging filter must never raise into the code that logs
            # Redaction itself failed: withhold the record's text and every extra rather than emit what may hold a secret
            record.msg = "[log record withheld: redaction failed]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            for name in tuple(vars(record)):
                if name not in _STANDARD_RECORD_ATTRIBUTES:
                    setattr(record, name, REDACTION_TEXT)
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        if record.args:
            record.args = redact_sensitive_data(record.args)
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = f"{record.msg} (arguments: {record.args!r})"
        record.msg, record.args = redact_sensitive_text(rendered), ()
        for name, value in tuple(vars(record).items()):
            if name in _STANDARD_RECORD_ATTRIBUTES:
                continue
            setattr(record, name, REDACTION_TEXT if _is_sensitive_key(name) else redact_sensitive_data(value))
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
