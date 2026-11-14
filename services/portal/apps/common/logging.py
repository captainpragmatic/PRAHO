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
# A key is sensitive when one of the words above is a whole part of it ("new_password1", "csrf_token", "b'password'"),
# not merely a substring ("circuit", "passwordless").
_SENSITIVE_KEY_NAME = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(_SENSITIVE_KEYS) + r")(?![A-Za-z])", re.IGNORECASE)
# Where a key=value or key: value may start in free text: an optional quote or parenthesis (perhaps escaped, as in
# JSON nested in JSON) and up to two dashes (a command-line --password), a name, then = or :. A candidate starts only
# where no word character, dot or dash precedes it, so a long word is scanned once, not once per character.
_KEY_CANDIDATE = re.compile(
    r"""(?<![\w.\-])(\\{0,3}["'(]?-{0,2})([A-Za-z_][\w.\-]*)(\\{0,3}["')]?)[ \t]*([=:])[ \t]*"""
)
_CLOSING = {"[": "]", "{": "}", "(": ")"}
# An unquoted value is redacted conservatively: it runs to a line break, and past whitespace, commas, semicolons and
# "&" unless what follows them is another key. Brackets and quotes inside it are part of it ("abc)tail", "can't"), so
# "password=correct horse battery" and "Authorization=Bearer  x" are redacted whole.
_DELIMITERS = frozenset(" \t,;&")
_MAX_QUOTE_ESCAPES = 3  # Backslashes before a quote: JSON nested up to three deep
_NEXT_KEY = re.compile(r"""["']?[A-Za-z_][\w.\-]*["']?[ \t]*[=:]""")
REDACTION_TEXT = "[REDACTED]"
# How deep structured redaction walks; deeper (or cyclic) values are replaced, never recursed into.
_MAX_DEPTH = 32


def _is_sensitive_key(name: object) -> bool:
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).decode("utf-8", "replace")
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


def _unquoted_end(text: str, start: int) -> int:
    index = start
    while index < len(text):
        char = text[index]
        if char in "\r\n":
            break
        if char in _DELIMITERS:
            after = index
            while after < len(text) and text[after] in _DELIMITERS:
                after += 1
            if _NEXT_KEY.match(text, after):
                break
            index = after
            continue
        index += 1
    return start + len(text[start:index].rstrip())


def _opening_quote(text: str, start: int) -> str:
    """The quote a value starts with, with any backslashes escaping it (JSON nested in JSON), or ""."""
    index = start
    while index < len(text) and index - start < _MAX_QUOTE_ESCAPES and text[index] == "\\":
        index += 1
    return text[start : index + 1] if index < len(text) and text[index] in "\"'" else ""


def _value_end(text: str, start: int) -> int:
    if start >= len(text):
        return start
    quote = _opening_quote(text, start)
    if quote == text[start : start + 1]:
        return _quoted_end(text, start)
    if quote:  # An escaped quote: the value ends at the next quote escaped at the opening one's depth
        # With k backslashes before the opening quote, a closing quote has k more 2(k+1) per backslash in the value
        # just before it (1, 5, 9... one level down); an interior quote has a run that doesn't fit (3, 7...).
        escapes, mark = len(quote) - 1, quote[-1]
        index = start + len(quote)
        while (index := text.find(mark, index)) >= 0:
            run = index
            while run > start and text[run - 1] == "\\":
                run -= 1
            if (index - run) % (2 * (escapes + 1)) == escapes:
                return index + 1
            index += 1
        return len(text)
    if text[start] in _CLOSING:
        return _bracketed_end(text, start)
    return _unquoted_end(text, start)


def redact_sensitive_text(value: str) -> str:
    """Replace the value after every sensitive key in a piece of log text, keeping the key so the line still reads.

    The value is a quoted string (escapes honoured, escaped quotes included), a bracketed list, dict or tuple (to its
    matching bracket), or an unquoted value read conservatively. A non-sensitive key's value is read on, so a
    sensitive key inside it is found too. Linear in the length of the text.
    """
    parts: list[str] = []
    position = 0
    while (match := _KEY_CANDIDATE.search(value, position)) is not None:
        if not _is_sensitive_key(match[2]):
            parts.append(value[position : match.end()])
            position = match.end()
            continue
        end = _value_end(value, match.end())
        found = value[match.end() : end]
        quote = _opening_quote(value, match.end()) if found else ""
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
        next_suffix: dict[Any, int] = {}  # Per redacted key, so many colliding keys stay linear
        for key, item in value.items():
            new_key = redact_sensitive_data(key, path, _depth + 1)
            if new_key in redacted:  # Keys that read alike once redacted: keep every entry
                count = next_suffix.get(new_key, 2)
                while f"{new_key} ({count})" in redacted:
                    count += 1
                next_suffix[new_key] = count + 1
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
            record.stack_info = None
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
        # Formatters write a cached exception text and the stack text as they are, with or without exc_info.
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_sensitive_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_sensitive_text(record.stack_info)


def with_sensitive_data_redaction(config: dict[str, Any]) -> dict[str, Any]:
    """A LOGGING dict whose every handler runs SensitiveDataFilter first and last.

    First, so structured arguments are redacted by key before any other filter renders them into text (the
    secret-URL filter does when a link is in the message); last, because the secret-URL filter rebuilds exc_text.
    The two places need two names: dictConfig builds one instance per name, and addFilter drops a repeated one.
    """
    result = copy.deepcopy(config)
    for name in ("sensitive_data", "sensitive_data_last"):
        result.setdefault("filters", {})[name] = {"()": "apps.common.logging.SensitiveDataFilter"}
    for handler in result.get("handlers", {}).values():
        filters = handler.setdefault("filters", [])
        filters.insert(0, "sensitive_data")
        filters.append("sensitive_data_last")
    return result
