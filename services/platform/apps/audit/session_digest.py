"""Session identifiers in audit rows are keyed one-way digests, never usable session keys.

Django cycles the session key before user_logged_in fires, so a key recorded at login is the live
one. Stored in an audit row it reached the CSV and JSON exports and the SIEM output, where anyone
holding an export could resume that session. An audit row keeps a digest instead: still equal for
the same session, so session correlation and search keep working, but not reversible to the key.

The digest is ``s1:`` plus the first 32 hex characters of HMAC-SHA256 under a dedicated derived
key (``AUDIT_SESSION_DIGEST_SECRET`` when provisioned, else derived from SECRET_KEY). It is
idempotent: an ``s1:`` value is returned unchanged, so re-saves and searches with an already
digested value need no special casing. Empty stays empty, which readers treat as "no session".
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from apps.common.key_derivation import derive_key

SESSION_DIGEST_PREFIX = "s1:"
_DIGEST_HEX_LENGTH = 32
# A key name that holds a session identifier: session_key, session_id, old_session_key,
# session_key_before_logout... Only such names are digested: session_info also records times and
# durations, which are evidence, not identifiers.
_SESSION_KEY_NAME = re.compile(r"(?:^|_)session_(?:key|id)s?(?:_|$)")
# A session key named in free text with no structured counterpart, as in "session_key=<key>" or
# "Session ID: <key>". Django session keys are 32 lowercase letters and digits.
_LABELLED_KEY_IN_TEXT = re.compile(r"(session[ _-]?(?:key|id)\s*[:=]\s*)([a-z0-9]{32})\b", re.IGNORECASE)
# Shorter values cannot be a Django session key (32 characters) and are never rewritten by value.
_MIN_RAW_KEY_LENGTH = 16
# Stored on purpose as a short, unusable prefix ("abcd1234...").
_TRUNCATED_SUFFIX = "..."


def session_key_digest(value: str | None) -> str:
    """The stored form of a session identifier: empty for none, unchanged if already digested."""
    if not value:
        return ""
    if value.startswith(SESSION_DIGEST_PREFIX):
        return value
    mac = hmac.new(derive_key("audit-session-digest"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{SESSION_DIGEST_PREFIX}{mac[:_DIGEST_HEX_LENGTH]}"


def _is_session_value(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith(SESSION_DIGEST_PREFIX)
        and not value.endswith(_TRUNCATED_SUFFIX)
    )


def _is_session_name(key: Any) -> bool:
    return isinstance(key, str) and bool(_SESSION_KEY_NAME.search(key))


def _collect_named(value: Any, found: set[str], *, named: bool = False) -> None:
    # `named`: this value sits under a session-named key, so every string below it is an identifier.
    if isinstance(value, dict):
        for key, item in value.items():
            _collect_named(item, found, named=named or _is_session_name(key))
    elif isinstance(value, (list, tuple)):  # a tuple is stored as a JSON array too
        for item in value:
            _collect_named(item, found, named=named)
    elif named and _is_session_value(value):
        found.add(value)


def _replace_raw(text: str, raw_keys: set[str]) -> str:
    for raw in raw_keys:
        if raw in text:
            text = text.replace(raw, session_key_digest(raw))
    return _LABELLED_KEY_IN_TEXT.sub(lambda match: match.group(1) + session_key_digest(match.group(2)), text)


def _scrub(value: Any, raw_keys: set[str], *, named: bool = False) -> Any:
    if isinstance(value, dict):
        return {key: _scrub(item, raw_keys, named=named or _is_session_name(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(item, raw_keys, named=named) for item in value]
    if named and _is_session_value(value):
        return session_key_digest(value)
    if isinstance(value, str):
        return _replace_raw(value, raw_keys)
    return value


def digest_session_identifiers(
    *,
    session_key: str | None,
    description: str,
    metadata: Any,
    old_values: Any,
    new_values: Any,
) -> tuple[str, str, Any, Any, Any]:
    """Return the event's fields with every session identifier replaced by its digest.

    Two nets. By key name: session_key, session_id and their plurals, *_session_key and session_key_*,
    at any depth, with every string below such a key included (session_info's keys too). By value:
    every occurrence of a raw key found by the first net, or passed as the event's session_key,
    anywhere in the description, metadata or values.
    """
    raw_keys: set[str] = set()
    if _is_session_value(session_key):
        raw_keys.add(session_key)  # type: ignore[arg-type]  # _is_session_value narrowed it to str
    for payload in (metadata, old_values, new_values):
        _collect_named(payload, raw_keys)
    raw_keys = {raw for raw in raw_keys if len(raw) >= _MIN_RAW_KEY_LENGTH}

    return (
        session_key_digest(session_key),
        _replace_raw(description or "", raw_keys),
        _scrub(metadata, raw_keys),
        _scrub(old_values, raw_keys),
        _scrub(new_values, raw_keys),
    )
