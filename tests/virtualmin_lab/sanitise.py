"""Strip secrets and run-to-run noise from a recorded Virtualmin exchange.

The contract suite records what the lab node really answers; the platform tests replay it. A raw
answer carries things that must not be committed (password hashes, a TLS key pair, the node's
addresses, the recovery seed that PRAHO stores in the domain description) and things that change on
every run (random ids, timestamps, sizes, load). This module removes both, and keeps everything the
gateway classifies on: the envelope keys, `status`, and the error text.

It is plain stdlib so the contract run, the drift check and the integration tests can all import it.
Every rule is idempotent: a sanitised value sanitises to itself, which is how the committed fixtures
are proven clean.
"""

from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "<redacted>"
PEM_MARKER = "<pem>"

# A key whose value is a secret or the recovery seed. The name stays, the value goes.
_SENSITIVE_KEY = re.compile(
    r"pass(?:word|wd|phrase)?|hash|secret|token|credential|private|pubkey|ssh_?key"
    r"|(?:^|[_\- ])key(?:$|[_\- ])|^cert$|certificate|^desc(?:ription)?$",
    re.IGNORECASE,
)
# A key that names a random identifier (domain id, uid, gid, plan id): its digits are noise.
_ID_KEY = re.compile(r"(?:^|[_\- ])(?:id|uid|gid)$", re.IGNORECASE)

_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----")
_SECRET_LINE = re.compile(
    r"(?im)^([ \t]*[^\n:]*\b(?:pass(?:word|wd)?|secret|token|hash(?:ed)?)\b[^\n:]*:)[ \t]*\S.*$"
)
_PASSWORD_HASH = re.compile(r"\$[0-9a-z]{1,3}(?:\$[^\s$\"'\\]+){2,}")
_TIMESTAMPS = (
    re.compile(r"\d{1,2}/\d{1,2}/\d{4},? \d{1,2}:\d{2}(?::\d{2})?(?: ?[AP]M)?"),
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z| ?UTC|[+-]\d{2}:?\d{2})?"),
    re.compile(r"(?<![0-9])1[5-9]\d{8}(?![0-9])"),
)
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?![\w:])"
    r"|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?(?![\w:])"
)
_LONG_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{16,}(?![0-9A-Za-z])")
_LONG_NUMBER = re.compile(r"(?<!\w)\d{9,}(?!\w)")
_OWNER_ID = re.compile(r"(?i)\b((?:user|group|uid|gid)(?: ID)?(?: is)?[: ]+)\d+")
_SIZE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?\s?(?:bytes?|[KMGT]i?B)\b")
_DURATION = re.compile(r"(?i)\b\d+(?:\.\d+)?(?= ?(?:seconds?|secs?|milliseconds?|ms)\b)")
# Numbers on their own line (`info`, `get-template`): counters and gauges that move between runs.
# `info` lists a feature only once the node has counted something for it (aliases, dbs, users appear after the
# first mailbox user or database), so the block's keys depend on what ran before.
_FEATURE_COUNTS = re.compile(r"(?m)^fcount:[ \t]*\n(?:[ \t]+\S.*\n?)+")
_BARE_NUMBER_LINE = re.compile(r"(?m)^(\s*(?:\* )?)-?\d+(?:\.\d+)?$")
_LABELLED_NUMBER_LINE = re.compile(r"(?m)^(\s*[A-Za-z_][A-Za-z_ ]*:)[ \t]*-?\d+(?:\.\d+)?$")

_FINDING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem block", re.compile(r"-----BEGIN [A-Z0-9 ]+-----")),
    ("password hash", _PASSWORD_HASH),
    ("ipv4 address", _IPV4),
    ("ipv6 address", _IPV6),
    ("long hex token", _LONG_HEX),
    ("long number", _LONG_NUMBER),
    ("timestamp", _TIMESTAMPS[0]),
    ("timestamp", _TIMESTAMPS[1]),
    ("unix time", _TIMESTAMPS[2]),
)


def sanitise_text(text: str, *, dates: bool = True) -> str:
    """One string, with secrets and run-to-run noise replaced by stable placeholders."""
    cleaned = _PEM_BLOCK.sub(PEM_MARKER, text)
    cleaned = _SECRET_LINE.sub(rf"\1 {REDACTED}", cleaned)
    cleaned = _PASSWORD_HASH.sub("<hash>", cleaned)
    for pattern in _TIMESTAMPS:
        cleaned = pattern.sub("<timestamp>", cleaned)
    if dates:
        cleaned = _DATE.sub("<date>", cleaned)
    cleaned = _IPV6.sub("<ip>", cleaned)
    cleaned = _IPV4.sub("<ip>", cleaned)
    # Digits first: a domain id is 14 or 18 digits depending on the run, and 16 digits are also valid hex.
    cleaned = _LONG_NUMBER.sub("<id>", cleaned)
    cleaned = _LONG_HEX.sub("<hex>", cleaned)
    cleaned = _OWNER_ID.sub(r"\1<id>", cleaned)
    cleaned = _SIZE.sub("<size>", cleaned)
    cleaned = _DURATION.sub("<n>", cleaned)
    if "\n" in cleaned:
        cleaned = _FEATURE_COUNTS.sub("fcount: <counts>\n", cleaned)
        cleaned = _BARE_NUMBER_LINE.sub(r"\1<n>", cleaned)
        cleaned = _LABELLED_NUMBER_LINE.sub(r"\1 <n>", cleaned)
    return cleaned


def _is_sensitive_key(key: str | None) -> bool:
    return key is not None and _SENSITIVE_KEY.search(key) is not None


def _collapse_pem_rows(rows: list[Any]) -> list[Any]:
    """A listing that prints a key pair line by line becomes one marker row per block."""
    collapsed: list[Any] = []
    inside = False
    for row in rows:
        name = row.get("name") if isinstance(row, dict) else None
        if not isinstance(name, str):
            collapsed.append(row)
            continue
        if name.startswith("-----BEGIN "):
            inside = True
            collapsed.append({**row, "name": PEM_MARKER})
        elif inside:
            inside = not name.startswith("-----END ")
        else:
            collapsed.append(row)
    return collapsed


def _redact_table_descriptions(rows: list[Any]) -> list[Any]:
    """The plain `list-domains` table prints each domain's description (the recovery seed) in its last column."""
    first = rows[0].get("name") if rows and isinstance(rows[0], dict) else None
    if not (isinstance(first, str) and first.startswith("Domain ") and "Description" in first):
        return rows
    redacted: list[Any] = [rows[0]]
    for row in rows[1:]:
        name = row.get("name") if isinstance(row, dict) else None
        parts = name.split(None, 2) if isinstance(name, str) and not name.startswith("-") else []
        redacted.append({**row, "name": f"{parts[0]} {parts[1]} {REDACTED}"} if len(parts) == 3 else row)
    return redacted


def sanitise_value(value: Any, *, key: str | None = None, dates: bool = True, _secret: bool = False) -> Any:
    """A JSON value, recursively. `key` is the name it sits under."""
    secret = _secret or _is_sensitive_key(key)
    if isinstance(value, dict):
        return {
            str(name): sanitise_value(item, key=str(name), dates=dates, _secret=secret) for name, item in value.items()
        }
    if isinstance(value, list):
        items = _redact_table_descriptions(_collapse_pem_rows(value))
        return [sanitise_value(item, key=key, dates=dates, _secret=secret) for item in items]
    if isinstance(value, str):
        if secret and value:
            return REDACTED
        if key is not None and _ID_KEY.search(key) and value.isdigit():
            return "<id>"
        return sanitise_text(value, dates=dates)
    return value


def _sanitise_param(value: Any, *, key: str, secret: bool) -> Any:
    if isinstance(value, list):
        return [_sanitise_param(item, key=key, secret=secret) for item in value]
    if not isinstance(value, str):
        return value
    if secret and value:
        return REDACTED
    if _ID_KEY.search(key) and value.isdigit():
        return "<id>"
    # Only what differs from run to run: random tokens in staging paths. Numbers stay exact, because
    # quotas, bandwidth and sizes are what the contract pins.
    return _LONG_HEX.sub("<hex>", value)


def sanitise_params(params: dict[str, Any]) -> dict[str, Any]:
    """The parameters of a call, kept as production sends them except secrets, ids and random path tokens."""
    return {
        str(name): _sanitise_param(value, key=str(name), secret=_is_sensitive_key(str(name)))
        for name, value in params.items()
    }


def sanitise_recording(recording: dict[str, Any]) -> dict[str, Any]:
    """A whole recording file: parameters keep their dates, everything else is sanitised as a response."""
    cleaned = sanitise_value({**recording, "cases": {}})
    cleaned["cases"] = {
        name: {**sanitise_value({**case, "params": {}}), "params": sanitise_params(case["params"])}
        for name, case in recording["cases"].items()
    }
    return cleaned


def sanitise_body(raw: str) -> Any:
    """A response body as sanitised data: parsed JSON when it is JSON, sanitised text otherwise."""
    text = (raw or "").strip()
    if text.startswith(("{", "[")):
        try:
            return sanitise_value(json.loads(text))
        except ValueError:
            pass
    return sanitise_text(text)


def _leaf_leak(key: str | None, value: str, *, secret: bool) -> str | None:
    """Why this string must not be committed as it is, or None when it is clean."""
    if value in {"", REDACTED, PEM_MARKER}:
        return None
    if secret:
        return "value under a secret key"
    if key is not None and _ID_KEY.search(key) and value.isdigit():
        return "random id"
    for label, pattern in _FINDING_PATTERNS:
        if pattern.search(value):
            return label
    return None


def find_recording_leaks(recording: dict[str, Any]) -> list[str]:
    """Leaks in a whole recording file, judging each case's parameters by the parameter rules.

    Parameters keep the numbers production sends, so they are checked against `sanitise_params`,
    not against the response rules that treat every long number as a possible id.
    """
    found = find_leaks({**recording, "cases": {}})
    for name, case in recording.get("cases", {}).items():
        found.extend(find_leaks({**case, "params": {}}, path=f"$.cases.{name}"))
        params = case.get("params", {})
        cleaned = sanitise_params(params)
        found.extend(
            f"$.cases.{name}.params.{key}: not sanitised" for key in params if cleaned.get(key) != params[key]
        )
    return found


def find_leaks(value: Any, *, path: str = "$", key: str | None = None, _secret: bool = False) -> list[str]:
    """Everything in `value` that sanitising would still change, one finding per leaf."""
    secret = _secret or _is_sensitive_key(key)
    if isinstance(value, dict):
        found: list[str] = []
        for name, item in value.items():
            found.extend(find_leaks(item, path=f"{path}.{name}", key=str(name), _secret=secret))
        return found
    if isinstance(value, list):
        found = []
        for index, item in enumerate(value):
            found.extend(find_leaks(item, path=f"{path}[{index}]", key=key, _secret=secret))
        return found
    if not isinstance(value, str):
        return []
    reason = _leaf_leak(key, value, secret=secret)
    return [f"{path}: {reason}"] if reason else []
