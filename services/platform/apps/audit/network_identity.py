"""Where someone connected from: shown to administrators only (#689).

Audit rows carry IP addresses, user agents and session keys, both in their own
columns and inside recorded values. Other staff roles keep the audit log without them.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from apps.common.decorators import is_administrator

HIDDEN = "[hidden]"

# Fragments that name a network identity wherever they appear in a recorded key, whether the
# key came from a model field, a request header (HTTP_X_FORWARDED_FOR) or a nested dict.
_IDENTITY_KEY_FRAGMENTS = ("ip_address", "client_ip", "remote_addr", "remote_ip", "forwarded", "user_agent", "session")

# Runs of address characters; each one is checked with ipaddress, so ordinary words and numbers stay.
_ADDRESS_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]{2,}")


def can_see_network_identity(user: Any) -> bool:
    return is_administrator(user)


def _is_identity_key(key: object) -> bool:
    name = str(key).lower().replace("-", "_").removeprefix("http_")
    return name == "ip" or name.endswith("_ip") or any(fragment in name for fragment in _IDENTITY_KEY_FRAGMENTS)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _hide_address(match: re.Match[str]) -> str:
    token = match.group(0)
    core = token.strip(".:")
    host, separator, port = core.rpartition(":")
    if _is_address(core) or (separator and port.isdigit() and _is_address(host)):
        return HIDDEN
    return token


def _hide_addresses_in_text(text: str) -> str:
    """Every IPv4 or IPv6 address in free text, with or without a port, replaced."""
    return _ADDRESS_CANDIDATE.sub(_hide_address, text)


def redact_network_identity(value: Any) -> Any:
    """A copy of recorded values with every address, user agent and session key hidden.

    Identity-named keys lose their whole value, addresses used as keys are renamed, and
    addresses inside any other text are replaced where they stand.
    """
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            shown_key = f"{HIDDEN} {index}" if isinstance(key, str) and _is_address(key) else key
            redacted[shown_key] = HIDDEN if _is_identity_key(key) else redact_network_identity(item)
        return redacted
    if isinstance(value, list):
        return [redact_network_identity(item) for item in value]
    if isinstance(value, str):
        return _hide_addresses_in_text(value)
    return value
