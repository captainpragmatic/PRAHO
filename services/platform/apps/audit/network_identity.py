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

# Keys that name a network identity wherever they appear in recorded values.
_IDENTITY_KEYS = frozenset(
    {
        "ip",
        "ip_address",
        "client_ip",
        "remote_addr",
        "remote_ip",
        "forwarded_for",
        "x_forwarded_for",
        "user_agent",
        "session_key",
        "session_id",
    }
)

# Search text made only of address characters may be probing for an address.
_ADDRESS_LIKE = re.compile(r"^[0-9a-fA-F.:]+$")


def can_see_network_identity(user: Any) -> bool:
    return is_administrator(user)


def _is_identity_key(key: object) -> bool:
    name = str(key).lower().replace("-", "_")
    return name in _IDENTITY_KEYS or name.endswith(("_ip", "_ip_address", "_user_agent"))


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def redact_network_identity(value: Any) -> Any:
    """A copy of recorded values with every address, user agent and session key hidden."""
    if isinstance(value, dict):
        return {key: HIDDEN if _is_identity_key(key) else redact_network_identity(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_network_identity(item) for item in value]
    if isinstance(value, str) and _is_address(value):
        return HIDDEN
    return value


def is_address_like(text: str) -> bool:
    """Search text that could match part of an address (digits, hex, dots and colons only)."""
    return bool(_ADDRESS_LIKE.match(text.strip()))
