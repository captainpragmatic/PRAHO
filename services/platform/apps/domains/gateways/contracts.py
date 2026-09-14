"""Small validation primitives shared by the documented registrar contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from apps.domains.domain_names import canonicalize_domain_name

from .errors import RegistrarAPIError, RegistrarErrorCode


def invalid_response(message: str) -> RegistrarAPIError:
    """Only describe the contract violation; never include provider payloads/PII."""
    return RegistrarAPIError(message, code=RegistrarErrorCode.INVALID_RESPONSE)


def api_endpoint(value: str, hosts: frozenset[str], path: str, ports: frozenset[int]) -> str:
    """Validate the configured API origin before credentials are accessed."""
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname in hosts
            and (parsed.port or 443) in ports
            and parsed.path.rstrip("/") == path
            and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
        )
    except ValueError:
        valid = False
    if not valid:
        raise RegistrarAPIError("Invalid registrar API endpoint", code=RegistrarErrorCode.NOT_CONFIGURED)
    return value.rstrip("/")


def parse_date(value: object, *, local_timezone: str | None = None) -> datetime | None:
    """Parse an aware timestamp; refuse missing offsets and ambiguous local times.

    ROTLD v2 examples omit offsets. Their documented server-local dates are
    interpreted in Europe/Bucharest. Both folds and nonexistent DST times remain
    unconfirmed instead of silently choosing a different instant.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        if local_timezone is None:
            return None
        local = parsed.replace(tzinfo=ZoneInfo(local_timezone))
        if local.utcoffset() != local.replace(fold=1).utcoffset():
            return None
        if local.astimezone(UTC).astimezone(local.tzinfo).replace(tzinfo=None) != parsed:
            return None
        parsed = local
    return parsed.astimezone(UTC)


def string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise invalid_response("Expected a list of strings")
    return value


def domain_identity(value: object, expected: str) -> str:
    if not isinstance(value, str) or canonicalize_domain_name(value) != canonicalize_domain_name(expected):
        raise invalid_response("Registrar returned a different or missing domain identity")
    return canonicalize_domain_name(value)


def required_contact(data: dict[str, Any], fields: tuple[str, ...]) -> None:
    missing = [field for field in fields if not isinstance(data.get(field), str) or not data[field].strip()]
    if missing:
        raise RegistrarAPIError(
            f"Missing registrant fields: {', '.join(missing)}", code=RegistrarErrorCode.INVALID_REGISTRANT_DATA
        )
