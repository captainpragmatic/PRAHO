"""Strict public mail receipts; Portal carries no native payload or enrollment authority."""

from __future__ import annotations

import re
from typing import Any, TypedDict

from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_aware

from apps.api_client.services import PlatformAPIError

_PORTS = {"imap_tls": 993, "pop3_tls": 995, "submission_tls": 465}
_MAX_TIMESTAMP_LENGTH = 64
_MAX_HOSTNAME_LENGTH = 253
_STATUSES = frozenset(
    {"queued", "running", "awaiting_dns", "needs_review", "completed", "failed", "cancelled", "unknown"}
)
_CHECKPOINTS = frozenset({"not_started", "claimed", "preflight", "native_inflight", "unknown"})
_ERRORS = frozenset(
    {
        "",
        "mail_operation_unrecognized",
        "mail_native_outcome_unknown",
        "mail_execution_interrupted",
        "mail_native_preparation_failed",
        "mail_execution_ownership_expired",
        "mail_execution_state_uncertain",
        "mail_execution_forbidden",
        "mail_generation_changed",
        "mail_account_unavailable",
        "mail_hosting_held",
        "mail_operation_active",
        "mail_mode_conflict",
        "mail_execution_invalid_consent",
        "mail_prerequisites_expired",
    }
)
_NAME = re.compile(r"[a-z0-9]{8}(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


class PublicMailOperation(TypedDict):
    intent: str
    status: str
    checkpoint: str
    error_code: str
    created_at: str | None
    updated_at: str | None
    resume_after: str | None


class PublicMailStatus(TypedDict):
    version: int
    applicability: str
    mode: str
    enrolled: bool | None
    verification: str
    verified_at: str | None
    account_name: str | None
    client_ports: dict[str, int]
    verified_login: str | None
    requires_owner_consent: bool
    operation: PublicMailOperation | None


def _unavailable() -> PlatformAPIError:
    return PlatformAPIError("Mail status is unavailable")


def _choice(value: object, choices: set[str] | frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise _unavailable()
    return value


def _timestamp(value: object, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > _MAX_TIMESTAMP_LENGTH:
        raise _unavailable()
    try:
        parsed = parse_datetime(value)
    except ValueError as error:
        raise _unavailable() from error
    if parsed is None or not is_aware(parsed):
        raise _unavailable()
    return value


def _name(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > _MAX_HOSTNAME_LENGTH or _NAME.fullmatch(value) is None:
        raise _unavailable()
    return value


def _operation(value: object) -> PublicMailOperation | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not value.keys() >= {
        "intent",
        "status",
        "checkpoint",
        "error_code",
        "created_at",
        "updated_at",
        "resume_after",
    }:
        raise _unavailable()
    return {
        "intent": _choice(value["intent"], {"enable", "disable", "unknown"}),
        "status": _choice(value["status"], _STATUSES),
        "checkpoint": _choice(value["checkpoint"], _CHECKPOINTS),
        "error_code": _choice(value["error_code"], _ERRORS),
        "created_at": _timestamp(value["created_at"], required=True),
        "updated_at": _timestamp(value["updated_at"], required=True),
        "resume_after": _timestamp(value["resume_after"]),
    }


def _consistent(status: PublicMailStatus) -> None:
    mode, enrolled, verification = status["mode"], status["enrolled"], status["verification"]
    expected = {"external": False, "hosted": True, "unknown": None}[mode]
    if enrolled is not expected:
        raise _unavailable()
    if mode != "hosted" and verification != "unverified":
        raise _unavailable()
    if mode == "hosted" and verification not in {"current", "stale"}:
        raise _unavailable()
    if verification == "current" and (status["verified_at"] is None or status["account_name"] is None):
        raise _unavailable()
    if status["applicability"] == "applicable" and status["client_ports"] != _PORTS:
        raise _unavailable()
    if status["applicability"] == "not_applicable" and (
        mode != "external"
        or status["account_name"] is not None
        or status["client_ports"]
        or status["operation"] is not None
    ):
        raise _unavailable()


def mail_status_receipt(response: object) -> PublicMailStatus:
    """Validate version1 and return only the public fields this consumer understands."""
    if not isinstance(response, dict) or response.get("success") is not True:
        raise _unavailable()
    data = response.get("data")
    value = data.get("mail_status") if isinstance(data, dict) else None
    if not isinstance(value, dict) or not value.keys() >= PublicMailStatus.__annotations__.keys():
        raise _unavailable()
    if type(value["version"]) is not int or value["version"] != 1:
        raise _unavailable()
    if value["verified_login"] is not None or value["requires_owner_consent"] is not True:
        raise _unavailable()
    enrolled: Any = value["enrolled"]
    ports = value["client_ports"]
    if (
        (enrolled is not None and type(enrolled) is not bool)
        or not isinstance(ports, dict)
        or ports not in ({}, _PORTS)
        or any(type(port) is not int for port in ports.values())
    ):
        raise _unavailable()
    status: PublicMailStatus = {
        "version": 1,
        "applicability": _choice(value["applicability"], {"applicable", "not_applicable"}),
        "mode": _choice(value["mode"], {"external", "hosted", "unknown"}),
        "enrolled": enrolled,
        "verification": _choice(value["verification"], {"unverified", "current", "stale"}),
        "verified_at": _timestamp(value["verified_at"]),
        "account_name": _name(value["account_name"]),
        "client_ports": dict(ports),
        "verified_login": None,
        "requires_owner_consent": True,
        "operation": _operation(value["operation"]),
    }
    _consistent(status)
    return status
