"""Closed native receipt contract. Virtualmin metadata alone never verifies a cap."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from django.utils.dateparse import parse_datetime

from .hosting_limit_policy import BYTES_PER_MIB

MAX_QUANTITY = (1 << 63) - 1
MAX_RECEIPT_AGE = timedelta(minutes=2)
IDENTITY_FIELDS = frozenset({"installation", "domain_id", "domain", "uid", "gid", "filesystem_uuid", "boot_id"})
QUANTITY_FIELDS = frozenset(
    {
        "uid_soft_kib",
        "uid_hard_kib",
        "gid_soft_kib",
        "gid_hard_kib",
        "uid_used_bytes",
        "gid_used_bytes",
        "available_bytes",
        "configured_quota_kib",
        "configured_uquota_kib",
        "configured_bandwidth_bytes",
    }
)
RECEIPT_FIELDS = QUANTITY_FIELDS | {
    "schema",
    "identity",
    "token",
    "generation",
    "observed_at",
    "filesystem",
    "storage_qualified",
    "uid_enforced",
    "gid_enforced",
}


@dataclass(frozen=True)
class VerifiedQuota:
    disk_limit_mib: int
    bandwidth_limit_mib: int
    safety_used_bytes: int
    available_bytes: int
    observed_at: datetime


def quantity(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_QUANTITY:
        raise ValueError("Native quota quantities must be explicit nonnegative integers")
    return value


def validate_identity(identity: object) -> dict[str, str | int]:
    if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
        raise ValueError("The native quota identity is incomplete")
    for key in ("installation", "filesystem_uuid", "boot_id"):
        if not isinstance(identity[key], str) or str(UUID(identity[key])) != identity[key]:
            raise ValueError("The native quota identity is invalid")
    for key in ("uid", "gid"):
        if not 0 < quantity(identity[key]) <= (1 << 32) - 2:
            raise ValueError("A tenant requires a non-root native UID and GID")
    for key, pattern in (("domain_id", r"[0-9]{1,30}"), ("domain", r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")):
        if not isinstance(identity[key], str) or re.fullmatch(pattern, identity[key]) is None:
            raise ValueError("The native quota domain identity is invalid")
    return dict(identity)


def verify_quota_receipt(  # noqa: PLR0913 -- All expected authority is mandatory and explicit.
    receipt: object,
    *,
    identity: Mapping[str, str | int],
    token: str,
    generation: int,
    disk_limit_mib: int,
    bandwidth_limit_mib: int,
    now: datetime,
) -> VerifiedQuota:
    """Verify an exact, recent result of the fenced application, including both kernel targets.

    Calling this on an arbitrary probe is NOT recovery: the caller must first obtain
    the native terminal receipt or fence the original token under the native lock.
    """
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("The native quota receipt has an unsupported shape")
    if (
        type(receipt["schema"]) is not int
        or receipt["schema"] != 1
        or validate_identity(receipt["identity"]) != validate_identity(dict(identity))
    ):
        raise ValueError("The native quota receipt belongs to a different identity or policy")
    if str(UUID(token)) != token or receipt["token"] != token:
        raise ValueError("The native quota receipt belongs to another application")
    if quantity(receipt["generation"]) != quantity(generation) or generation == 0:
        raise ValueError("The native quota receipt belongs to another generation")
    observed = parse_datetime(receipt["observed_at"]) if isinstance(receipt["observed_at"], str) else None
    if (
        observed is None
        or observed.utcoffset() is None
        or now.utcoffset() is None
        or not -timedelta(seconds=5) <= now - observed <= MAX_RECEIPT_AGE
    ):
        raise ValueError("The native quota receipt is stale or has no trustworthy time")
    if receipt["filesystem"] != "ext4" or any(
        receipt[field] is not True for field in ("storage_qualified", "uid_enforced", "gid_enforced")
    ):
        raise ValueError("The native filesystem, storage or kernel enforcement is not qualified")
    for field in QUANTITY_FIELDS:
        quantity(receipt[field])
    expected_kib = quantity(disk_limit_mib) * 1024
    if any(
        receipt[field] != expected_kib
        for field in (
            "uid_soft_kib",
            "uid_hard_kib",
            "gid_soft_kib",
            "gid_hard_kib",
            "configured_quota_kib",
            "configured_uquota_kib",
        )
    ):
        raise ValueError("Configured and kernel UID/GID caps must all match the desired hard limit")
    if receipt["configured_bandwidth_bytes"] != quantity(bandwidth_limit_mib) * BYTES_PER_MIB:
        raise ValueError("The native bandwidth configuration differs from the assignment")
    return VerifiedQuota(
        disk_limit_mib=disk_limit_mib,
        bandwidth_limit_mib=bandwidth_limit_mib,
        safety_used_bytes=max(receipt["uid_used_bytes"], receipt["gid_used_bytes"]),
        available_bytes=receipt["available_bytes"],
        observed_at=observed,
    )
