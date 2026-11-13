"""Closed native receipt contract. Virtualmin metadata alone never verifies a cap."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from django.utils.dateparse import parse_datetime

from .hosting_limit_policy import BYTES_PER_MIB, OVERLAY_QUOTA_PROTOCOL

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


# Older helpers omit these. backup_staging_left: a ~/.backup the home still holds (ADR-0075); absent means unknown.
OPTIONAL_PROBE_FIELDS = frozenset({"observation", "bandwidth_actions_safe", "quota_protocol", "backup_staging_left"})


@dataclass(frozen=True)
class VerifiedQuota:
    disk_limit_mib: int
    bandwidth_limit_mib: int
    safety_used_bytes: int
    available_bytes: int
    observed_at: datetime


@dataclass(frozen=True)
class VerifiedQuotaProbe:
    """Known current evidence; differing caps are not a successful application."""

    capacity_baseline_kib: int | None
    safety_used_bytes: int
    available_bytes: int
    observed_at: datetime


def current_verified_binding(  # noqa: PLR0913 -- Batch selectors supply preloaded scalar authority, never native I/O.
    *,
    record: Mapping[str, object],
    service_id: int,
    owner_id: int,
    revision: int,
    server_id: object,
    connection_identity: str,
    node_identity: Mapping[str, str],
    overlay_revision: int = 0,
    overlay_extra_mib: int = 0,
    overlay_expires_at: datetime | None = None,
) -> bool:
    """Pure current-state predicate; historical verified receipts remain visible separately.

    ``record`` is a values()/preloaded projection of execution and its job. This
    function performs zero queries, so list selectors can cache node policy once.
    """
    identity, receipt = record.get("identity"), record.get("receipt")
    return bool(
        record.get("phase") == "completed"
        and record.get("service_id") == service_id
        and record.get("owner_id") == owner_id
        and record.get("service_revision") == revision
        and record.get("overlay_revision", 0) == overlay_revision
        and record.get("overlay_extra_mib", 0) == overlay_extra_mib
        and record.get("overlay_expires_at") == overlay_expires_at
        and record.get("server_id") == server_id
        and record.get("connection_identity") == connection_identity
        and set(node_identity) == {"installation", "filesystem_uuid", "boot_id"}
        and isinstance(identity, dict)
        and isinstance(receipt, dict)
        and receipt.get("bandwidth_actions_safe") is True
        and (overlay_revision == 0 or receipt.get("quota_protocol") == OVERLAY_QUOTA_PROTOCOL)
        and all(identity.get(key) == value for key, value in node_identity.items())
        and receipt.get("identity") == identity
        and receipt.get("generation") == record.get("account_epoch")
        and receipt.get("token") == record.get("token")
    )


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
    require_bandwidth_actions_safe: bool = False,
) -> VerifiedQuota:
    """Verify an exact, recent result of the fenced application, including both kernel targets.

    Calling this on an arbitrary probe is NOT recovery: the caller must first obtain
    the native terminal receipt or fence the original token under the native lock.
    """
    if not isinstance(receipt, dict) or set(receipt) - OPTIONAL_PROBE_FIELDS != RECEIPT_FIELDS:
        raise ValueError("The native quota receipt has an unsupported shape")
    probe = verify_quota_probe(
        {key: value for key, value in receipt.items() if key not in {"token", "generation"}},
        identity=identity,
        now=now,
    )
    if str(UUID(token)) != token or receipt["token"] != token:
        raise ValueError("The native quota receipt belongs to another application")
    if quantity(receipt["generation"]) != quantity(generation) or generation == 0:
        raise ValueError("The native quota receipt belongs to another generation")
    if require_bandwidth_actions_safe and receipt.get("bandwidth_actions_safe") is not True:
        raise ValueError("Native bandwidth suspension and reactivation must remain disabled")
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
        observed_at=probe.observed_at,
    )


def verify_quota_probe(
    probe: object,
    *,
    identity: Mapping[str, str | int],
    now: datetime,
) -> VerifiedQuotaProbe:
    """Validate a fresh closed read without assuming old UID/GID/config caps agree.

    Explicit adoption can repair a known historical missing-uquota configuration.
    Only the final token-bound receipt may certify the new exact matching caps.
    """
    fields = RECEIPT_FIELDS - {"token", "generation"}
    if not isinstance(probe, dict) or set(probe) - OPTIONAL_PROBE_FIELDS != fields:
        raise ValueError("The native quota probe has an unsupported shape")
    if "quota_protocol" in probe and (
        type(probe["quota_protocol"]) is not int or probe["quota_protocol"] not in {1, 2}
    ):
        raise ValueError("The native quota protocol is unsupported")
    if any(key in probe and type(probe[key]) is not bool for key in ("bandwidth_actions_safe", "backup_staging_left")):
        raise ValueError("Native bandwidth action safety must be explicit")
    if (
        type(probe["schema"]) is not int
        or probe["schema"] != 1
        or validate_identity(probe["identity"]) != validate_identity(dict(identity))
    ):
        raise ValueError("The native quota probe belongs to another identity or policy")
    observed = parse_datetime(probe["observed_at"]) if isinstance(probe["observed_at"], str) else None
    if (
        observed is None
        or observed.utcoffset() is None
        or now.utcoffset() is None
        or not -timedelta(seconds=5) <= now - observed <= MAX_RECEIPT_AGE
    ):
        raise ValueError("The native quota probe is stale or has no trustworthy time")
    if probe["filesystem"] != "ext4" or any(
        probe[field] is not True for field in ("storage_qualified", "uid_enforced", "gid_enforced")
    ):
        raise ValueError("The native filesystem, storage or kernel enforcement is not qualified")
    for field in QUANTITY_FIELDS:
        quantity(probe[field])
    if "observation" in probe:
        canonical_observation(probe["observation"])
    positive = [
        probe[key] for key in ("uid_soft_kib", "uid_hard_kib", "gid_soft_kib", "gid_hard_kib") if probe[key] > 0
    ]
    return VerifiedQuotaProbe(
        capacity_baseline_kib=min(positive) if positive else None,
        safety_used_bytes=max(probe["uid_used_bytes"], probe["gid_used_bytes"]),
        available_bytes=probe["available_bytes"],
        observed_at=observed,
    )


def canonical_observation(value: object) -> int:
    """A distinct canonical numerator; kernel totals never stand in for missing data."""
    if not isinstance(value, dict) or set(value) != {"files_bytes", "database_bytes", "total_bytes"}:
        raise ValueError("The canonical disk observation has an unsupported shape")
    files, database, total = (quantity(value[key]) for key in ("files_bytes", "database_bytes", "total_bytes"))
    if files + database != total:
        raise ValueError("The canonical disk observation does not conserve allocated bytes")
    return total
