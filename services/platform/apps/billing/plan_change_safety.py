"""Read-only plan-change safety selector; old enforcement receipts never count."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from django.utils import timezone
from django.utils.dateparse import parse_datetime

if TYPE_CHECKING:
    from apps.provisioning.service_models import Service


@dataclass(frozen=True)
class SafetySnapshot:
    used_bytes: int
    available_bytes: int
    capacity_baseline_kib: int | None
    quota_protocol: int
    observed_at: datetime


def current_safety_used_bytes(service: Service) -> int | None:
    snapshot = current_safety_snapshot(service)
    return snapshot.used_bytes if snapshot is not None else None


def downgrade_allowance_mib(service: Service, assigned_mib: int, *, effective_at: datetime) -> int:
    """A current verified R counts only while valid at the agreed boundary.

    The commercial admission primes exact current enforcement under Service.
    Missing proof contributes no R; native E never contributes to quote fit.
    Assignment later clamps the same fixed R to the target's purchased base.
    """
    from apps.provisioning.hosting_raise_policy import RaiseTerms, maximum_raise_mib  # noqa: PLC0415

    terms = service.__dict__.get("_hosting_current_overlay_terms")
    if (
        assigned_mib <= 0
        or service.__dict__.get("_hosting_current_verified") is not True
        or not isinstance(terms, RaiseTerms)
        or terms.expires_at is None
        or terms.expires_at <= max(effective_at, timezone.now())
    ):
        return assigned_mib
    return assigned_mib + min(terms.extra_mib, maximum_raise_mib(assigned_mib))


def current_safety_snapshot(service: Service) -> SafetySnapshot | None:  # noqa: PLR0911 -- Independent scope, terminal-state, strict time, identity and quantity refusals.
    from apps.provisioning.hosting_limit_native import (  # noqa: PLC0415 -- Shared closed parser.
        quantity,
        validate_identity,
    )
    from apps.provisioning.hosting_safety_scope import SAFETY_SCHEMA, SAFETY_TTL, current_safety_scope  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import (  # noqa: PLC0415
        SAFETY_OBSERVATION_OPERATION,
        VirtualminProvisioningJob,
    )

    scope = current_safety_scope(service.pk)
    if scope is None:
        return None
    job = (
        VirtualminProvisioningJob.objects.filter(operation=SAFETY_OBSERVATION_OPERATION, account_id=scope["account_id"])
        .order_by("-created_at")
        .first()
    )
    if job is None or job.status != "completed" or job.completed_at is None:
        return None
    result = job.result
    try:
        if (
            not isinstance(result, dict)
            or set(result)
            != {
                "schema",
                "scope",
                "observed_at",
                "identity",
                "components",
                "used_bytes",
                "available_bytes",
                "capacity_baseline_kib",
                "quota_protocol",
            }
            or type(result["schema"]) is not int
            or result["schema"] != SAFETY_SCHEMA
            or result["scope"] != scope
            or job.parameters.get("scope") != scope
        ):
            return None
        observed = parse_datetime(result["observed_at"]) if isinstance(result["observed_at"], str) else None
        now = timezone.now()
        if (
            observed is None
            or timezone.is_naive(observed)
            or not observed <= job.completed_at <= now
            or not observed <= now <= observed + SAFETY_TTL
        ):
            return None
        identity = validate_identity(result["identity"])
        if identity["domain"] != scope["domain"] or any(
            identity.get(key) != value for key, value in scope["native_identity"].items()
        ):
            return None
        parts = result["components"]
        if not isinstance(parts, dict) or set(parts) != {"uid_bytes", "gid_bytes", "canonical_bytes"}:
            return None
        used = quantity(result["used_bytes"])
        if used != max(quantity(value) for value in parts.values()):
            return None
        available = quantity(result["available_bytes"])
        baseline = result["capacity_baseline_kib"]
        if baseline is not None:
            baseline = quantity(baseline)
            if baseline == 0:
                return None
        protocol = quantity(result["quota_protocol"])
        return SafetySnapshot(used, available, baseline, protocol, observed)
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
