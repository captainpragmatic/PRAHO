"""Read-only plan-change safety selector; old enforcement receipts never count."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone
from django.utils.dateparse import parse_datetime

if TYPE_CHECKING:
    from apps.provisioning.service_models import Service


def current_safety_used_bytes(service: Service) -> int | None:  # noqa: PLR0911 -- Independent scope, terminal-state, strict time, identity and quantity refusals.
    from apps.provisioning.hosting_limit_native import (  # noqa: PLC0415 -- Shared closed parser.
        quantity,
        validate_identity,
    )
    from apps.provisioning.hosting_safety_scope import SAFETY_TTL, current_safety_scope  # noqa: PLC0415
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
            or set(result) != {"schema", "scope", "observed_at", "identity", "components", "used_bytes"}
            or type(result["schema"]) is not int
            or result["schema"] != 1
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
        return used if used == max(quantity(value) for value in parts.values()) else None
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
