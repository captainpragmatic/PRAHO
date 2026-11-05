"""Local customer-safe allowance facts, independent of mutable catalog rows."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.utils import timezone

if TYPE_CHECKING:
    from .service_models import Service
    from .virtualmin_models import VirtualminAccount


def prime_current_verification(
    services: list[Service], accounts: dict[int, VirtualminAccount], *, at: datetime | None = None
) -> None:
    """One execution/credential batch, with no per-service reads or remote calls."""
    from .hosting_limit_execution_models import HostingLimitExecution  # noqa: PLC0415
    from .hosting_limit_native import current_verified_binding  # noqa: PLC0415
    from .hosting_node_policy import POLICY_VERSION, verify_quota_evidence  # noqa: PLC0415
    from .hosting_raise_models import ServiceHostingRaise  # noqa: PLC0415 -- One overlay batch; no per-service reads.
    from .hosting_raise_service import raise_terms_for  # noqa: PLC0415 -- Pure counterpart for preloaded rows.
    from .virtualmin_security import connection_identities  # noqa: PLC0415

    if not services:
        return
    now = at or timezone.now()
    overlays = {
        row.service_id: row
        for row in ServiceHostingRaise.objects.filter(service_id__in=[service.pk for service in services])
    }
    candidates = {}
    for service in services:
        service.__dict__["_hosting_raise_row"] = overlays.get(service.pk)
        service.__dict__["_hosting_current_verified"] = False
        service.__dict__["_hosting_operational_verified"] = False
        service.__dict__["_hosting_current_overlay_terms"] = None
        account = accounts.get(service.pk)
        managed = bool(account is not None and getattr(account, "quota_managed", False))
        service.__dict__["_hosting_enforcement_state"] = (
            "managed" if managed else "unmanaged" if account is not None else "not_provisioned"
        )
        limits = getattr(service, "hosting_limits", None)
        if (
            limits is not None
            and limits.verified_at
            and limits.verified_receipt
            and limits.operational_revision is not None
            and limits.applied_revision == limits.operational_revision
            and service.pk in accounts
            and managed
        ):
            candidates[service.pk] = service
    if not candidates:
        return
    servers = {accounts[pk].server_id: accounts[pk].server for pk in candidates}
    try:
        identities = connection_identities(servers.values())
    except (ValidationError, OSError, ValueError):
        return
    records: dict[int, list[dict[str, Any]]] = {}
    for execution in HostingLimitExecution.objects.filter(
        phase="completed",
        job__hosting_limit_application__service_id__in=candidates,
    ).select_related("job__hosting_limit_application"):
        application = execution.job.hosting_limit_application
        if application is None:
            continue
        records.setdefault(application.service_id, []).append(
            {
                "phase": execution.phase,
                "service_id": application.service_id,
                "owner_id": execution.owner_id,
                "service_revision": execution.service_revision,
                "overlay_revision": execution.overlay_revision,
                "overlay_extra_mib": application.overlay_extra_mib,
                "overlay_expires_at": application.overlay_expires_at,
                "server_id": execution.job.server_id,
                "connection_identity": execution.connection_identity,
                "identity": execution.identity,
                "receipt": execution.receipt,
                "account_epoch": execution.account_epoch,
                "token": str(execution.job.execution_token),
            }
        )
    for pk, service in candidates.items():
        account, limits = accounts[pk], service.hosting_limits
        if limits.operational_revision is None:
            continue
        policy = getattr(account.server, "hosting_policy", None)
        identity = identities.get(account.server_id)
        if (
            policy is None
            or identity is None
            or policy.operation
            or not policy.quota_adopted
            or not policy.quota_verified_at
            or policy.policy_version != POLICY_VERSION
            or policy.connection_identity != identity
        ):
            continue
        try:
            evidence = verify_quota_evidence(policy.quota_evidence, identity)
        except (ValidationError, ValueError, TypeError):
            continue
        node_identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        overlay = raise_terms_for(overlays.get(pk), service.customer_id, at=now)
        service.__dict__["_hosting_current_overlay_terms"] = overlay
        verified = any(
            limits.applied_overlay_revision == overlay.revision
            and record["receipt"] == limits.verified_receipt
            and record["account_epoch"] == account.quota_generation
            and current_verified_binding(
                record=record,
                service_id=pk,
                owner_id=service.customer_id,
                revision=limits.operational_revision,
                server_id=account.server_id,
                connection_identity=identity,
                node_identity=node_identity,
                overlay_revision=overlay.revision,
                overlay_extra_mib=overlay.extra_mib,
                overlay_expires_at=overlay.expires_at,
            )
            and record["identity"].get("domain") == account.domain
            for record in records.get(pk, [])
        )
        service.__dict__["_hosting_operational_verified"] = verified
        service.__dict__["_hosting_current_verified"] = verified and limits.operational_revision == limits.revision


def allowance_gib(mib: int | None) -> float | None:
    """Keep unknown distinct from explicit unlimited zero."""
    return mib / 1024 if mib is not None else None


def operational_allowances(service: Service) -> tuple[int | None, int | None]:
    limits = getattr(service, "hosting_limits", None)
    if limits is None:
        return None, None
    return limits.operational_disk_allowance_mib, limits.operational_bandwidth_allowance_mib


def usage_percentage(used_mib: int | float, allowance_mib: int | None) -> float | None:
    return round(used_mib / allowance_mib * 100, 1) if allowance_mib else None


def _amounts(disk: int | None, bandwidth: int | None) -> dict[str, object]:
    return {
        "disk_mib": disk,
        "bandwidth_mib": bandwidth,
        "disk_gib": allowance_gib(disk),
        "bandwidth_gib": allowance_gib(bandwidth),
    }


def hosting_limits_summary(service: Service) -> dict[str, object]:
    """Only purchased allowances escape this boundary; native headroom stays private.

    The operational denominator deliberately stays at its prior revision while
    a newer desired assignment is waiting. Applied values are historical proof,
    rather than permission to advertise the desired cap as already enforced.
    """
    limits = getattr(service, "hosting_limits", None)
    if limits is None:
        return {
            "state": "unknown",
            "revision": None,
            "assigned": _amounts(None, None),
            "operational": {"revision": None, **_amounts(None, None)},
            "verified": None,
            "enforcement_state": "unknown",
            "managed": False,
        }
    pending = limits.revision > 1 and limits.operational_revision != limits.revision
    state = "pending" if pending else "unverified"
    # Current-execution validation is supplied by the native worker's pure
    # verifier and primed on request-scoped instances. Missing proof fails closed.
    if not pending and getattr(service, "_hosting_current_verified", False):
        state = "verified"
    if limits.disk_allowance_mib is None and limits.bandwidth_allowance_mib is None and not pending:
        state = "unknown"
    verified = None
    if limits.applied_revision is not None and limits.verified_receipt:
        verified = {
            "revision": limits.applied_revision,
            **_amounts(limits.applied_disk_allowance_mib, limits.applied_bandwidth_allowance_mib),
            "at": limits.verified_at.isoformat() if limits.verified_at else None,
        }
    return {
        "state": state,
        "revision": limits.revision,
        "assigned": _amounts(limits.disk_allowance_mib, limits.bandwidth_allowance_mib),
        "operational": {
            "revision": limits.operational_revision,
            **_amounts(limits.operational_disk_allowance_mib, limits.operational_bandwidth_allowance_mib),
        },
        "verified": verified,
        "enforcement_state": getattr(service, "_hosting_enforcement_state", "unknown"),
        "managed": getattr(service, "_hosting_enforcement_state", "unknown") == "managed",
        "provenance": {"disk": limits.disk_source, "bandwidth": limits.bandwidth_source},
    }
