"""Batched customer-safe warning conditions; request reads never contact a node."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, cast

from django.conf import settings
from django.utils import timezone

from .hosting_limit_models import ServiceHostingLimits
from .hosting_warning_models import HostingWarningState
from .hosting_warning_observation import MIB, STALE_AFTER, _reading, warning_scope
from .hosting_warning_policy import Resource, WarningContext, WarningReading, evaluate_warning
from .hosting_warning_state import state_from_snapshot
from .virtualmin_usage_models import AccountUsageState

if TYPE_CHECKING:
    from .service_models import Service


def _unknown() -> dict[str, object]:
    return {
        "condition": None,
        "availability": "unknown",
        "observed_at": None,
        "used_bytes": None,
        "operational_allowance_mib": None,
        "period_start": None,
        "period_end": None,
        "period_timezone": None,
    }


def warning_resource_data(
    service: Service,
    usage: AccountUsageState,
    cursor: HostingWarningState | None,
    limits: ServiceHostingLimits | None,
    at: datetime,
) -> dict[str, object]:
    from .virtualmin_usage_service import month  # noqa: PLC0415 -- Selector reuses the canonical operator month.

    result = _unknown()
    if cursor is None or limits is None:
        return result
    if cursor.resource not in {"disk", "bandwidth"}:
        return result
    resource = cast("Resource", cursor.resource)
    start, end = month(at)
    try:
        scope = warning_scope(resource, service.pk, service.customer_id, usage.owner_scope, at)
        previous = state_from_snapshot(cursor.policy_state)
        reading, _stored = _reading(usage, resource, scope, observed=at, partial_changed=False)
        if (
            (
                reading is None
                or (
                    reading.quality == "stale"
                    and previous.last_observed_at is not None
                    and previous.last_observed_at >= reading.observed_at
                )
            )
            and previous.scope == scope
            and previous.last_quality == "partial"
            and previous.last_observed_at
        ):
            reading = WarningReading(
                scope,
                previous.last_observed_at,
                previous.last_used_bytes,
                "partial" if previous.last_observed_at >= at - STALE_AFTER else "stale",
            )
        allowance = (
            limits.operational_disk_allowance_mib if resource == "disk" else limits.operational_bandwidth_allowance_mib
        )
        transition = evaluate_warning(
            previous,
            context=WarningContext(scope, None if allowance is None else allowance * MIB, limits.operational_revision),
            reading=reading,
        )
    except ValueError:
        return result
    current = transition.state
    return {
        "condition": int(current.condition) if current.condition else None,
        "availability": transition.availability,
        "observed_at": current.last_observed_at.isoformat() if current.last_observed_at else None,
        "used_bytes": current.last_used_bytes,
        "operational_allowance_mib": allowance,
        "period_start": start.isoformat() if resource == "bandwidth" else None,
        "period_end": end.isoformat() if resource == "bandwidth" else None,
        "period_timezone": settings.TIME_ZONE if resource == "bandwidth" else None,
    }


def prime_hosting_warnings(services: list[Service], *, at: datetime | None = None) -> None:
    """Fixed read batch, including blank/other-provider service results."""
    instant = at or timezone.now()
    for service in services:
        service.__dict__["_hosting_warnings"] = {"disk": _unknown(), "bandwidth": _unknown()}
    service_map = {service.pk: service for service in services}
    states = list(
        AccountUsageState.objects.filter(account__service_id__in=service_map).select_related(
            "account",
            "disk_reading",
            "bandwidth_reading",
        )
    )
    cursors = {
        (row.account_id, row.resource): row
        for row in HostingWarningState.objects.filter(
            account_id__in=[state.account_id for state in states],
        )
    }
    limits = {row.service_id: row for row in ServiceHostingLimits.objects.filter(service_id__in=service_map)}
    for state in states:
        service = service_map[state.account.service_id]
        if (state.service_id_snapshot, state.customer_id_snapshot) != (service.pk, service.customer_id):
            continue
        service.__dict__["_hosting_warnings"] = {
            resource: warning_resource_data(
                service, state, cursors.get((state.account_id, resource)), limits=limits.get(service.pk), at=instant
            )
            for resource in ("disk", "bandwidth")
        }


def service_warning_data(service: Service) -> dict[str, object]:
    if "_hosting_warnings" not in service.__dict__:
        prime_hosting_warnings([service])
    return cast("dict[str, object]", service.__dict__["_hosting_warnings"])
