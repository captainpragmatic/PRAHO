"""Closed JSON encoding of the pure warning policy's durable state."""

from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID

from .hosting_warning_policy import Resource, WarningEpisode, WarningLevel, WarningScope, WarningState


def scope_snapshot(scope: WarningScope) -> dict[str, object]:
    return {
        "resource": scope.resource,
        "service_id": scope.service_id,
        "customer_id": scope.customer_id,
        "owner_scope": str(scope.owner_scope),
        "period_start": scope.period_start.isoformat() if scope.period_start else None,
        "period_end": scope.period_end.isoformat() if scope.period_end else None,
        "period_timezone": scope.period_timezone,
    }


def state_snapshot(state: WarningState) -> dict[str, object]:
    return {
        "version": 1,
        "scope": scope_snapshot(state.scope),
        "condition": int(state.condition) if state.condition else None,
        "episodes": [
            {
                "threshold": int(item.threshold),
                "generation": item.generation,
                "latched": item.latched,
                "below_hour": item.below_hour.isoformat() if item.below_hour else None,
            }
            for item in state.episodes
        ],
        "last_observed_at": state.last_observed_at.isoformat() if state.last_observed_at else None,
        "last_used_bytes": state.last_used_bytes,
        "last_quality": state.last_quality,
        "operational_allowance_bytes": state.operational_allowance_bytes,
        "operational_revision": state.operational_revision,
    }


def _time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Stored warning timestamp is invalid")
    return datetime.fromisoformat(value)


def _integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("Stored warning quantity is invalid")
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)


def scope_from_snapshot(raw: object) -> WarningScope:
    if not isinstance(raw, dict) or set(raw) != {
        "resource",
        "service_id",
        "customer_id",
        "owner_scope",
        "period_start",
        "period_end",
        "period_timezone",
    }:
        raise ValueError("Stored warning scope is invalid")
    zone = raw["period_timezone"]
    if zone is not None and not isinstance(zone, str):
        raise ValueError("Stored warning timezone is invalid")
    return WarningScope(
        resource=cast("Resource", raw["resource"]),
        service_id=_integer(raw["service_id"]),
        customer_id=_integer(raw["customer_id"]),
        owner_scope=UUID(str(raw["owner_scope"])),
        period_start=_time(raw["period_start"]),
        period_end=_time(raw["period_end"]),
        period_timezone=zone,
    )


def state_from_snapshot(raw: object) -> WarningState:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "version",
            "scope",
            "condition",
            "episodes",
            "last_observed_at",
            "last_used_bytes",
            "last_quality",
            "operational_allowance_bytes",
            "operational_revision",
        }
        or type(raw["version"]) is not int
        or raw["version"] != 1
    ):
        raise ValueError("Stored warning policy version is invalid")
    episodes = raw["episodes"]
    if not isinstance(episodes, list):
        raise ValueError("Stored warning episodes are invalid")
    restored = []
    for item in episodes:
        if not isinstance(item, dict) or set(item) != {"threshold", "generation", "latched", "below_hour"}:
            raise ValueError("Stored warning episode is invalid")
        restored.append(
            WarningEpisode(
                threshold=WarningLevel(_integer(item["threshold"])),
                generation=_integer(item["generation"]),
                latched=item["latched"],
                below_hour=_time(item["below_hour"]),
            )
        )
    return WarningState(
        scope=scope_from_snapshot(raw["scope"]),
        condition=WarningLevel(_integer(raw["condition"])) if raw["condition"] is not None else None,
        episodes=tuple(restored),
        last_observed_at=_time(raw["last_observed_at"]),
        last_used_bytes=_optional_integer(raw["last_used_bytes"]),
        last_quality=raw["last_quality"],
        operational_allowance_bytes=_optional_integer(raw["operational_allowance_bytes"]),
        operational_revision=_optional_integer(raw["operational_revision"]),
    )
