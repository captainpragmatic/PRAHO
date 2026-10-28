"""Transactional publication of bounded, configuration-bound check results."""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from .status_models import NodeResourceHourlySummary, SystemCheckState

logger = logging.getLogger(__name__)
LEVELS = frozenset({"green", "amber", "red", "grey", "unknown"})
STALE_AFTER = timedelta(minutes=25)
LEASE_TIME = timedelta(seconds=330)  # Normal Q2 task deadline (300s) plus termination margin.
MAX_DETAILS_LENGTH = 4096
MAX_PUBLIC_STRING = 500
MAX_PERCENT = 100
DETAIL_KEYS = frozenset(
    {
        "name",
        "message",
        "detail",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "source",
        "measurement_time_known",
        "run_id",
        "offsite_completed_at",
        "attempt_at",
        "due_at",
        "schedule",
        "schedule_timezone",
        "destination",
        "backup_count",
        "expected_count",
        "failed_count",
        "runner_enabled",
        "configuration_applied",
        "command_version",
        "scan_after",
    }
)
PublicValue = str | float | int | bool | None


@dataclass(frozen=True)
class ResourceValues:
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_percent: float | None = None

    def details(self) -> dict[str, PublicValue]:
        return {
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "disk_percent": self.disk_percent,
            "source": "virtualmin_info",
            "measurement_time_known": False,
        }


@dataclass(frozen=True)
class CheckClaim:
    state_id: UUID
    token: UUID
    generation: int
    sequence: int
    input_identity: str
    started_at: datetime


@dataclass(frozen=True)
class Observation:
    level: str
    reason: str
    details: Mapping[str, PublicValue] = field(default_factory=dict)
    resources: ResourceValues | None = None
    scheduled: bool = False


def claim_check(
    check_key: str, *, identity: str, node_id: UUID | None = None, lease_time: timedelta = LEASE_TIME
) -> CheckClaim | None:
    """Claim one bounded refresh; overlapping attempts share the current evidence."""
    if not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", check_key) or not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise ValueError("Invalid check identity")
    with transaction.atomic():
        if node_id is not None:
            from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

            if not VirtualminServer.objects.select_for_update().filter(pk=node_id).exists():
                return None
        state, _ = SystemCheckState.objects.get_or_create(check_key=check_key, node_id=node_id)
        state = SystemCheckState.objects.select_for_update().get(pk=state.pk)
        now = timezone.now()
        if state.input_identity == identity and state.lease_until and state.lease_until > now:
            return None
        if state.input_identity != identity:
            state.configuration_generation += 1
            state.input_identity = identity
            state.verified_generation = None
            state.level = "unknown"
            state.reason = "configuration_changed"
            state.changed_at = now
        state.sequence += 1
        state.claim_token = uuid.uuid4()
        state.lease_until = now + lease_time
        state.last_attempt_at = now
        state.save()
        return CheckClaim(state.id, state.claim_token, state.configuration_generation, state.sequence, identity, now)


def _public_details(observation: Observation) -> dict[str, PublicValue]:
    if observation.level not in LEVELS or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", observation.reason):
        raise ValueError("Invalid observation status")
    public = dict(observation.details)
    for value in public.values():
        if type(value) not in {str, float, int, bool, type(None)}:
            raise ValueError("Public check details must be scalar values")
        if isinstance(value, str) and len(value) > MAX_PUBLIC_STRING:
            raise ValueError("Public check detail is too long")
    if set(public) - DETAIL_KEYS or len(json.dumps(public, allow_nan=False)) > MAX_DETAILS_LENGTH:
        raise ValueError("Unsupported public check details")
    return public


def finish_check(
    claim: CheckClaim,
    *,
    identity: str | Callable[[], str],
    observation: Observation,
    on_accept: Callable[[], None] | None = None,
) -> bool:
    """Publish only a still-owned observation of the same effective configuration."""
    level, reason = observation.level, observation.reason
    public = _public_details(observation)
    with transaction.atomic():
        # All node writers use server -> state lock order; deletion cannot resurrect evidence.
        node_id = SystemCheckState.objects.filter(pk=claim.state_id).values_list("node_id", flat=True).first()
        if node_id is not None:
            from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

            if not VirtualminServer.objects.select_for_update().filter(pk=node_id).exists():
                return False
        state = SystemCheckState.objects.select_for_update().filter(pk=claim.state_id).first()
        now = timezone.now()
        if not _owns_claim(state, claim, now):
            return False
        assert state is not None
        current_identity = identity() if callable(identity) else identity
        if state.input_identity != current_identity or claim.input_identity != current_identity:
            state.configuration_generation += 1
            state.input_identity = current_identity
            state.verified_generation = None
            state.level = "unknown"
            state.reason = "configuration_changed"
            state.claim_token = None
            state.lease_until = None
            state.save()
            return False
        if on_accept is not None:
            on_accept()
        changed = (state.level, state.reason) != (level, reason)
        state.level, state.reason, state.details = level, reason, public
        state.observed_at = now
        state.claim_token = None
        state.lease_until = None
        if level == "green":
            state.last_success_at = now
            state.verified_generation = state.configuration_generation
        if changed:
            state.changed_at = now
            logger.info("✅ [SystemStatus] Check %s changed to %s (%s)", state.check_key, level, reason)
        if observation.scheduled and observation.resources is not None and node_id is not None:
            slot = claim.started_at.astimezone(UTC).replace(
                minute=claim.started_at.minute // 10 * 10, second=0, microsecond=0
            )
            if state.last_scheduled_slot is None or slot > state.last_scheduled_slot:
                _aggregate(node_id, slot, observation.resources)
                state.last_scheduled_slot = slot
        state.save()
        return True


def _owns_claim(state: SystemCheckState | None, claim: CheckClaim, now: datetime) -> bool:
    return bool(
        state is not None
        and state.claim_token == claim.token
        and state.sequence == claim.sequence
        and state.configuration_generation == claim.generation
        and state.lease_until
        and state.lease_until > now
    )


def _aggregate(node_id: UUID, slot: datetime, resources: ResourceValues) -> None:
    hour = slot.replace(minute=0)
    row, _ = NodeResourceHourlySummary.objects.get_or_create(node_id=node_id, hour=hour)
    for name in ("cpu", "memory", "disk"):
        value = getattr(resources, f"{name}_percent")
        if value is None or not math.isfinite(value) or not 0 <= value <= MAX_PERCENT:
            continue
        setattr(row, f"{name}_sum", getattr(row, f"{name}_sum") + value)
        setattr(row, f"{name}_count", getattr(row, f"{name}_count") + 1)
        peak = getattr(row, f"{name}_peak")
        setattr(row, f"{name}_peak", value if peak is None else max(peak, value))
    row.save()


def display_level(state: SystemCheckState, *, current_identity: str | None = None) -> str:
    """A snapshot's age is distinct from the age of any backup it describes."""
    if state.observed_at is None or timezone.now() - state.observed_at > STALE_AFTER:
        return "unknown"
    if state.node_id is not None and current_identity is None:
        from apps.common.system_status import node_input_identity  # noqa: PLC0415

        node = state.node
        if node is None:
            return "unknown"
        current_identity = node_input_identity(node)
    if current_identity is not None and state.input_identity != current_identity:
        return "unknown"
    return state.level


def prune_hourly_summaries() -> int:
    """Bound each sweep's transaction and leave the next sweep to finish large backlogs."""
    keys = list(
        NodeResourceHourlySummary.objects.filter(hour__lt=timezone.now() - timedelta(days=30))
        .order_by("hour")
        .values_list("pk", flat=True)[:1000]
    )
    return NodeResourceHourlySummary.objects.filter(pk__in=keys).delete()[0]
