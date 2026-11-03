"""Pure owner-scoped warning episodes over canonical bytes and operational allowances.

Publication supplies current ownership/month context separately from a last-good
reading. This module neither reads a database nor decides whether mail may be sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Literal
from uuid import UUID

Resource = Literal["disk", "bandwidth"]
ReadingQuality = Literal["fresh", "stale", "partial", "unknown"]
Availability = Literal["fresh", "stale", "partial", "unknown", "unlimited"]
IgnoreReason = Literal["scope_mismatch", "older_reading", "same_reading"]


class WarningLevel(IntEnum):
    WARNING = 80
    HIGH = 95
    CRITICAL = 100


_REARM_BELOW = {WarningLevel.WARNING: 75, WarningLevel.HIGH: 90, WarningLevel.CRITICAL: 95}
_HOUR = timedelta(hours=1)


def _quantity(value: int | None, name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer" + (" or None" if optional else ""))


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Warning timestamps must be timezone-aware")


@dataclass(frozen=True)
class WarningScope:
    resource: Resource
    service_id: int
    customer_id: int
    owner_scope: UUID
    period_start: datetime | None = None
    period_end: datetime | None = None
    period_timezone: str | None = None

    def __post_init__(self) -> None:
        if self.resource not in ("disk", "bandwidth") or not isinstance(self.owner_scope, UUID):
            raise ValueError("A disk/bandwidth resource and actual owner-scope UUID are required")
        if any(type(value) is not int or value <= 0 for value in (self.service_id, self.customer_id)):
            raise ValueError("Positive service and customer identities are required")
        if self.resource == "disk":
            if any(value is not None for value in (self.period_start, self.period_end, self.period_timezone)):
                raise ValueError("Disk warning scope is continuous within its ownership scope")
        else:
            if self.period_start is None or self.period_end is None or not self.period_timezone:
                raise ValueError("Bandwidth warning scope requires exact period boundaries and timezone")
            _aware(self.period_start)
            _aware(self.period_end)
            if self.period_start >= self.period_end:
                raise ValueError("Bandwidth warning period must be non-empty")


@dataclass(frozen=True)
class WarningContext:
    scope: WarningScope
    operational_allowance_bytes: int | None
    operational_revision: int | None

    def __post_init__(self) -> None:
        _quantity(self.operational_allowance_bytes, "Operational allowance", optional=True)
        if self.operational_revision is not None and (
            type(self.operational_revision) is not int or self.operational_revision < 1
        ):
            raise ValueError("Operational revision must be positive or unknown")


@dataclass(frozen=True)
class WarningReading:
    """Canonical evidence; partial means a fresh proven bandwidth lower bound.

    Upstream publication owns identity and freshness validation. Stale partial
    evidence must be labelled stale, and native kernel totals are not canonical usage.
    """

    scope: WarningScope
    observed_at: datetime
    used_bytes: int | None
    quality: ReadingQuality = "fresh"

    def __post_init__(self) -> None:
        _aware(self.observed_at)
        _quantity(self.used_bytes, "Canonical usage", optional=True)
        if self.quality not in ("fresh", "stale", "partial", "unknown"):
            raise ValueError("Unsupported warning reading quality")


@dataclass(frozen=True)
class WarningEpisode:
    threshold: WarningLevel
    generation: int = 0
    latched: bool = False
    below_hour: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.threshold, WarningLevel) or type(self.latched) is not bool:
            raise ValueError("A typed warning threshold and boolean latch are required")
        _quantity(self.generation, "Warning episode generation")
        if self.latched and self.generation == 0:
            raise ValueError("A latched episode requires a generation")
        if self.below_hour is not None:
            _aware(self.below_hour)
            if (
                not self.latched
                or self.below_hour.utcoffset() != timedelta(0)
                or self.below_hour != self.below_hour.replace(minute=0, second=0, microsecond=0)
            ):
                raise ValueError("A below-hour marker must be one latched episode's UTC-hour bucket")


def _initial_episodes() -> tuple[WarningEpisode, ...]:
    return tuple(WarningEpisode(level) for level in WarningLevel)


@dataclass(frozen=True)
class WarningState:
    scope: WarningScope
    condition: WarningLevel | None = None
    episodes: tuple[WarningEpisode, ...] = field(default_factory=_initial_episodes)
    last_observed_at: datetime | None = None
    last_used_bytes: int | None = None
    last_quality: Literal["fresh", "partial"] | None = None
    operational_allowance_bytes: int | None = None
    operational_revision: int | None = None

    def __post_init__(self) -> None:
        if tuple(episode.threshold for episode in self.episodes) != tuple(WarningLevel):
            raise ValueError("Warning state must contain each ordered threshold exactly once")
        if self.condition is not None and not isinstance(self.condition, WarningLevel):
            raise ValueError("The current warning condition must be a typed level or None")
        if self.last_observed_at is not None:
            _aware(self.last_observed_at)
        _quantity(self.last_used_bytes, "Last canonical usage", optional=True)
        if self.last_quality not in (None, "fresh", "partial"):
            raise ValueError("Stored warning evidence must be fresh, partial or absent")
        WarningContext(self.scope, self.operational_allowance_bytes, self.operational_revision)


@dataclass(frozen=True)
class WarningCrossing:
    threshold: WarningLevel
    generation: int


@dataclass(frozen=True)
class WarningTransition:
    state: WarningState
    crossing: WarningCrossing | None = None
    rearmed: tuple[WarningLevel, ...] = ()
    replaced_scope: WarningScope | None = None
    availability: Availability = "unknown"
    ignored: IgnoreReason | None = None


def evaluate_warning(
    previous: WarningState | None, *, context: WarningContext, reading: WarningReading | None
) -> WarningTransition:
    """Evaluate accepted readings against operational (never desired/native-headroom) bytes.

    Persist the returned state and cancel replaced-scope intents atomically with
    publication. A crossing is policy evidence, not permission to send mail.
    Re-evaluating the same fresh reading after an operational allowance change
    updates its condition but neither counts an observation nor emits a crossing.
    """
    state, replaced_scope = _current_scope(previous, context.scope)
    base = WarningTransition(state, replaced_scope=replaced_scope)
    if reading is not None and reading.scope != context.scope:
        return replace(base, ignored="scope_mismatch")
    allowance = context.operational_allowance_bytes
    base = replace(base, availability=_availability(context, reading))
    if allowance is None or allowance == 0 or reading is None or reading.used_bytes is None:
        return base
    if reading.quality != "fresh" and not (reading.quality == "partial" and context.scope.resource == "bandwidth"):
        return base
    if state.last_observed_at is not None:
        if reading.observed_at < state.last_observed_at:
            return replace(base, ignored="older_reading")
        if reading.observed_at == state.last_observed_at:
            return _same_time(base, context, reading, reading.used_bytes, allowance)
    return _advance(base, context, reading, reading.used_bytes, allowance)


def _availability(context: WarningContext, reading: WarningReading | None) -> Availability:
    if context.operational_allowance_bytes is None:
        return "unknown"
    if context.operational_allowance_bytes == 0:
        return "unlimited"
    if reading is None or (reading.quality == "fresh" and reading.used_bytes is None):
        return "unknown"
    return reading.quality


def _current_scope(previous: WarningState | None, scope: WarningScope) -> tuple[WarningState, WarningScope | None]:
    if previous is None:
        return WarningState(scope), None
    if (previous.scope.service_id, previous.scope.resource) != (scope.service_id, scope.resource):
        raise ValueError("Different services/resources must not share warning state")
    if previous.scope != scope:
        return WarningState(scope), previous.scope
    return previous, None


def _condition(used: int, allowance: int) -> WarningLevel | None:
    return next((level for level in reversed(WarningLevel) if _reached(used, allowance, level)), None)


def _reached(used: int, allowance: int, percent: int) -> bool:
    return used * 100 >= allowance * percent


def _partial_condition(previous: WarningLevel | None, observed: WarningLevel | None) -> WarningLevel | None:
    return max((level for level in (previous, observed) if level is not None), default=None)


def _same_time(
    base: WarningTransition, context: WarningContext, reading: WarningReading, used: int, allowance: int
) -> WarningTransition:
    if (
        base.state.last_quality == "partial"
        and base.state.last_used_bytes is not None
        and used >= base.state.last_used_bytes
        and (reading.quality == "fresh" or used > base.state.last_used_bytes)
    ):
        # Accepted partial evidence may be completed/refined at the same as-of.
        # Partial input never accrued a below-hour, so completion cannot double-count it.
        return _advance(base, context, reading, used, allowance)
    return _recompute_same_reading(base, context, reading, used, allowance)


def _recompute_same_reading(
    base: WarningTransition, context: WarningContext, reading: WarningReading, used: int, allowance: int
) -> WarningTransition:
    state = base.state
    if state.last_used_bytes != used:
        return replace(base, ignored="same_reading")
    changed = allowance != state.operational_allowance_bytes
    if not changed and context.operational_revision == state.operational_revision:
        return replace(base, ignored="same_reading")
    episodes = tuple(replace(episode, below_hour=None) for episode in state.episodes) if changed else state.episodes
    condition = _condition(used, allowance)
    if reading.quality == "partial":
        condition = _partial_condition(state.condition, condition)
    return replace(
        base,
        state=replace(
            state,
            condition=condition,
            episodes=episodes,
            last_quality="partial" if reading.quality == "partial" else "fresh",
            operational_allowance_bytes=allowance,
            operational_revision=context.operational_revision,
        ),
    )


def _rearm(episode: WarningEpisode, used: int, allowance: int, hour: datetime) -> tuple[WarningEpisode, bool]:
    if not episode.latched:
        return episode, False
    if _reached(used, allowance, _REARM_BELOW[episode.threshold]):
        return replace(episode, below_hour=None), False
    if episode.below_hour == hour:
        return episode, False
    if episode.below_hour is not None and hour - episode.below_hour == _HOUR:
        return replace(episode, latched=False, below_hour=None), True
    return replace(episode, below_hour=hour), False


def _advance(
    base: WarningTransition, context: WarningContext, reading: WarningReading, used: int, allowance: int
) -> WarningTransition:
    hour = reading.observed_at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    denominator_changed = allowance != base.state.operational_allowance_bytes
    episodes, rearmed = [], []
    crossing = None
    partial = reading.quality == "partial"
    for prior in base.state.episodes:
        episode = replace(prior, below_hour=None) if denominator_changed or partial else prior
        episode, did_rearm = (episode, False) if partial else _rearm(episode, used, allowance, hour)
        if did_rearm:
            rearmed.append(episode.threshold)
        if not episode.latched and _reached(used, allowance, episode.threshold):
            episode = replace(episode, latched=True, generation=episode.generation + 1, below_hour=None)
            crossing = WarningCrossing(episode.threshold, episode.generation)
        episodes.append(episode)
    condition = _condition(used, allowance)
    if partial:
        condition = _partial_condition(base.state.condition, condition)
    return replace(
        base,
        state=WarningState(
            scope=context.scope,
            condition=condition,
            episodes=tuple(episodes),
            last_observed_at=reading.observed_at,
            last_used_bytes=used,
            last_quality="partial" if partial else "fresh",
            operational_allowance_bytes=allowance,
            operational_revision=context.operational_revision,
        ),
        crossing=crossing,
        rearmed=tuple(rearmed),
    )
