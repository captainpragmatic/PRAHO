"""Describe stored detection, enforcement and catch-up facts independently."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.utils.translation import gettext as _

from .models import SecuritySource, SecuritySyncState

STALE_AFTER = timedelta(minutes=3)
FAILED_OUTCOMES = frozenset({"unavailable", "enqueue_failed", "identity_changed", "superseded", "reconfigured"})


@dataclass(frozen=True)
class SourceStatus:
    source: SecuritySource
    state: SecuritySyncState | None
    freshness: str
    detection: str
    enforcement: str
    clock: str
    alerts: str
    stale: bool


def _flag(health: object, group: str, field: str) -> bool | None:
    if not isinstance(health, dict):
        return None
    value = health.get(group)
    result = value.get(field) if isinstance(value, dict) else None
    return result if type(result) is bool else None


def source_status(source: SecuritySource, now: datetime) -> SourceStatus:
    state = getattr(source, "sync_state", None)
    health = state.health if state else {}
    stale = (
        state is None
        or state.outcome in FAILED_OUTCOMES
        or state.last_published_generation != source.generation
        or state.last_decision_sync_at is None
        or now - state.last_decision_sync_at > STALE_AFTER
    )
    if source.retired_at:
        freshness = _("Retired source")
        stale = True
    elif not source.sync_enabled or not settings.PRAHO_CROWDSEC_SYNC_ENABLED:
        freshness = _("Synchronization disabled")
    elif state is None or state.last_decision_sync_at is None:
        freshness = _("Never synchronized")
    elif state.outcome in FAILED_OUTCOMES:
        freshness = _("Degraded; last snapshot retained")
    else:
        freshness = _("Stale") if stale else _("Decisions current")
    canonical = _flag(health, "configuration", "qualified")
    active = _flag(health, "engine", "active")
    detection = _("Unconfirmed")
    if canonical is True and active is not None:
        detection = _("Reported running") if active else _("Reported stopped")
    simulation = health.get("simulation") if isinstance(health, dict) else None
    bouncer = _flag(health, "bouncer", "active")
    enforcement = _("Unconfirmed")
    if canonical is True and _flag(health, "firewall", "qualified") is True:
        if simulation is True and bouncer is False and _flag(health, "firewall", "ban_sets_empty") is True:
            enforcement = _("Simulation; bans cleared")
        elif simulation is False and bouncer is True:
            enforcement = _("Bouncer process reported running")
    clock = _("Qualified") if _flag(health, "clock", "qualified") is True else _("Unqualified or unknown")
    if state and state.has_more:
        alerts = _("Catch-up pending")
    elif state and state.last_alert_sync_at and now - state.last_alert_sync_at <= STALE_AFTER:
        alerts = _("Caught up")
    else:
        alerts = _("Not current")
    return SourceStatus(source, state, freshness, detection, enforcement, clock, alerts, stale)
