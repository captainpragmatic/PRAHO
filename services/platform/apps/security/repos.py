"""Short database transactions own scheduling and publication; remote I/O happens between them."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .addresses import address_bounds
from .locks import lock_source
from .models import SecurityAlert, SecurityDecision, SecuritySource, SecuritySyncState
from .transport import Observation, SourceConnection, capture_connection, validate_observation

LEASE_SECONDS = 120
BATCH_SIZE = 500


@dataclass(frozen=True)
class QueuedClaim:
    source_id: UUID
    token: UUID


@dataclass(frozen=True)
class PollClaim:
    source_id: UUID
    token: UUID
    generation: int
    identity: str
    alert_cursor: int
    connection: SourceConnection


def enabled() -> bool:
    return bool(getattr(settings, "PRAHO_CROWDSEC_SYNC_ENABLED", False))


def _eligible(source: SecuritySource) -> bool:
    return enabled() and source.sync_enabled and source.retired_at is None


def _next_minute(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(second=0, microsecond=0) + timedelta(minutes=1)


def _clear(state: SecuritySyncState, outcome: str) -> None:
    state.claim_token, state.claim_phase, state.lease_until = None, "", None
    state.outcome = outcome


def _locked(source_id: UUID) -> tuple[SecuritySource, SecuritySyncState] | None:
    source = lock_source(source_id)
    if source is None:
        return None
    state, _ = SecuritySyncState.objects.get_or_create(source=source)
    state = SecuritySyncState.objects.select_for_update().get(pk=state.pk)
    return source, state


@transaction.atomic
def claim_for_queue(source_id: UUID) -> QueuedClaim | None:
    pair = _locked(source_id)
    if pair is None:
        return None
    source, state = pair
    now = timezone.now()
    if (
        not _eligible(source)
        or state.next_run > now
        or (state.claim_token is not None and state.lease_until is not None and state.lease_until > now)
    ):
        return None
    try:
        connection = capture_connection(source)
    except ValidationError:
        _clear(state, "identity_changed")
        state.next_run = _next_minute(now)
        state.save()
        return None
    state.claim_token = uuid4()
    state.claim_phase = "queued"
    state.lease_until = now + timedelta(seconds=LEASE_SECONDS)
    state.claimed_generation, state.input_identity = source.generation, connection.identity
    state.next_run, state.last_attempt_at, state.outcome = _next_minute(now), now, "queued"
    state.save()
    return QueuedClaim(source.pk, state.claim_token)


@transaction.atomic
def consume_claim(source_id: UUID, token: UUID) -> PollClaim | None:
    pair = _locked(source_id)
    if pair is None:
        return None
    source, state = pair
    now = timezone.now()
    if state.claim_token != token or state.claim_phase != "queued":
        return None
    try:
        connection = capture_connection(source)
    except ValidationError:
        connection = None
    if (
        not _eligible(source)
        or state.lease_until is None
        or state.lease_until <= now
        or state.claimed_generation != source.generation
        or connection is None
        or connection.identity != state.input_identity
    ):
        _clear(state, "superseded")
        state.save()
        return None
    state.claim_token, state.claim_phase = uuid4(), "running"
    state.lease_until, state.outcome = now + timedelta(seconds=LEASE_SECONDS), "running"
    state.save()
    return PollClaim(
        source.pk, state.claim_token, source.generation, connection.identity, state.alert_cursor, connection
    )


def _timestamp(value: object) -> datetime:
    parsed = datetime.fromisoformat(cast("str", value))
    if parsed.tzinfo is None:
        raise ValueError("A remote timestamp requires its UTC offset")
    return parsed.astimezone(UTC)


def _decision_values(row: dict[str, object]) -> dict[str, object]:
    scope, value = cast("str", row["scope"]), cast("str", row["value"])
    bounds = address_bounds(scope, value)
    return {
        "source_created_at": _timestamp(row["created_at"]),
        "expires_at": _timestamp(row["expires_at"]),
        "scenario": row["scenario"],
        "type": row["type"],
        "scope": scope,
        "value": value,
        "origin": row["origin"],
        "simulated": row["simulated"],
        "address_family": bounds.address_family,
        "network_start": bounds.network_start,
        "network_end": bounds.network_end,
    }


def _alert_values(row: dict[str, object]) -> dict[str, object]:
    bounds = address_bounds(cast("str", row["scope"]), cast("str", row["value"])) if row["scope"] is not None else None
    return {
        "source_created_at": _timestamp(row["created_at"]),
        "scenario": row["scenario"],
        "event_count": row["event_count"],
        "scope": row["scope"] or "",
        "value": row["value"] or "",
        "simulated": row["simulated"],
        "address_family": bounds.address_family if bounds else None,
        "network_start": bounds.network_start if bounds else None,
        "network_end": bounds.network_end if bounds else None,
    }


def _matches(row: SecurityDecision | SecurityAlert, values: dict[str, object]) -> bool:
    return all(getattr(row, name) == value for name, value in values.items())


def _mirror(source: SecuritySource, observation: Observation, now: datetime) -> None:
    decisions = cast("list[dict[str, object]]", observation.snapshot["decisions"])
    alerts = cast("list[dict[str, object]]", observation.snapshot["alerts"])
    current_decisions = {
        row.remote_id: row
        for row in SecurityDecision.objects.filter(source=source, remote_id__in=[item["id"] for item in decisions])
    }
    current_alerts = {
        row.remote_id: row
        for row in SecurityAlert.objects.filter(source=source, remote_id__in=[item["id"] for item in alerts])
    }
    new_decisions, seen_decisions, new_alerts = [], [], []
    observed_at = _timestamp(observation.snapshot["observed_at"])
    for item in decisions:
        values = _decision_values(item)
        expiry = cast("datetime", values["expires_at"])
        if expiry <= observed_at:
            raise ValidationError(_("An active decision must expire after its observation"))
        old = current_decisions.get(cast("int", item["id"]))
        if old is not None:
            # Local retention can observe absolute expiry while an earlier snapshot is in flight.
            # Preserve that known end; a prior disappearance must never be reopened by replay.
            ended_early = old.ended_at is not None and not (old.ended_at == expiry and expiry <= now)
            if ended_early or not _matches(old, values):
                raise ValidationError(_("A decision ID changed its immutable payload"))
            old.last_seen_at = now
            seen_decisions.append(old)
        else:
            new_decisions.append(
                SecurityDecision(
                    source=source,
                    remote_id=cast("int", item["id"]),
                    first_seen_at=now,
                    last_seen_at=now,
                    ended_at=expiry if expiry <= now else None,
                    **values,
                )
            )
    for item in alerts:
        values = _alert_values(item)
        old_alert = current_alerts.get(cast("int", item["id"]))
        if old_alert is not None and not _matches(old_alert, values):
            raise ValidationError(_("An alert ID changed its immutable payload"))
        if old_alert is None:
            new_alerts.append(SecurityAlert(source=source, remote_id=cast("int", item["id"]), **values))
    SecurityDecision.objects.bulk_create(new_decisions, batch_size=BATCH_SIZE)
    SecurityDecision.objects.bulk_update(seen_decisions, ["last_seen_at"], batch_size=BATCH_SIZE)
    SecurityAlert.objects.bulk_create(new_alerts, batch_size=BATCH_SIZE)
    SecurityDecision.objects.filter(source=source, ended_at__isnull=True).exclude(
        remote_id__in=[item["id"] for item in decisions]
    ).update(
        ended_at=models.Case(
            models.When(expires_at__lte=now, then=models.F("expires_at")),
            default=models.Value(now),
            output_field=models.DateTimeField(),
        ),
        updated_at=now,
    )


@transaction.atomic
def publish_observation(claim: PollClaim, observation: Observation) -> bool:
    validate_observation(claim.connection, claim.alert_cursor, observation)
    pair = _locked(claim.source_id)
    if pair is None:
        return False
    source, state = pair
    now = timezone.now()
    if state.claim_token != claim.token or state.claim_phase != "running":
        return False
    try:
        identity = capture_connection(source).identity
    except ValidationError:
        identity = ""
    if (
        not _eligible(source)
        or state.lease_until is None
        or state.lease_until <= now
        or source.generation != claim.generation
        or state.claimed_generation != claim.generation
        or state.input_identity != claim.identity
        or identity != claim.identity
        or state.alert_cursor != claim.alert_cursor
    ):
        _clear(state, "superseded")
        state.save()
        return False
    _mirror(source, observation, now)
    state.alert_cursor = cast("int", observation.snapshot["alert_watermark"])
    state.has_more = cast("bool", observation.snapshot["has_more"])
    state.last_decision_sync_at, state.last_alert_batch_at = now, now
    state.last_published_generation = source.generation
    if not state.has_more:
        state.last_alert_sync_at = now
    state.health = observation.health
    _clear(state, "catching_up" if state.has_more else "ok")
    state.save()
    return True


def fail_claim(source_id: UUID, token: UUID, outcome: str) -> bool:
    return bool(
        SecuritySyncState.objects.filter(source_id=source_id, claim_token=token).update(
            claim_token=None, claim_phase="", lease_until=None, outcome=outcome, updated_at=timezone.now()
        )
    )
