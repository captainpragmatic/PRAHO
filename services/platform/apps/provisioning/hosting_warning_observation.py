"""Persist warning episodes inside the accepted account-publication transaction."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import validate_email
from django.db import transaction

from .hosting_limit_selectors import operational_allowances
from .hosting_node_policy import platform_notifications_owned
from .hosting_warning_models import HostingWarningIntent, HostingWarningState
from .hosting_warning_policy import (
    ReadingQuality,
    Resource,
    WarningContext,
    WarningCrossing,
    WarningLevel,
    WarningReading,
    WarningScope,
    evaluate_warning,
)
from .hosting_warning_state import scope_snapshot, state_from_snapshot, state_snapshot
from .virtualmin_models import VirtualminAccount
from .virtualmin_usage_models import AccountUsageState, UsageInterval, UsageReading

STALE_AFTER = timedelta(hours=6)
MIB = 1024**2
logger = logging.getLogger(__name__)


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def recipient_hash(address: str) -> str:
    from apps.notifications.models import recipient_digest  # noqa: PLC0415 -- Shared recipient digest contract.

    normalized = address.strip().casefold()
    try:
        validate_email(normalized)
    except ValidationError:
        return ""
    return recipient_digest(normalized)


def _handover(account: VirtualminAccount) -> str:
    if not platform_notifications_owned(account.server):
        return ""
    policy = account.server.hosting_policy
    if policy.notifications_verified_at is None:
        return ""
    return fingerprint(
        {
            "server": str(account.server_id),
            "verified_at": policy.notifications_verified_at.isoformat(),
            "notification_identity": policy.notification_evidence["identity"],
        }
    )


def _reading(
    state: AccountUsageState,
    resource: str,
    scope: WarningScope,
    *,
    observed: datetime,
    partial_changed: bool,
) -> tuple[WarningReading | None, UsageReading | None]:
    account = state.account
    stored = state.disk_reading if resource == "disk" else state.bandwidth_reading
    valid = False
    value = None
    if stored is not None and stored.owner_scope == state.owner_scope:
        if resource == "disk":
            valid = (
                stored.server_id_snapshot == account.server_id
                and stored.chain_epoch == account.chain_epoch
                and stored.taken_at >= state.gauge_not_before
            )
            value = stored.disk_total_bytes if valid else None
        else:
            valid = (
                (stored.period_start, stored.period_end, stored.period_timezone)
                == (scope.period_start, scope.period_end, scope.period_timezone)
                and stored.bandwidth_complete
                and stored.server_id_snapshot == account.server_id
            )
            value = stored.bandwidth_bytes if valid else None
    fallback: tuple[WarningReading | None, UsageReading | None] = (None, None)
    if valid and stored is not None:
        quality: ReadingQuality = "stale" if stored.taken_at < observed - STALE_AFTER else "fresh"
        if (
            resource == "bandwidth"
            and state.bandwidth_incomplete_since
            and state.bandwidth_incomplete_since >= stored.taken_at
        ):
            quality = "stale"
        fallback = WarningReading(scope, stored.taken_at, value, quality), stored
        if quality == "fresh":
            return fallback
    if resource == "bandwidth" and partial_changed and scope.period_start is not None:
        # Only complete owner-scoped segment intersections accepted by THIS poll
        # may establish a new lower bound. Unknown/missing coverage is never zero.
        key = scope.period_start.isoformat()
        parts = UsageInterval.objects.filter(account=account, owner_scope=state.owner_scope)
        totals = [part.totals[key] for part in parts if key in part.totals and part.totals[key].get("complete") is True]
        if totals:
            lower_bound = sum(item["bytes"] for item in totals)
            if type(lower_bound) is int and lower_bound >= 0:
                return WarningReading(scope, observed, lower_bound, "partial"), None
    return fallback


def _cancel_pending(cursor: HostingWarningState, reason: str, *, below: int | None = None) -> None:
    from apps.common.row_locks import lock_many_and_load  # noqa: PLC0415 -- Fresh phases after a delivery wait.

    intents = cursor.intents.filter(phase__in=("pending", "linked"))
    if below is not None:
        intents = intents.filter(threshold__lt=below)
    for intent in lock_many_and_load(intents.order_by("pk"), no_key=True):
        intent.cancel(reason)
        intent.save(update_fields=["phase", "refusal_reason", "updated_at"])


def _intent(
    cursor: HostingWarningState,
    crossing: WarningCrossing,
    reading: WarningReading,
    stored: UsageReading | None,
    kind: str,
) -> None:
    scope, threshold, generation, observed = reading.scope, crossing.threshold, crossing.generation, reading.observed_at
    key = {
        "scope": scope_snapshot(scope),
        "threshold": int(threshold),
        "generation": generation,
        "recipient": cursor.recipient_hash,
        "channel": "email",
        "kind": kind,
    }
    due = observed + timedelta(hours=23) if threshold == WarningLevel.WARNING else observed
    if kind == "rollout":
        # Bound rollout by customer, critical first. Normal crossings stay immediate.
        rank = int(cursor.recipient_hash[:8], 16) % 300
        due = observed + timedelta(seconds=rank if threshold == WarningLevel.CRITICAL else rank + 300)
        if threshold == WarningLevel.WARNING:
            due = observed + timedelta(hours=23, seconds=rank)
    HostingWarningIntent.objects.get_or_create(
        identity=fingerprint(key),
        defaults={
            "state": cursor,
            "service_id_snapshot": scope.service_id,
            "customer_id_snapshot": scope.customer_id,
            "owner_scope": scope.owner_scope,
            "resource": scope.resource,
            "generation": generation,
            "threshold": int(threshold),
            "recipient_hash": cursor.recipient_hash,
            "kind": kind,
            "due_at": due,
            "reading": stored,
            "scope_snapshot": scope_snapshot(scope),
            "evidence_snapshot": {
                "observed_at": reading.observed_at.isoformat(),
                "used_bytes": reading.used_bytes,
                "quality": reading.quality,
            },
        },
    )


def warning_scope(
    resource: Resource, service_id: int, customer_id: int, owner_scope: UUID, at: datetime
) -> WarningScope:
    from .virtualmin_usage_service import month  # noqa: PLC0415 -- Canonical operator timezone/month.

    start, end = month(at)
    return WarningScope(
        resource,
        service_id,
        customer_id,
        owner_scope,
        period_start=start if resource == "bandwidth" else None,
        period_end=end if resource == "bandwidth" else None,
        period_timezone=settings.TIME_ZONE if resource == "bandwidth" else None,
    )


@dataclass(frozen=True)
class _Publication:
    account: VirtualminAccount
    current: AccountUsageState
    recipient: str
    handover: str
    poll: UUID
    observed: datetime
    changed_disk: set[UUID]
    changed_bandwidth: set[UUID]


def _observe_resource(publication: _Publication, resource: Resource) -> int:
    account, current = publication.account, publication.current
    handover, recipient = publication.handover, publication.recipient
    scope = warning_scope(
        resource, account.service_id, account.service.customer_id, current.owner_scope, publication.observed
    )
    cursor, created = HostingWarningState.objects.select_for_update().get_or_create(
        account=account,
        resource=resource,
        defaults={
            "service_id_snapshot": account.service_id,
            "customer_id_snapshot": account.service.customer_id,
            "owner_scope": current.owner_scope,
        },
    )
    try:
        previous = state_from_snapshot(cursor.policy_state) if cursor.policy_state else None
    except ValueError:
        # Preserve accepted usage and corrupt evidence. A silent episode reset
        # would make a duplicate notification possible.
        cursor.condition, cursor.availability, cursor.last_poll = None, "unknown", publication.poll
        cursor.save(update_fields=["condition", "availability", "last_poll", "updated_at"])
        logger.error("Stored hosting warning policy is invalid; warning publication requires review")
        return 0
    reading, stored = _reading(
        current,
        resource,
        scope,
        observed=publication.observed,
        partial_changed=account.pk in publication.changed_bandwidth,
    )
    accepted = publication.changed_disk if resource == "disk" else publication.changed_bandwidth
    if account.pk not in accepted:
        reading, stored = None, None
    allowance = operational_allowances(account.service)[0 if resource == "disk" else 1]
    try:
        revision = account.service.hosting_limits.operational_revision
    except ObjectDoesNotExist:
        revision = None
    result = evaluate_warning(
        previous,
        context=WarningContext(scope, None if allowance is None else allowance * MIB, revision),
        reading=reading,
    )
    changed_recipient = cursor.recipient_hash != recipient
    verified_at = account.server.hosting_policy.notifications_verified_at if handover else None
    imported = verified_at is not None and account.created_at <= verified_at
    new_handover = bool(handover) and cursor.handover_fingerprint != handover and (not created or imported)
    fresh = reading is not None and reading.quality in {"fresh", "partial"} and result.ignored is None
    if result.replaced_scope:
        _cancel_pending(cursor, "warning_scope_changed")
    if changed_recipient:
        _cancel_pending(cursor, "warning_recipient_changed")
    if new_handover and fresh:
        _cancel_pending(cursor, "warning_handover_baseline")
    cursor.service_id_snapshot, cursor.customer_id_snapshot, cursor.owner_scope = (
        scope.service_id,
        scope.customer_id,
        scope.owner_scope,
    )
    cursor.policy_state = state_snapshot(result.state)
    cursor.condition = int(result.state.condition) if result.state.condition else None
    cursor.availability, cursor.reading, cursor.recipient_hash = result.availability, stored, recipient
    created_intent = 0
    if fresh and reading is not None and recipient and result.state.condition and cursor.last_poll != publication.poll:
        threshold = result.state.condition
        episode = next(item for item in result.state.episodes if item.threshold == threshold)
        if result.crossing or changed_recipient or new_handover:
            _cancel_pending(cursor, "warning_superseded", below=int(threshold))
            _intent(
                cursor,
                WarningCrossing(threshold, episode.generation),
                reading,
                stored,
                "rollout" if new_handover else "crossing",
            )
            created_intent = 1
    if fresh or not handover:
        cursor.handover_fingerprint = handover
    cursor.last_poll = publication.poll
    cursor.save()
    return created_intent


def observe_warning_accounts(
    account_ids: set[UUID],
    *,
    poll: UUID,
    observed: datetime,
    changed_disk: set[UUID],
    changed_bandwidth: set[UUID],
) -> int:
    """Caller owns Account locks. No customer, delivery or EmailLog lock is acquired here."""
    from apps.customers.models import Customer  # noqa: PLC0415 -- Batched read only, never a customer lock.

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Warning episodes require the accepted publication transaction")

    accounts = list(
        VirtualminAccount.objects.filter(pk__in=account_ids).select_related(
            "service__hosting_limits", "server__hosting_policy"
        )
    )
    customers = {
        row["pk"]: row
        for row in Customer.all_objects.filter(pk__in={item.service.customer_id for item in accounts}).values(
            "pk",
            "primary_email",
            "status",
            "anonymized_at",
            "deleted_at",
        )
    }
    usage = {
        row.account_id: row
        for row in AccountUsageState.objects.filter(account_id__in=account_ids).select_related(
            "account", "disk_reading", "bandwidth_reading"
        )
    }
    handovers: dict[UUID, str] = {}
    count = 0
    for account in accounts:
        current = usage.get(account.pk)
        if current is None or (current.service_id_snapshot, current.customer_id_snapshot) != (
            account.service_id,
            account.service.customer_id,
        ):
            continue
        current.account = account
        customer = customers.get(account.service.customer_id)
        address = (
            customer["primary_email"]
            if customer
            and customer["status"] == "active"
            and not customer["anonymized_at"]
            and not customer["deleted_at"]
            else ""
        )
        recipient = recipient_hash(address)
        if account.server_id not in handovers:
            handovers[account.server_id] = _handover(account)
        publication = _Publication(
            account=account,
            current=current,
            recipient=recipient,
            handover=handovers[account.server_id],
            poll=poll,
            observed=observed,
            changed_disk=changed_disk,
            changed_bandwidth=changed_bandwidth,
        )
        count += _observe_resource(publication, "disk") + _observe_resource(publication, "bandwidth")
    return count
