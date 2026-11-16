"""Database over-allowance episodes: when one opens, when its clock pauses, and when it closes.

An episode opens on a fresh reading that puts an account with databases over its allowance, and closes after
24 hours of observed readings under it. Only what is observed counts: a reading counts once (by its own
`taken_at`), and a gap of more than 3 hours between counted readings restarts the 24 hours. A hold, its node
I/O and the deadline belong to the sweep; this module only records decisions, under the account's row lock.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import models, transaction
from django.utils import timezone

from .database_overage_models import RELEASE_TO_GRACE, DatabaseOverageEpisode, EpisodeState

if TYPE_CHECKING:
    from .service_models import Service
    from .virtualmin_models import VirtualminAccount
    from .virtualmin_usage_models import AccountUsageState, UsageReading

logger = logging.getLogger(__name__)

MIB = 1024 * 1024
FRESH_FOR = timedelta(hours=2)
CONTINUITY_GAP = timedelta(hours=3)
UNDER_FOR = timedelta(hours=24)
# The episode's audit trail; all are kept as contract evidence (audit retention CLAIMS_ACTIONS).
AUDIT_ACTIONS = (
    "database_overage_opened",
    "database_overage_notice_sent",
    "database_overage_hold_requested",
    "database_overage_hold_applied",
    "database_overage_release_requested",
    "database_overage_hold_released",
    "database_overage_extended",
    "database_overage_waived",
    "database_overage_closed",
    "database_hold_drift",
)
CRITICAL_WARNING_THRESHOLD = 100  # the hosting warning's 100% level, which the day-0 notice replaces
MIN_REMAINING_ON_RESUME = timedelta(days=3)
OVER_BEFORE_DEADLINE = timedelta(hours=2)  # the over reading a hold rests on is at most this old at the deadline


def overage_enabled() -> bool:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_setting("provisioning.database_overage_enabled", False) is True


def grace_period() -> timedelta:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    days = SettingsService.get_setting("provisioning.database_overage_grace_days", 14)
    return timedelta(days=days if isinstance(days, int) and not isinstance(days, bool) and days >= 1 else 14)


def audit_episode(
    episode: DatabaseOverageEpisode, action: str, description: str, *, user: object = None, **values: object
) -> None:
    """One audit event on the episode, in the caller's transaction: by staff when `user` is given, else system."""
    from apps.audit.services import AuditService  # noqa: PLC0415 -- Cross-app at call time (ADR-0007).

    if action not in AUDIT_ACTIONS:
        raise ValueError(f"not a database overage audit action: {action}")
    AuditService.log_simple_event(
        action,
        user=user,
        content_object=episode,
        description=description,
        new_values={
            "state": episode.state,
            "deadline_at": episode.deadline_at.isoformat(),
            "hold_generation": episode.hold_generation,
            **{key: str(value) if isinstance(value, UUID) else value for key, value in values.items()},
        },
        actor_type="user" if user is not None else "system",
    )


def superseded_by_database_overage(resource: str, threshold: int, account_id: UUID) -> bool:
    """The day-0 database overage notice replaces the account's 100% disk warning and its reminders."""
    return (
        resource == "disk"
        and threshold == CRITICAL_WARNING_THRESHOLD
        and DatabaseOverageEpisode.objects.filter(account_id=account_id).exclude(state=EpisodeState.CLOSED).exists()
    )


def allowance_bytes(service: Service, account: VirtualminAccount, *, at: datetime) -> int | None:
    """The purchased disk allowance plus active temporary relief, in bytes; 0 is unlimited, None unknown.

    Unknown until the operational limits are applied and verified on the node; native headroom never counts.
    """
    from .hosting_limit_selectors import operational_allowances, prime_current_verification  # noqa: PLC0415
    from .hosting_raise_service import current_raise_terms  # noqa: PLC0415

    prime_current_verification([service], {service.pk: account}, at=at)
    if not service.__dict__.get("_hosting_operational_verified"):
        return None
    disk_mib = operational_allowances(service)[0]
    if disk_mib is None:
        return None
    if disk_mib == 0:
        return 0
    return (disk_mib + current_raise_terms(service.pk, service.customer_id, at=at).extra_mib) * MIB


def fresh_disk_reading(account: VirtualminAccount, state: AccountUsageState, *, at: datetime) -> UsageReading | None:
    """The account's disk reading when it still describes this account, owner and node, and is under 2 hours old."""
    from .virtualmin_usage_models import NodeUsageSyncState  # noqa: PLC0415

    service = account.service
    reading = state.disk_reading
    if (
        reading is None
        or service is None
        or (state.service_id_snapshot, state.customer_id_snapshot, state.server_id_snapshot)
        != (service.pk, service.customer_id, account.server_id)
        or reading.owner_scope != state.owner_scope
        or reading.server_id_snapshot != account.server_id
        or reading.chain_epoch != account.chain_epoch
        or reading.scan_started_at is None
        or reading.scan_started_at < state.gauge_not_before
        or reading.disk_total_bytes is None
        or reading.disk_db_bytes is None
        or not at - FRESH_FOR <= reading.taken_at <= at
    ):
        return None
    poll = NodeUsageSyncState.objects.filter(server_id=account.server_id).first()
    if (
        poll is not None
        and poll.outcome == "unavailable"
        and poll.last_attempt_at
        and poll.last_attempt_at > reading.taken_at
    ):
        return None  # a later scan failed: what this reading says may no longer hold
    return reading


def is_over(reading: UsageReading, allowance: int) -> bool:
    """Over only with database bytes: the hold stops database growth, nothing else."""
    disk_total, disk_db = reading.disk_total_bytes or 0, reading.disk_db_bytes or 0
    return allowance > 0 and disk_db > 0 and disk_total > allowance


@dataclass(frozen=True)
class Observation:
    reading: UsageReading | None  # fresh, with a known allowance; None when nothing can be said
    over: bool
    active: bool
    allowance: int | None = None


def _observe(account: VirtualminAccount, *, at: datetime) -> Observation:
    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    service = account.service
    active = account.status == "active" and service is not None and service.status == "active"
    state = AccountUsageState.objects.select_related("disk_reading").filter(account=account).first()
    if service is None or state is None:
        return Observation(None, False, active)
    reading = fresh_disk_reading(account, state, at=at)
    allowance = allowance_bytes(service, account, at=at) if reading is not None else None
    if reading is None or allowance is None:
        return Observation(None, False, active)
    return Observation(reading, is_over(reading, allowance), active, allowance)


def _open(account: VirtualminAccount, observation: Observation, *, at: datetime) -> DatabaseOverageEpisode | None:
    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    reading, service = observation.reading, account.service
    state = AccountUsageState.objects.filter(account=account).first()
    if (
        reading is None
        or not observation.over
        or not observation.active
        or not account.quota_managed
        or service is None
        or state is None
        or not state.domain_id
        or not overage_enabled()
    ):
        return None
    episode = DatabaseOverageEpisode.objects.create(
        account=account,
        service=service,
        service_id_snapshot=service.pk,
        customer_id_snapshot=service.customer_id,
        owner_scope=state.owner_scope,
        server_id=account.server_id,
        domain_id=state.domain_id,
        domain=account.domain,
        installation=state.installation,
        opened_at=at,
        opened_reading=reading,
        deadline_at=at + grace_period(),
        last_fresh_at=reading.taken_at,
        last_over_at=reading.taken_at,
    )
    # The reading itself is purged long before the claims period ends, so its numbers go into the trail.
    audit_episode(
        episode,
        "database_overage_opened",
        "Database over-allowance episode opened",
        reading=reading.pk,
        taken_at=reading.taken_at.isoformat(),
        disk_total_bytes=reading.disk_total_bytes,
        disk_files_bytes=reading.disk_files_bytes,
        disk_db_bytes=reading.disk_db_bytes,
        allowance_bytes=observation.allowance,
    )
    logger.info("✅ [DatabaseOverage] Episode %s opened for account %s", episode.pk, account.pk)
    return episode


def _pause_or_resume(episode: DatabaseOverageEpisode, *, active: bool, at: datetime) -> list[str]:
    """While the service or account isn't active the clock stops; on resume at least 3 days remain."""
    if not active:
        if episode.paused_at is None:
            episode.paused_at = at
            return ["paused_at"]
        return []
    if episode.paused_at is None:
        return []
    paused = max(at - episode.paused_at, timedelta(0))
    episode.paused_total += paused
    episode.deadline_at = max(episode.deadline_at + paused, at + MIN_REMAINING_ON_RESUME)
    episode.paused_at = None
    return ["paused_at", "paused_total", "deadline_at"]


def _count(episode: DatabaseOverageEpisode, observation: Observation, *, at: datetime) -> list[str]:
    """Advance the observed span on a newer fresh reading; restart it after a gap or an over reading.

    The gap that breaks continuity is between counted readings. Without a newer reading, the sweep's own
    time breaks it once more than 3 hours have passed since the last one: 24 hours under have to be
    observed, not assumed across an outage.
    """
    reading, last = observation.reading, episode.last_fresh_at
    if (
        reading is None
        or reading.owner_scope != episode.owner_scope
        or (last is not None and reading.taken_at <= last)  # swept again, or an older one published late
    ):
        if last is not None and at - last > CONTINUITY_GAP and episode.below_since is not None:
            episode.below_since = None
            return ["below_since"]
        return []
    if observation.over:
        episode.last_over_at = reading.taken_at
    if observation.over or (last is not None and reading.taken_at - last > CONTINUITY_GAP):
        episode.below_since = None
    if not observation.over and episode.below_since is None:
        episode.below_since = reading.taken_at
    episode.last_fresh_at = reading.taken_at
    return ["last_fresh_at", "below_since", "last_over_at"]


def _under_long_enough(episode: DatabaseOverageEpisode, observation: Observation) -> bool:
    reading = observation.reading
    return (
        reading is not None
        and not observation.over
        and episode.below_since is not None
        and reading.taken_at == episode.last_fresh_at
        and reading.taken_at - episode.below_since >= UNDER_FOR
    )


def _end_under_allowance(episode: DatabaseOverageEpisode) -> str | None:
    """24 observed hours under: a grace episode closes, a hold is marked for release."""
    if episode.state == EpisodeState.GRACE:
        episode.close("under_allowance")
        episode.save()
        audit_episode(
            episode, "database_overage_closed", "Under the allowance for 24 hours", close_reason="under_allowance"
        )
        logger.info("✅ [DatabaseOverage] Episode %s closed: under the allowance for 24h", episode.pk)
        return "closed"
    if episode.state in (EpisodeState.HOLDING, EpisodeState.HELD):
        episode.start_release("under_allowance")
        episode.save()
        logger.info("✅ [DatabaseOverage] Episode %s releasing: under the allowance for 24h", episode.pk)
        return "releasing"
    return None


def _previous_owner(episode: DatabaseOverageEpisode, account: VirtualminAccount) -> str | None:
    """An episode of an owner the account no longer has: close it, or release its hold; never carry it over."""
    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    owner = AccountUsageState.objects.filter(account=account).values_list("owner_scope", flat=True).first()
    if owner is None or owner == episode.owner_scope:
        return None
    if episode.state == EpisodeState.GRACE:
        episode.close("ownership_changed")
        episode.save()
        audit_episode(episode, "database_overage_closed", "The account changed owner", close_reason="ownership_changed")
        logger.info("✅ [DatabaseOverage] Episode %s closed: the account changed owner", episode.pk)
        return "closed"
    if episode.state in (EpisodeState.HOLDING, EpisodeState.HELD):
        episode.start_release("ownership_changed")
        episode.save()
        logger.info("✅ [DatabaseOverage] Episode %s releasing: the account changed owner", episode.pk)
    return "releasing"


def evaluate_account(account_id: UUID, *, at: datetime | None = None) -> str:
    """One account's episode decision. Returns what happened, for the sweep's log and tests.

    The account row is locked first, then the episode; nothing here talks to the node.
    """
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    with transaction.atomic():
        # Locked alone: a joined row read under FOR UPDATE can be the one from before the wait.
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
        if account is None:
            return "missing"
        episode = (
            DatabaseOverageEpisode.objects.select_for_update()
            .filter(account=account)
            .exclude(state=EpisodeState.CLOSED)
            .first()
        )
        now = at or timezone.now()  # after the lock waits, so freshness is judged at the time of deciding
        observation = _observe(account, at=now)
        if episode is None:
            return "opened" if _open(account, observation, at=now) is not None else "none"
        if (outcome := _previous_owner(episode, account)) is not None:
            return outcome
        changed = _pause_or_resume(episode, active=observation.active, at=now)
        if episode.paused_at is not None:
            if changed:
                episode.save(update_fields=[*changed, "updated_at"])
            return "paused"
        changed += _count(episode, observation, at=now)
        if _under_long_enough(episode, observation) and (outcome := _end_under_allowance(episode)) is not None:
            return outcome
        if changed:
            episode.save(update_fields=[*dict.fromkeys(changed), "updated_at"])
        return "observed"


def account_busy(account: VirtualminAccount, *, ignore_episode_id: UUID | None = None) -> bool:
    """A migration, backup, restore, delete or another hold in progress on the account: a hold waits for it."""
    from .virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415

    return account_has_active_operation(account, ignore_episode_id=ignore_episode_id)


def pending_assignment_covers(service: Service, disk_total_bytes: int) -> bool:
    """An assigned allowance not yet applied on the node that would already cover the usage."""
    from .hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415

    limits = ServiceHostingLimits.objects.filter(service=service).first()
    if limits is None or limits.revision == limits.operational_revision or limits.disk_allowance_mib is None:
        return False
    return limits.disk_allowance_mib == 0 or limits.disk_allowance_mib * MIB >= disk_total_bytes


def next_hold_generation(account: VirtualminAccount) -> int:
    """Per account and only ever forward: the node keeps one journal per domain across episodes."""
    newest = DatabaseOverageEpisode.objects.filter(account=account).aggregate(newest=models.Max("hold_generation"))
    return (newest["newest"] or 0) + 1


def enforcement_refusal(  # noqa: PLR0911 -- one return per precondition, in the plan's order
    episode: DatabaseOverageEpisode, account: VirtualminAccount, *, at: datetime
) -> str | None:
    """Why the hold may not be applied now, or None. Every precondition the plan names, checked under the locks."""
    from .database_overage_models import DatabaseOverageNotice, NoticeKind  # noqa: PLC0415

    service = account.service
    if not overage_enabled():
        return "flag_off"
    if episode.hold_refused_at is not None:
        return "hold_refused_needs_staff"
    day0 = DatabaseOverageNotice.objects.filter(episode=episode, kind=NoticeKind.DAY0).first()
    if day0 is None or day0.accepted_at is None:
        return "day0_not_accepted"
    if episode.paused_at is not None or service is None or account.status != "active" or service.status != "active":
        return "inactive"
    if episode.suspended_for:
        return "suspended_for_migration"
    if not _current_identity(episode, account):
        return "identity_unknown"  # moved to another node whose domain id and installation aren't collected yet
    # Observed again here, under the locks: the newest fresh reading, against the allowance verified now.
    observation = _observe(account, at=at)
    reading = observation.reading
    if reading is None or not observation.over or reading.taken_at < episode.deadline_at - OVER_BEFORE_DEADLINE:
        return "no_fresh_over_reading"
    if pending_assignment_covers(service, reading.disk_total_bytes or 0):
        return "pending_assignment_covers"
    if account_busy(account, ignore_episode_id=episode.pk):  # a re-sent hold is its own operation
        return "active_operation"
    return None


def collected_identity(account: VirtualminAccount) -> tuple[UUID, str, UUID] | None:
    """The native identity the usage collector verified for the account on the node it is on now, if it has one."""
    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    state = AccountUsageState.objects.filter(account=account).first()
    if state is None or state.server_id_snapshot != account.server_id or not state.domain_id or not state.installation:
        return None
    return account.server_id, state.domain_id, state.installation


def _current_identity(episode: DatabaseOverageEpisode, account: VirtualminAccount) -> bool:
    """Under the locks: the episode names the account's verified native identity now. In grace it is refreshed on
    any change (a move, or a domain recreated on the same node); False while the collector hasn't verified one."""
    collected = collected_identity(account)
    if collected is None:
        return False
    if (episode.server_id, episode.domain_id, episode.installation) == collected:
        return True
    if episode.state != EpisodeState.GRACE:
        return False
    episode.server_id, episode.domain_id, episode.installation = collected
    return True


def abandon_hold(episode: DatabaseOverageEpisode, reason: str, *, for_staff: bool) -> None:
    """Without the node: the hold's journal is on a domain or node that can no longer be asked. The episode leaves
    it (to grace, or closed by its release's purpose) and the abandoned journal goes on record. The caller saves.

    for_staff latches the episode like a refused hold, so nothing holds again until staff extend or waive.
    """
    old = {
        "server_id": episode.server_id,
        "domain_id": episode.domain_id,
        "installation": episode.installation,
        "token": episode.hold_token,
        "generation": episode.hold_generation,
    }
    if episode.state in (EpisodeState.HOLDING, EpisodeState.HELD):
        episode.start_release("hold_withdrawn")
    purpose = episode.release_purpose
    if purpose in RELEASE_TO_GRACE:
        episode.confirm_released_to_grace()
    else:
        episode.confirm_released_to_closed()
    episode.needs_reconcile = False
    episode.last_error = reason
    if for_staff:
        episode.hold_refused_at = timezone.now()
    episode.save()
    audit_episode(
        episode,
        "database_overage_hold_released",
        "Database write hold left on a node that can no longer be asked",
        purpose=purpose,
        abandoned=True,
        reason=reason,
        **old,
    )
    if episode.state == EpisodeState.CLOSED:
        audit_episode(episode, "database_overage_closed", "Closed after release", close_reason=episode.close_reason)
    logger.warning("⚠️ [DatabaseOverage] Episode %s: hold abandoned: %s", episode.pk, reason)


def stale_identity(episode: DatabaseOverageEpisode, account: VirtualminAccount | None) -> bool:
    """For a hold on the node: the domain was recreated on the same node since (a verified recreation resets the
    collected identity, and the collector verifies the new domain id). A move to another node is the migration's
    to settle; an identity not collected yet is no evidence. The collector never accepts another installation
    under a verified binding, so only the domain id can change here."""
    collected = None if account is None else collected_identity(account)
    return collected is not None and collected[0] == episode.server_id and collected[1] != episode.domain_id


def rehold_refusal(episode: DatabaseOverageEpisode, account: VirtualminAccount | None) -> str | None:
    """Why grants that drifted under a held episode may not be held again now, or None. Checked under the locks.

    The hold already rests on the deadline and the over reading that decided it; a re-hold only needs the node and
    the account to be free, as the first hold did.
    """
    from .virtualmin_models import VirtualminServer  # noqa: PLC0415

    if account is None:
        return "account_gone"
    if not overage_enabled():
        return "flag_off"
    if episode.suspended_for:
        return "suspended_for_migration"
    if not VirtualminServer.objects.filter(pk=episode.server_id).exists():
        return "server_missing"
    if account_busy(account, ignore_episode_id=episode.pk):  # a re-hold sent again is its own operation
        return "active_operation"
    return None
