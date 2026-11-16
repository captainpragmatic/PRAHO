"""The database overage sweep, every 15 minutes: notices, the deadline, and the node hold and its release.

Every node call follows the same shape: the decision is persisted under the account and episode locks first,
the node is asked outside any transaction, and the answer is recorded under the episode lock again, only if
the episode still holds the decision it was asked about. A lost answer is never taken as success: the next
sweep verifies before deciding anything.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Result

from . import database_hold_gateway
from .database_overage_admission import close_for_terminated_account, release_writer
from .database_overage_delivery import notice_due, record_notice_acceptance, send_notice
from .database_overage_models import DatabaseOverageEpisode, EpisodeState, NoticeKind
from .database_overage_service import (
    audit_episode,
    enforcement_refusal,
    evaluate_account,
    next_hold_generation,
    overage_enabled,
    rehold_refusal,
)

logger = logging.getLogger(__name__)

SCHEDULE_NAME = "database-overages"
SWEEP_FUNCTION = "apps.provisioning.database_overage_tasks.sweep_database_overages"
VERIFY_EVERY = timedelta(hours=1)
DEFERRAL_ATTENTION = timedelta(hours=24)
# Node refusals that pass: the node is busy or another operation holds the domain. Wait and ask again.
# Every other code is a refusal of the account's grants as they stand, which staff must look at.
RETRY_CODES = frozenset({"uncertain", "lock_busy", "barrier_active", "component_fence_active"})


def setup_overage_sweep() -> dict[str, str]:
    from django_q.models import Schedule  # noqa: PLC0415

    _schedule, created = Schedule.objects.update_or_create(
        name=SCHEDULE_NAME,
        defaults={"func": SWEEP_FUNCTION, "schedule_type": "I", "minutes": 15, "repeats": -1},
    )
    return {"database_overages": "created" if created else "updated"}


def _gateway() -> ModuleType:
    """The node's hold gateway; tests put a stand-in for the node here."""
    return database_hold_gateway


def _ask(gateway: Any, action: str, identity: Any, **terms: Any) -> Result[Any, Any]:
    """One node call. A server record gone since the episode opened answers like a lost response: wait, never crash."""
    from .virtualmin_models import VirtualminServer  # noqa: PLC0415

    try:
        result: Result[Any, Any] = getattr(gateway, action)(identity, **terms)
    except VirtualminServer.DoesNotExist:
        logger.warning("⚠️ [DatabaseOverage] %s for domain %s: the server record is gone", action, identity.domain_id)
        return Err(database_hold_gateway.HoldRefusal("uncertain", "server_missing"))
    return result


def _identity(gateway: Any, episode: DatabaseOverageEpisode) -> Any:
    return gateway.HoldIdentity(
        server_id=episode.server_id,
        domain_id=episode.domain_id,
        domain=episode.domain,
        installation=episode.installation,
    )


def _bound(receipt: Any, identity: Any, generation: int, token: UUID | None = None) -> bool:
    """The receipt answers this request: same identity, generation and, for a hold, token."""
    return (
        receipt.identity == identity and receipt.generation == generation and (token is None or receipt.token == token)
    )


def _defer(episode_id: UUID, reason: str, *, at: datetime) -> str:
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.deferred_since is None:
            episode.deferred_since = at
        if at - episode.deferred_since >= DEFERRAL_ATTENTION and reason not in episode.last_error:
            episode.last_error = f"deferred since {episode.deferred_since.isoformat()}: {reason}"
            logger.error("🔥 [DatabaseOverage] Hold for episode %s deferred over a day: %s", episode.pk, reason)
        episode.save(update_fields=["deferred_since", "last_error", "updated_at"])
    return "deferred"


def _enforce(episode_id: UUID, gateway: Any, *, at: datetime | None) -> str:
    """At the deadline: persist the decision to hold, ask the node, record its answer.

    ``at`` is for tests; otherwise the decision is timed once the locks are held, never at the sweep's start.
    """
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    with transaction.atomic():
        account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
        if account_id is None:
            return "not_due"  # an episode with no account is closed by node_gone or staff, never held
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        now = at or timezone.now()
        if account is None or episode.state != EpisodeState.GRACE or now < episode.deadline_at:
            return "not_due"
        reason = enforcement_refusal(episode, account, at=now)
        if reason is None:
            token, generation = uuid4(), next_hold_generation(account)
            episode.start_hold(token=token, generation=generation)
            episode.deferred_since, episode.last_error = None, ""
            episode.save()
            # On record before the node is asked: a worker dying mid-call still leaves the attempt in the trail.
            audit_episode(episode, "database_overage_hold_requested", "Database write hold requested from the node")
    if reason is not None:
        return _defer(episode_id, reason, at=now)
    identity = _identity(gateway, episode)
    result = _ask(gateway, "hold", identity, token=token, generation=generation)
    return _record_hold(episode_id, result, identity, token, generation, at=at or timezone.now())


def _record_hold(  # noqa: PLR0913 -- the answer and the request it answers
    episode_id: UUID, result: Any, identity: Any, token: UUID | None, generation: int, *, at: datetime
) -> str:
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        # Only the decision this answer was asked for may be settled by it, success or refusal.
        if episode.state != EpisodeState.HOLDING or (episode.hold_token, episode.hold_generation) != (
            token,
            generation,
        ):
            return "superseded"
        if result.is_err():
            refusal = result.error
            if refusal.code in RETRY_CODES:
                episode.last_error = f"hold not settled: {refusal.code}"
                episode.save(update_fields=["last_error", "updated_at"])
                return "uncertain"  # the next sweep verifies, and sends the hold again only if still due
            episode.start_release("hold_refused")
            episode.hold_refused_at, episode.last_error = at, f"hold refused: {refusal.code}: {refusal.detail}"
            episode.save()
            logger.error("🔥 [DatabaseOverage] Node refused the hold for episode %s: %s", episode.pk, refusal.code)
            return "refused"
        receipt = result.unwrap()
        if not _bound(receipt, identity, episode.hold_generation, episode.hold_token):
            episode.last_error = "hold receipt for another request"
            episode.save(update_fields=["last_error", "updated_at"])
            return "uncertain"
        return _settle_holding(episode, receipt, at=at)


def _settle_holding(episode: DatabaseOverageEpisode, receipt: Any, *, at: datetime) -> str:
    """Held only when every row is revoked and every session open at the revoke has gone."""
    if receipt.phase in {"held", "verified"} and not receipt.sessions_remaining and not receipt.drift:
        episode.confirm_held(digest=receipt.held_digest)
        episode.verified_at, episode.last_error = at, ""
        episode.save()
        audit_episode(episode, "database_overage_hold_applied", "Database write hold confirmed on the node")
        logger.info("✅ [DatabaseOverage] Episode %s held", episode.pk)
        return "held"
    episode.sessions_remaining = list(receipt.sessions_remaining)
    episode.save(update_fields=["sessions_remaining", "updated_at"])
    return "holding"


def _withdraw_unless_due(episode_id: UUID, token: UUID | None, generation: int, *, at: datetime | None) -> str | None:
    """Before sending an undelivered hold again: the same checks as the first time, under the same locks."""
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    with transaction.atomic():
        account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first() if account_id else None
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.state != EpisodeState.HOLDING or (episode.hold_token, episode.hold_generation) != (
            token,
            generation,
        ):
            return "superseded"
        now = at or timezone.now()  # timed under the locks, like the first decision
        if episode.needs_reconcile:
            # A re-hold after drift (needs_reconcile stays set until the node confirms it): it rests on the hold
            # already decided, so it is sent again on the re-hold's terms, and never withdrawn into a release.
            if (reason := rehold_refusal(episode, account)) is None:
                audit_episode(
                    episode,
                    "database_overage_hold_requested",
                    "Database write hold requested again",
                    resent=True,
                    reason="reconcile",
                )
                return None
            episode.last_error = f"re-hold pending: {reason}"
            episode.save(update_fields=["last_error", "updated_at"])
            return "rehold_deferred"
        if account is None:
            reason = "account_gone"
        elif now < episode.deadline_at:
            reason = "not_due"  # a pause moved the deadline: the 14 days are a promise, resent holds included
        else:
            reason = enforcement_refusal(episode, account, at=now)
        if reason is None:
            audit_episode(
                episode, "database_overage_hold_requested", "Database write hold requested again", resent=True
            )
            return None
        # Nothing reached the node; fencing the token in the release keeps a late copy from ever applying.
        episode.start_release("hold_withdrawn")
        episode.last_error = f"hold withdrawn before it reached the node: {reason}"
        episode.save()
    return "withdrawn"


def _verify_holding(episode_id: UUID, gateway: Any, *, at: datetime | None) -> str:
    """Holding with no settled answer: ask the node what it has, and send a hold it never received again."""
    episode = DatabaseOverageEpisode.objects.get(pk=episode_id)
    if episode.suspended_for:
        return "suspended"  # a migration's activation hold: that migration settles it, or its end does
    identity, token, generation = _identity(gateway, episode), episode.hold_token, episode.hold_generation
    result = _ask(gateway, "verify", identity, generation=generation)
    if result.is_ok() and _bound(result.unwrap(), identity, generation) and result.unwrap().drift:
        # The node has no journal for this decision (the request never reached it, or the node turned it away),
        # or grants came back before the hold settled. The same decision, sent again, resumes the node's journal.
        # Sent again only if the hold would still be decided now; else withdrawn.
        if (withdrawn := _withdraw_unless_due(episode_id, token, generation, at=at)) is not None:
            return withdrawn
        result = _ask(gateway, "hold", identity, token=token, generation=generation)
        return _record_hold(episode_id, result, identity, token, generation, at=at or timezone.now())
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.state != EpisodeState.HOLDING or (episode.hold_token, episode.hold_generation) != (
            token,
            generation,
        ):
            return "superseded"
        if result.is_err() or not _bound(result.unwrap(), identity, generation):
            return "uncertain"
        return _settle_holding(episode, result.unwrap(), at=at or timezone.now())


def _verify_held(episode_id: UUID, gateway: Any, *, at: datetime) -> str:
    episode = DatabaseOverageEpisode.objects.get(pk=episode_id)
    if episode.verified_at is not None and at - episode.verified_at < VERIFY_EVERY and not episode.needs_reconcile:
        return "verified_recently"
    identity, asked_at_revision = _identity(gateway, episode), episode.revision
    result = _ask(gateway, "verify", identity, generation=episode.hold_generation)
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.state != EpisodeState.HELD or result.is_err():
            return "uncertain"
        receipt = result.unwrap()
        if not _bound(receipt, identity, episode.hold_generation):
            return "uncertain"
        if episode.revision != asked_at_revision and not receipt.drift:
            # A clean answer may be older than drift recorded meanwhile: never let it clear that. Drift is kept.
            return "superseded"
        episode.verified_at = at
        episode.needs_reconcile = bool(receipt.drift)  # a clean verify resolves earlier drift
        if receipt.drift:
            audit_episode(
                episode, "database_hold_drift", "The node's grants differ from the hold", drift=list(receipt.drift)
            )
            logger.warning("⚠️ [DatabaseOverage] Hold drift on episode %s: %s", episode.pk, ", ".join(receipt.drift))
        episode.save(update_fields=["verified_at", "needs_reconcile", "updated_at"])
        return "drift" if receipt.drift else "verified"


def _locked_for_rehold(episode_id: UUID, token: UUID | None) -> tuple[DatabaseOverageEpisode, Any] | None:
    """Account then episode, under the caller's transaction; None unless still held with drift on that token."""
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
    account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first() if account_id else None
    episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
    if episode.state != EpisodeState.HELD or not episode.needs_reconcile or episode.hold_token != token:
        return None
    return episode, account


def _rehold(episode_id: UUID, gateway: Any, *, at: datetime | None) -> str:
    """Grants came back under a held episode (a restore, a re-create, an edit): fence the hold's token, then hold
    again with a new generation. The node keeps each row's original image, so a release still restores those."""
    token = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("hold_token", flat=True).first()
    with transaction.atomic():
        if (locked := _locked_for_rehold(episode_id, token)) is None:
            return "superseded"
        episode, account = locked
        if (reason := rehold_refusal(episode, account)) is not None:
            episode.last_error = f"re-hold deferred: {reason}"  # held as it is; the drift stays on the list
            episode.save(update_fields=["last_error", "updated_at"])
            return "rehold_deferred"
    identity = _identity(gateway, episode)
    if token is not None and isinstance(fenced := _ask(gateway, "fence", identity, token=token), Err):
        # Nothing changed: still held, and the next sweep verifies and tries again.
        return _note(episode_id, f"re-hold pending: the hold token could not be fenced: {fenced.error.detail}")
    with transaction.atomic():
        if (locked := _locked_for_rehold(episode_id, token)) is None:
            return "superseded"
        episode, account = locked
        if (reason := rehold_refusal(episode, account)) is not None:  # admitted meanwhile: still held, retried
            episode.last_error = f"re-hold deferred: {reason}"
            episode.save(update_fields=["last_error", "updated_at"])
            return "rehold_deferred"
        new_token, generation = uuid4(), next_hold_generation(account)
        episode.start_rehold(token=new_token, generation=generation)
        episode.last_error = ""
        episode.save()
        audit_episode(
            episode,
            "database_overage_hold_requested",
            "Database write hold requested again after drift",
            reason="reconcile",
            fenced_token=token,
        )
    result = _ask(gateway, "hold", identity, token=new_token, generation=generation)
    return _record_hold(episode_id, result, identity, new_token, generation, at=at or timezone.now())


def _note(episode_id: UUID, detail: str) -> str:
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        episode.last_error = detail
        episode.save(update_fields=["last_error", "updated_at"])
    logger.warning("⚠️ [DatabaseOverage] Episode %s: %s", episode_id, detail)
    return "uncertain"


def _release(episode_id: UUID, gateway: Any, *, at: datetime, ignore_migration_id: UUID | None = None) -> str:
    """Fence the hold's token, so it can never hold again, then restore the journalled grants.

    A release waits while another live operation writes the same grants or identity (a restore, a quota change,
    a migration): it would restore over them. It never waits on one parked for staff.
    """
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    with transaction.atomic():
        account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first() if account_id else None
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.state != EpisodeState.RELEASING:
            return "superseded"
        if _release_waits(episode, account, at=at, ignore_migration_id=ignore_migration_id):
            return "release_waiting"
        # On record before the node is asked, each attempt numbered, including one whose worker then dies.
        episode.attempts += 1
        episode.deferred_since = None
        episode.save(update_fields=["attempts", "deferred_since", "updated_at"])
        audit_episode(
            episode,
            "database_overage_release_requested",
            "Database write hold release requested from the node",
            purpose=episode.release_purpose,
            attempt=episode.attempts,
        )
    identity, token, generation = _identity(gateway, episode), episode.hold_token, episode.hold_generation
    if token is not None and isinstance(fenced := _ask(gateway, "fence", identity, token=token), Err):
        return _release_failed(episode_id, f"the hold token could not be fenced: {fenced.error.detail}")
    result = _ask(gateway, "release", identity, generation=generation)
    if isinstance(result, Err) or not _bound(result.unwrap(), identity, generation):
        detail = result.error.detail if isinstance(result, Err) else "release receipt for another request"
        return _release_failed(episode_id, detail)
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        # The receipt answers the release asked for: never settle a newer hold with it.
        if episode.state != EpisodeState.RELEASING or (episode.hold_token, episode.hold_generation) != (
            token,
            generation,
        ):
            return "superseded"
        purpose = episode.release_purpose
        episode.needs_reconcile = False  # released: the journalled grants are restored, no hold left to drift
        if purpose in {"hold_refused", "hold_withdrawn", "extend", "migration"}:
            episode.confirm_released_to_grace()
            if purpose == "hold_refused":
                episode.deferred_since = at  # left for staff: extend or waive
        else:
            episode.confirm_released_to_closed()
        episode.save()
        audit_episode(episode, "database_overage_hold_released", "Database write hold released", purpose=purpose)
        if episode.state == EpisodeState.CLOSED:
            audit_episode(episode, "database_overage_closed", "Closed after release", close_reason=episode.close_reason)
    logger.info("✅ [DatabaseOverage] Episode %s released (%s)", episode_id, purpose)
    return "released"


def _release_waits(
    episode: DatabaseOverageEpisode, account: Any, *, at: datetime, ignore_migration_id: UUID | None = None
) -> bool:
    """Under the locks: a live writer of the same grants runs, so the release waits, on record, for the next sweep.

    A migration releasing its own episode before it moves the account is not a writer it waits for.
    """
    if account is None or (writer := release_writer(account, ignore_migration_id=ignore_migration_id)) is None:
        return False
    if episode.deferred_since is None:
        episode.deferred_since = at  # past a day, staff see it (the attention list)
    episode.last_error = f"release waiting for a running {writer}"
    episode.save(update_fields=["deferred_since", "last_error", "updated_at"])
    return True


def _release_failed(episode_id: UUID, detail: str) -> str:
    with transaction.atomic():
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        episode.last_error = f"release pending: {detail}"  # the attempt was counted before the node call
        episode.save(update_fields=["last_error", "updated_at"])
    logger.warning("⚠️ [DatabaseOverage] Release of episode %s pending: %s", episode_id, detail)
    return "release_pending"


def _advance(episode_id: UUID, gateway: Any, *, at: datetime | None) -> str:
    """One episode's step. A hold decision reads the clock under its locks; the rest at the step's start."""
    episode = DatabaseOverageEpisode.objects.get(pk=episode_id)
    now = at or timezone.now()
    if episode.state == EpisodeState.GRACE:
        if overage_enabled() and notice_due(episode, NoticeKind.DAY0):
            send_notice(episode.pk, NoticeKind.DAY0, at=now)
        if now < episode.deadline_at:
            return "grace"
        return _enforce(episode.pk, gateway, at=at)
    if episode.state == EpisodeState.HOLDING:
        return _verify_holding(episode.pk, gateway, at=at)
    if episode.state == EpisodeState.RELEASING:
        return _release(episode.pk, gateway, at=now)
    if notice_due(episode, NoticeKind.DAY14):
        send_notice(episode.pk, NoticeKind.DAY14, at=now)
    outcome = _verify_held(episode.pk, gateway, at=now)
    if outcome == "drift":
        return _rehold(episode.pk, gateway, at=at)
    return outcome


def sweep_database_overages(at: datetime | None = None) -> dict[str, int]:
    """One pass over every quota-managed account and every open episode."""
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    outcomes: Counter[str] = Counter()
    outcomes["accepted"] = record_notice_acceptance()
    # Backstop for the termination hook: an account terminated without it (or whose hook failed) closes here.
    for account_id in (
        DatabaseOverageEpisode.objects.exclude(state=EpisodeState.CLOSED)
        .filter(account__status="terminated")
        .values_list("account_id", flat=True)
    ):
        outcomes["node_deleted"] += close_for_terminated_account(account_id)
    open_accounts = DatabaseOverageEpisode.objects.exclude(state=EpisodeState.CLOSED).values("account_id")
    accounts = VirtualminAccount.objects.filter(quota_managed=True) | VirtualminAccount.objects.filter(
        pk__in=open_accounts
    )
    for account_id in accounts.values_list("pk", flat=True).distinct():
        outcomes[evaluate_account(account_id, at=at)] += 1  # it reads the clock under its own locks
    gateway = _gateway()
    for episode_id in DatabaseOverageEpisode.objects.exclude(state=EpisodeState.CLOSED).values_list("pk", flat=True):
        try:
            outcomes[_advance(episode_id, gateway, at=at)] += 1
        except Exception:  # One episode's failure never stops the sweep for the others
            logger.exception("🔥 [DatabaseOverage] Sweep step failed for episode %s", episode_id)
            outcomes["failed"] += 1
    return dict(outcomes)
