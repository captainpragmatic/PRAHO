"""A database overage episode across a migration of its account (#776, plan 7B.3 and revision 3 item 4).

- Start: under the migration's admission lock the episode is suspended for that migration; a held episode also
  moves to releasing, remembering it was held.
- Before the barrier record: the hold is fenced and released, verified, so the move copies the customer's own
  grants. A release that doesn't complete refuses the migration.
- Activation: an episode held at the start is held again on the target, by the activation itself, before the
  target admits writes. A hold the target turns down leaves the episode in grace, due, and staff are told.
- The end: completed, failed, cancelled or rolled back, the suspension is cleared.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err

from .database_overage_models import DatabaseOverageEpisode, EpisodeState, SuspendedFor
from .database_overage_service import abandon_hold, audit_episode, next_hold_generation, overage_enabled
from .virtualmin_models import VirtualminAccount

logger = logging.getLogger(__name__)


class MigrationHoldReleaseError(ValueError):
    """The episode's hold could not be released before the move: the migration is refused."""


def _open_episode(account_id: Any) -> DatabaseOverageEpisode | None:
    return (
        DatabaseOverageEpisode.objects.select_for_update()
        .filter(account_id=account_id)
        .exclude(state=EpisodeState.CLOSED)
        .first()
    )


def component_review_refusal(account_id: Any) -> str | None:
    """A component review records the source's grants: never while a hold has revoked some of them."""
    if (
        DatabaseOverageEpisode.objects.filter(account_id=account_id)
        .filter(state__in=(EpisodeState.HOLDING, EpisodeState.HELD, EpisodeState.RELEASING))
        .exists()
    ):
        return _("Extend or waive the database write hold before reviewing or starting a component migration.")
    return None


def suspend_for_migration(account: VirtualminAccount, migration_id: UUID, *, held_allowed: bool = True) -> None:
    """In the migration's admission transaction, its account row already locked.

    A whole-domain move releases a held episode itself; a component move (held_allowed False) never sees one.
    """
    episode = _open_episode(account.pk)
    if episode is None:
        return
    if not held_allowed and episode.state != EpisodeState.GRACE:
        raise ValueError(component_review_refusal(account.pk) or "The database write hold is not in grace")
    if episode.suspended_for and episode.suspended_migration_id != migration_id:
        raise ValueError("The account's database write hold is suspended for another migration")
    if episode.state not in (EpisodeState.GRACE, EpisodeState.HELD):
        raise ValueError("A database write hold is being applied or released; migrate once it settles")
    episode.suspended_for, episode.suspended_migration_id = SuspendedFor.MIGRATION, migration_id
    if episode.state == EpisodeState.HELD:
        episode.hold_follows_migration = True
        episode.start_release("migration")
    episode.save()
    # The release itself goes on record with each attempt (release_requested); the migration audits its own start.
    logger.info("✅ [DatabaseOverage] Episode %s suspended for migration %s", episode.pk, migration_id)


def suspend_for_recovery(account: VirtualminAccount, recovery_id: UUID) -> None:
    """In the recovery's admission, its account locked, before the busy check: the source node is fenced, so a hold
    there can't be released or verified. Its journal is left on record as abandoned (no node is asked), and an
    episode that was holding or held is held again on the target before the target is enabled."""
    episode = _open_episode(account.pk)
    if episode is None:
        return
    if episode.suspended_for and episode.suspended_migration_id != recovery_id:
        raise ValueError("The account's database write hold is suspended for another migration")
    follows = episode.state in (EpisodeState.HOLDING, EpisodeState.HELD)
    if episode.state != EpisodeState.GRACE:
        abandon_hold(
            episode,
            f"source node fenced for recovery: its hold journal (generation {episode.hold_generation}) is abandoned",
            for_staff=False,
        )
    if episode.state == EpisodeState.CLOSED:
        return
    episode.suspended_for, episode.suspended_migration_id = SuspendedFor.MIGRATION, recovery_id
    episode.hold_follows_migration = follows
    episode.save()


def hold_before_enable(migration: Any, hold: dict[str, Any] | None) -> str:
    """Recovery activation, before the target's runtime is enabled: the decided hold applied through the hold
    gateway. Held or holding: on record, with a verify at the next sweep. Refused: the target activates, the
    episode releases for staff. Not settled: the activation is retried later with this same hold."""
    from .database_overage_tasks import RETRY_CODES, _ask, _gateway, _identity  # noqa: PLC0415

    if hold is None:
        return "no_hold"
    gateway = _gateway()
    episode = DatabaseOverageEpisode.objects.get(account_id=migration.account_id, suspended_migration_id=migration.pk)
    identity = _identity(gateway, episode)
    result = _ask(gateway, "hold", identity, token=UUID(hold["token"]), generation=hold["generation"])
    refusal: Any = result.error if isinstance(result, Err) else None
    receipt: Any = None if refusal is not None else result.unwrap()
    if refusal is not None and refusal.code in RETRY_CODES:
        raise MigrationHoldReleaseError(f"the target's database write hold is not settled: {refusal.code}")
    if receipt is not None and (receipt.identity != identity or str(receipt.token) != hold["token"]):
        raise MigrationHoldReleaseError("the target's database write hold receipt is for another request")
    with transaction.atomic():
        VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
        current = _open_episode(migration.account_id)
        if current is None or not activation_hold_current(migration, hold):
            return "superseded"
        episode = current
        episode.suspended_for, episode.suspended_migration_id, episode.hold_follows_migration = "", None, False
        if receipt is None:
            episode.start_release("hold_refused")
            episode.hold_refused_at = timezone.now()
            episode.last_error = f"target hold refused: {refusal.code}: {refusal.detail}"
            episode.save()
            return "refused"
        episode.needs_reconcile = True  # activation re-enables the logins: the first sweep verifies the grants
        if receipt.phase == "held" and not receipt.sessions_remaining:
            episode.confirm_held(digest=receipt.held_digest)
            episode.needs_reconcile = True
            episode.verified_at = timezone.now()
            audit_episode(
                episode, "database_overage_hold_applied", "Database write hold applied on the recovery target"
            )
        episode.save()
    return "held"


def release_before_move(migration_id: UUID, account_id: Any) -> None:
    """Before the barrier record: an episode released for this migration must be released on the node now."""
    from .database_overage_tasks import _gateway, _release  # noqa: PLC0415 -- the sweep's own release step

    episode = DatabaseOverageEpisode.objects.filter(account_id=account_id, suspended_migration_id=migration_id).first()
    if episode is None or episode.state != EpisodeState.RELEASING:
        return
    outcome = _release(episode.pk, _gateway(), at=timezone.now(), ignore_migration_id=migration_id)
    episode.refresh_from_db()
    if episode.state != EpisodeState.GRACE:
        raise MigrationHoldReleaseError(f"The database write hold was not released before the move: {outcome}")


def target_installation(server_id: Any) -> UUID | None:
    """The usage collector installation the target node last reported, which its hold journal is keyed by."""
    from .virtualmin_usage_models import UsageInterval  # noqa: PLC0415

    return (
        UsageInterval.objects.filter(server_id=server_id, installation__isnull=False)
        .order_by("-started_at")
        .values_list("installation", flat=True)
        .first()
    )


def activation_hold(migration: Any) -> dict[str, Any] | None:
    """Before activation: the hold to apply on the target, persisted first with the target's identity, or None.

    A retried activation sends the hold it already decided on: the node resumes the same token and generation.
    """
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
        episode = _open_episode(account.pk)
        if (
            episode is None
            or episode.suspended_migration_id != migration.pk
            or not episode.hold_follows_migration
            or not overage_enabled()
        ):
            return None
        identity = {
            "server_id": migration.target_server_id,
            "domain_id": str(migration.barrier_state.get("target_domain_id") or ""),
            "domain": account.domain,
            "installation": target_installation(migration.target_server_id),
        }
        if episode.state == EpisodeState.GRACE:
            if episode.deadline_at > timezone.now():  # extended since the source was released: writes stay open
                episode.hold_follows_migration = False
                episode.save(update_fields=["hold_follows_migration", "updated_at"])
                return None
            if not identity["domain_id"] or identity["installation"] is None:
                episode.last_error = "the target's native identity is not known yet; held after the move instead"
                episode.save(update_fields=["last_error", "updated_at"])
                return None
            for field, value in identity.items():
                setattr(episode, field, value)
            episode.start_hold(token=uuid4(), generation=next_hold_generation(account))
            episode.save()
            audit_episode(
                episode,
                "database_overage_hold_requested",
                "Database write hold requested on the migration target, with its activation",
                migration=migration.pk,
            )
        elif episode.state != EpisodeState.HOLDING or any(
            getattr(episode, field) != value for field, value in identity.items()
        ):
            return None
    return {
        "token": str(episode.hold_token),
        "generation": episode.hold_generation,
        "installation": str(episode.installation),
    }


def activation_hold_current(migration: Any, hold: dict[str, Any] | None) -> dict[str, Any] | None:
    """Under the activation guard: the decided hold if it still stands; None once staff extended or waived it."""
    if hold is None:
        return None
    episode = _open_episode(migration.account_id)
    current = (
        episode is not None
        and episode.state == EpisodeState.HOLDING
        and episode.suspended_migration_id == migration.pk
        and (str(episode.hold_token), episode.hold_generation) == (hold["token"], hold["generation"])
    )
    return hold if current else None


def record_activation_hold(migration: Any, hold: dict[str, Any] | None, outcome: object) -> str:
    """The activation's hold outcome, for exactly the hold it was asked: held, or back in grace and due for staff."""
    if hold is None:
        return "no_hold"
    if not isinstance(outcome, dict):
        raise ValueError("Target activation returned no billing hold outcome")
    now = timezone.now()
    with transaction.atomic():
        VirtualminAccount.objects.select_for_update().get(pk=migration.account_id)
        episode = _open_episode(migration.account_id)
        if (
            episode is None
            or episode.state != EpisodeState.HOLDING
            or (str(episode.hold_token), episode.hold_generation) != (hold["token"], hold["generation"])
        ):
            return "superseded"
        episode.suspended_for, episode.suspended_migration_id, episode.hold_follows_migration = "", None, False
        if outcome["outcome"] == "held":
            episode.confirm_held(digest=outcome["held_digest"])
            episode.verified_at, episode.last_error = now, ""
            episode.save()
            audit_episode(
                episode, "database_overage_hold_applied", "Database write hold applied on the migration target"
            )
            return "held"
        # The node already fenced the token, released and verified nothing is held, and activated as before.
        episode.start_release("migration")
        episode.confirm_released_to_grace()
        episode.hold_refused_at = now  # staff decide: extend or waive, as for any refused hold
        episode.last_error = f"target hold not applied: {outcome['reason']}: {outcome['code'] or ''}".rstrip(": ")
        episode.save()
        audit_episode(
            episode,
            "database_overage_hold_released",
            "The migration target did not keep the database write hold",
            purpose="migration",
            reason=outcome["reason"],
            code=outcome["code"],
        )
    logger.error("🔥 [DatabaseOverage] Target hold for episode %s not applied: %s", episode.pk, episode.last_error)
    return "not_held"


def settle_after_migration(migration_id: UUID, account_id: Any) -> None:
    """In the migration's terminal transaction, its account locked: the episode is no longer suspended for it.

    Its native identity is brought up to the account's current server by the next hold decision, never here.
    """
    episode = (
        DatabaseOverageEpisode.objects.select_for_update()
        .filter(account_id=account_id, suspended_migration_id=migration_id)
        .exclude(state=EpisodeState.CLOSED)
        .first()
    )
    if episode is None:
        return
    episode.suspended_for, episode.suspended_migration_id, episode.hold_follows_migration = "", None, False
    episode.save()
