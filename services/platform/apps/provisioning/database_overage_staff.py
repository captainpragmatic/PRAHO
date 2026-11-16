"""What staff may do to a database overage episode: extend it, waive it, or release every hold at once.

Each action is decided under the account and episode locks and audited with the staff member and their
reason. A hold is never dropped here: an episode that may hold writes goes through `releasing`, and the sweep
fences its token and restores the grants.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from .database_overage_models import DatabaseOverageEpisode, EpisodeState
from .database_overage_service import audit_episode

if TYPE_CHECKING:
    from apps.users.models import User

logger = logging.getLogger(__name__)

MIN_EXTENSION_DAYS, MAX_EXTENSION_DAYS = 1, 30
MIN_REASON = 10


def _locked(episode_id: UUID, expected_revision: int | None) -> DatabaseOverageEpisode:
    """The account row, then the episode, as every episode writer locks them; refused if it changed since shown."""
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
    if account_id is not None:
        VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
    episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
    if expected_revision is not None and episode.revision != expected_revision:
        raise ValidationError(_("This episode changed since the page was shown. Review it again."))
    if episode.state == EpisodeState.CLOSED:
        raise ValidationError(_("This episode is closed."))
    if episode.state == EpisodeState.RELEASING:
        raise ValidationError(_("A release is in progress. Try again once it has finished."))
    return episode


def _reason(reason: str) -> str:
    reason = reason.strip()
    if len(reason) < MIN_REASON:
        raise ValidationError(_("Give a reason of at least %(count)d characters.") % {"count": MIN_REASON})
    return reason


def extend_episode(  # noqa: PLR0913 -- the staff decision and the revision it was made on
    episode_id: UUID,
    *,
    user: User,
    days: int,
    reason: str,
    expected_revision: int | None = None,
    at: datetime | None = None,
) -> None:
    """A later deadline: `max(now, deadline) + days`. A hold is released, which is the customer's write window."""
    now = at or timezone.now()
    if not MIN_EXTENSION_DAYS <= days <= MAX_EXTENSION_DAYS:
        raise ValidationError(
            _("Extend by %(low)d to %(high)d days.") % {"low": MIN_EXTENSION_DAYS, "high": MAX_EXTENSION_DAYS}
        )
    reason = _reason(reason)
    with transaction.atomic():
        episode = _locked(episode_id, expected_revision)
        previous = episode.deadline_at
        episode.deadline_at = max(now, episode.deadline_at) + timedelta(days=days)
        episode.hold_refused_at, episode.deferred_since, episode.last_error = None, None, ""
        if episode.state in (EpisodeState.HOLDING, EpisodeState.HELD):
            episode.start_release("extend")
        episode.save()
        audit_episode(
            episode,
            "database_overage_extended",
            "Staff extended the database over-allowance deadline",
            user=user,
            reason=reason,
            days=days,
            previous_deadline=previous.isoformat(),
        )
    logger.info("✅ [DatabaseOverage] Episode %s extended by %d days", episode_id, days)


def waive_episode(
    episode_id: UUID, *, user: User, reason: str, expected_revision: int | None = None, at: datetime | None = None
) -> None:
    """Close the episode: at once from grace, through the release when a hold may exist."""
    reason = _reason(reason)
    with transaction.atomic():
        episode = _locked(episode_id, expected_revision)
        if episode.state == EpisodeState.GRACE:
            episode.close("waived")
        else:
            episode.start_release("waived")
        episode.hold_refused_at = None
        episode.save()
        audit_episode(
            episode, "database_overage_waived", "Staff waived the database over-allowance", user=user, reason=reason
        )
    logger.info("✅ [DatabaseOverage] Episode %s waived", episode_id)


def _settle_rollback(episode_id: UUID) -> bool:
    """Under the lock: True when no hold is left (closed, or released into grace and now closed as rollback).

    Otherwise marks the episode's release as the rollback's and returns False, for the node to be asked.
    """
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415

    with transaction.atomic():
        # The account row first, as every episode writer locks them: a release becomes the account's operation.
        account_id = DatabaseOverageEpisode.objects.filter(pk=episode_id).values_list("account_id", flat=True).first()
        if account_id is not None:
            VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        if episode.state == EpisodeState.CLOSED:
            return True
        if episode.state == EpisodeState.GRACE:  # a release finished, for a write window or a migration
            episode.close("flag_rollback")
            episode.save()
            audit_episode(episode, "database_overage_closed", "Closed by release-all", close_reason="flag_rollback")
            return True
        if episode.state in (EpisodeState.HOLDING, EpisodeState.HELD):
            episode.start_release("flag_rollback")
        else:  # already releasing: it now ends closed, even if this attempt fails
            episode.release_purpose = "flag_rollback"
        episode.save()
        return False


def release_all(*, at: datetime | None = None) -> dict[str, Any]:
    """Rollback: every holding or held episode released and closed as flag_rollback; releasing ones finish first."""
    from .database_overage_tasks import _gateway, _release  # noqa: PLC0415 -- the sweep's own release step

    now = at or timezone.now()
    gateway = _gateway()
    outcomes: dict[str, Any] = {"released": 0, "pending": []}
    for episode_id in DatabaseOverageEpisode.objects.filter(
        state__in=(EpisodeState.HOLDING, EpisodeState.HELD, EpisodeState.RELEASING)
    ).values_list("pk", flat=True):
        # The sweep keeps running: decide on the state found under the lock, not the one listed above.
        # Whatever the node step answered, the locked state decides: the sweep may have settled it meanwhile.
        if _settle_rollback(episode_id) or (_release(episode_id, gateway, at=now) and _settle_rollback(episode_id)):
            outcomes["released"] += 1
        else:
            outcomes["pending"].append(str(episode_id))
    return outcomes
