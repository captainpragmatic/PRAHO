"""Database overage episodes that need staff, across every service."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.db.models import Q, QuerySet
from django.utils import timezone

from .database_overage_models import DatabaseOverageEpisode, EpisodeState

DEFERRED_FOR = timedelta(hours=24)


def episodes_needing_attention(*, at: datetime | None = None) -> QuerySet[DatabaseOverageEpisode]:
    """Open episodes the sweep can't move on by itself.

    A hold deferred for more than a day, a hold the node refused (latched until staff extend or waive), a release
    whose last attempt failed, and grants that drifted from the hold.
    """
    now = at or timezone.now()
    return (
        DatabaseOverageEpisode.objects.exclude(state=EpisodeState.CLOSED)
        .filter(
            Q(deferred_since__lte=now - DEFERRED_FOR)
            | Q(hold_refused_at__isnull=False)
            | Q(state=EpisodeState.RELEASING, last_error__startswith="release pending")
            | Q(needs_reconcile=True)
        )
        .select_related("service")
        .order_by("deadline_at", "pk")
    )
