"""Admission for the database write hold: the node is asked only what an open episode stands for."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from .database_overage_models import DatabaseOverageEpisode, EpisodeState
from .database_overage_service import audit_episode, overage_enabled
from .virtualmin_models import VirtualminAccount, VirtualminServer

logger = logging.getLogger(__name__)

HOLD_PLAYBOOK = "virtualmin_database_hold.yml"
IDENTITY_KEYS = frozenset({"domain_id", "domain", "installation"})
# Per action: the request's terms beyond action and identity, and the states the episode may be in.
ADMITTED = {
    "hold": (frozenset({"token", "generation"}), frozenset({EpisodeState.HOLDING})),
    "verify": (frozenset({"generation"}), frozenset({EpisodeState.HOLDING, EpisodeState.HELD})),
    # Releasing, or held with drift to reconcile: the old token is fenced before a new generation holds.
    "fence": (frozenset({"token"}), frozenset({EpisodeState.RELEASING, EpisodeState.HELD})),
    "release": (frozenset({"generation"}), frozenset({EpisodeState.RELEASING})),
}
REFUSED = "The database hold request is not the one its open overage episode stands for."
# The node calls in flight: while one is, the account's grants are the hold's to change.
BLOCKING_STATES = frozenset({EpisodeState.HOLDING, EpisodeState.RELEASING})
# Who else writes the grants or the identity a release restores: a release waits for them while they run.
RELEASE_WRITER_JOBS = ("restore_domain", "apply_hosting_limits")


def episode_blocks(account: VirtualminAccount, *, ignore_episode_id: UUID | None = None) -> bool:
    """A hold or a release of the account's episode is on its way to the node: other operations wait for it.

    A held episode doesn't block: it lasts days, and backups, restores and migrations go on meanwhile.
    """
    blocking = DatabaseOverageEpisode.objects.filter(account_id=account.pk, state__in=BLOCKING_STATES)
    if ignore_episode_id is not None:
        blocking = blocking.exclude(pk=ignore_episode_id)
    return blocking.exists()


def flag_reconcile(account_id: UUID) -> None:
    """In the caller's transaction, under its account lock: a hold on the account is verified at the next sweep."""
    DatabaseOverageEpisode.objects.filter(
        account_id=account_id, state__in=(EpisodeState.HOLDING, EpisodeState.HELD)
    ).update(needs_reconcile=True)


def release_writer(account: VirtualminAccount, *, ignore_migration_id: UUID | None = None) -> str | None:
    """The live operation a release waits for, or None. Never one parked for staff: release is the safe way."""
    from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415 -- migrations import this module
    from .virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415

    migrations = VirtualminMigration.objects.filter(account_id=account.pk).exclude(
        status__in=("completed", "failed", "rolled_back", "needs_review")
    )
    if ignore_migration_id is not None:
        migrations = migrations.exclude(pk=ignore_migration_id)
    if migrations.exists():
        return "migration"
    return (
        VirtualminProvisioningJob.objects.filter(
            account_id=account.pk, operation__in=RELEASE_WRITER_JOBS, status__in=("pending", "running")
        )
        .values_list("operation", flat=True)
        .first()
    )


def database_hold_transport_refusal(server: VirtualminServer, variables: dict[str, Any] | None) -> str | None:
    """The shared SSH runner runs the hold playbook only for the exact request an open episode decided on."""
    values = variables or {}
    action, request = values.get("hold_action"), values.get("hold_request")
    if action not in ADMITTED or not isinstance(request, dict) or request.get("action") != action:
        return "An admitted database hold action is required."
    terms, states = ADMITTED[action]
    if (parsed := _request_terms(request, terms)) is None:
        return REFUSED
    identity, installation, token, generation = parsed
    # One open episode per account, and a closed one is never in an admitted state.
    episode = DatabaseOverageEpisode.objects.filter(
        state__in=states,
        server_id=server.pk,
        domain_id=identity["domain_id"],
        domain=identity["domain"],
        installation=installation,
    ).first()
    if (
        episode is None
        or (episode.state == EpisodeState.HELD and action == "fence" and not episode.needs_reconcile)
        or (token is not None and token != episode.hold_token)
        or (generation is not None and generation != episode.hold_generation)
    ):
        return REFUSED
    if action == "hold" and not overage_enabled():
        return "Database overage holds are switched off."
    return None


def _request_terms(
    request: dict[str, Any], terms: frozenset[str]
) -> tuple[dict[str, Any], UUID, UUID | None, int | None] | None:
    """The request's identity, installation, token and generation, if it has exactly the action's terms."""
    identity = request.get("identity")
    if (
        set(request) != terms | {"action", "identity"}
        or not isinstance(identity, dict)
        or set(identity) != IDENTITY_KEYS
    ):
        return None
    generation = request.get("generation")
    if "generation" in terms and type(generation) is not int:
        return None
    try:
        installation = UUID(str(identity["installation"]))
        token = UUID(request["token"]) if "token" in terms else None
    except (TypeError, ValueError, AttributeError):
        return None
    return identity, installation, token, generation


def settle_ownership_change(account_ids: Iterable[Any]) -> None:
    """In the ownership change's transaction, its accounts already locked: an episode in grace closes with it; a
    hold on the node, or a migration that suspended the episode, refuses the change until staff release or waive."""
    episodes = (
        DatabaseOverageEpisode.objects.select_for_update()
        .filter(account_id__in=tuple(account_ids))
        .exclude(state=EpisodeState.CLOSED)
        .order_by("pk")
    )
    for episode in episodes:
        if episode.state != EpisodeState.GRACE or episode.suspended_for:
            raise ValidationError(
                _("Release or waive the database write hold of %(domain)s before changing hosting ownership.")
                % {"domain": episode.domain}
            )
        episode.close("ownership_changed")
        episode.save()
        audit_episode(episode, "database_overage_closed", "The account changed owner", close_reason="ownership_changed")


def on_account_terminated(account_id: UUID) -> None:
    """After the termination commits: close the account's episode. Never raised into it; the sweep backstops."""
    try:
        close_for_terminated_account(account_id)
    except Exception:
        logger.exception("🔥 [DatabaseOverage] Could not close the episode of terminated account %s", account_id)


def close_for_terminated_account(account_id: UUID) -> bool:
    """The account was terminated, its node domain deleted with any hold on it: its open episode closes."""
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().filter(pk=account_id).first()
        episode = (
            DatabaseOverageEpisode.objects.select_for_update()
            .filter(account_id=account_id)
            .exclude(state=EpisodeState.CLOSED)
            .first()
        )
        if account is None or account.status != "terminated" or episode is None:
            return False
        episode.node_gone()
        episode.save()
        audit_episode(episode, "database_overage_closed", "The account was terminated", close_reason="node_deleted")
    logger.info("✅ [DatabaseOverage] Episode %s closed: account %s terminated", episode.pk, account_id)
    return True
