"""A database over-allowance episode: 14 days of notice, then a write hold on the account's databases.

Once a hold may exist on the node (from `holding` on), the episode reaches `closed` only through `releasing`,
or through `node_gone` when the account's node domain was deleted. Transitions only record a decision; the
node I/O runs outside them, in the service.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, ClassVar
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransition, ConcurrentTransitionMixin, FSMField, transition


class EpisodeState(models.TextChoices):
    GRACE = "grace", _("Grace period")
    HOLDING = "holding", _("Applying the hold")
    HELD = "held", _("Writes held")
    RELEASING = "releasing", _("Releasing the hold")
    CLOSED = "closed", _("Closed")


OPEN_STATES = (EpisodeState.GRACE, EpisodeState.HOLDING, EpisodeState.HELD, EpisodeState.RELEASING)

# Why a hold is released, and so where the release ends: back in grace, or closed with that reason.
RELEASE_TO_GRACE = frozenset({"extend", "migration", "hold_refused", "hold_withdrawn"})
RELEASE_TO_CLOSED = frozenset({"under_allowance", "waived", "ownership_changed", "flag_rollback"})
# Reasons an episode in grace closes for; nothing was held, so nothing is released.
CLOSE_FROM_GRACE = RELEASE_TO_CLOSED


class SuspendedFor(models.TextChoices):
    NONE = "", _("Not suspended")
    MIGRATION = "migration", _("Account migration")


# Written only by a transition and save(): a queryset write would skip the invariant or the stale-copy fence.
_GUARDED_FIELDS = frozenset({"state", "revision"})


class DatabaseOverageEpisodeQuerySet(models.QuerySet["DatabaseOverageEpisode"]):
    """The state changes only through a transition; a queryset write would skip the invariant."""

    def update(self, **kwargs: Any) -> int:
        if set(kwargs) & _GUARDED_FIELDS:
            raise ValidationError(_("An overage episode's state changes only through its transitions."))
        # Any write outdates the copies already read, so it moves the revision on too.
        return super().update(**kwargs, revision=models.F("revision") + 1)

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        # One revision per row can't be checked in a bulk write: episodes are saved one by one.
        raise ValidationError(_("An overage episode's state changes only through its transitions."))

    def bulk_create(  # noqa: PLR0913 -- QuerySet.bulk_create's own signature, so no option goes unseen
        self,
        objs: Any,
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Any = None,
        unique_fields: Any = None,
    ) -> list[DatabaseOverageEpisode]:
        objs = list(objs)
        if update_conflicts or any(obj.state != EpisodeState.GRACE for obj in objs):
            raise ValidationError(_("An overage episode's state changes only through its transitions."))
        return super().bulk_create(
            objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts, unique_fields=unique_fields
        )


def _account_terminated(episode: models.Model) -> bool:
    # A deleted account row is no proof the node domain was deleted: that episode stays open for staff.
    account = getattr(episode, "account", None)
    return account is not None and account.status == "terminated"


def _releases_to_grace(episode: models.Model) -> bool:
    return getattr(episode, "release_purpose", "") in RELEASE_TO_GRACE


def _releases_to_closed(episode: models.Model) -> bool:
    return getattr(episode, "release_purpose", "") in RELEASE_TO_CLOSED


class DatabaseOverageEpisode(ConcurrentTransitionMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        "provisioning.VirtualminAccount", null=True, on_delete=models.SET_NULL, related_name="database_overages"
    )
    service = models.ForeignKey(
        "provisioning.Service", null=True, on_delete=models.SET_NULL, related_name="database_overages"
    )
    service_id_snapshot = models.PositiveBigIntegerField()
    customer_id_snapshot = models.PositiveBigIntegerField()
    owner_scope = models.UUIDField()
    # The native identity a hold is applied to; a migration moves it to the target's.
    server_id = models.UUIDField()
    domain_id = models.CharField(max_length=30)
    domain = models.CharField(max_length=253)
    installation = models.UUIDField(null=True)

    state = FSMField(default=EpisodeState.GRACE, max_length=12, choices=EpisodeState.choices, protected=True)

    opened_at = models.DateTimeField()
    opened_reading = models.ForeignKey(
        "provisioning.UsageReading", null=True, on_delete=models.SET_NULL, related_name="+"
    )
    deadline_at = models.DateTimeField(db_index=True)
    paused_at = models.DateTimeField(null=True)
    paused_total = models.DurationField(default=timedelta)
    below_since = models.DateTimeField(null=True)
    last_fresh_at = models.DateTimeField(null=True)
    last_over_at = models.DateTimeField(null=True)  # the newest counted reading that was over the allowance
    deferred_since = models.DateTimeField(null=True)

    suspended_for = models.CharField(max_length=12, choices=SuspendedFor.choices, default=SuspendedFor.NONE, blank=True)
    suspended_migration_id = models.UUIDField(null=True)
    # Held when the migration started: released before the move, held again on the target at activation.
    hold_follows_migration = models.BooleanField(default=False)

    # Every save moves it on, and a save from an older copy matches no row: a stale worker can't win.
    revision = models.PositiveBigIntegerField(default=0)
    hold_token = models.UUIDField(null=True)
    hold_generation = models.PositiveBigIntegerField(default=0)
    held_digest = models.CharField(max_length=128, blank=True)
    sessions_remaining = models.JSONField(default=list)
    needs_reconcile = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True)  # the node last confirmed the hold as journalled
    # The node refused a hold: no further hold until staff extend or waive. Kept apart from last_error,
    # which any later diagnostic can overwrite.
    hold_refused_at = models.DateTimeField(null=True)
    release_purpose = models.CharField(max_length=24, blank=True)

    close_reason = models.CharField(max_length=24, blank=True)
    closed_at = models.DateTimeField(null=True)
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DatabaseOverageEpisodeQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_database_overage_episode"
        db_table_comment = "A database over-allowance: grace, then a journalled write hold, then release or close."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("account",),
                condition=~models.Q(state=EpisodeState.CLOSED),
                name="database_overage_one_open_per_account",
            ),
            models.CheckConstraint(
                condition=models.Q(state__in=EpisodeState.values), name="database_overage_state_valid"
            ),
            models.CheckConstraint(
                condition=models.Q(suspended_for=SuspendedFor.NONE, suspended_migration_id__isnull=True)
                | models.Q(suspended_for=SuspendedFor.MIGRATION, suspended_migration_id__isnull=False),
                name="database_overage_suspension_names_migration",
            ),
            models.CheckConstraint(
                condition=(models.Q(state=EpisodeState.CLOSED) & ~models.Q(close_reason=""))
                | (~models.Q(state=EpisodeState.CLOSED) & models.Q(close_reason="")),
                name="database_overage_close_reason_when_closed",
            ),
        ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Read only when loaded: touching a deferred field here would load it, recursively.
        self._loaded_revision: int | None = self.__dict__.get("revision")

    def save(self, *args: Any, **kwargs: Any) -> None:
        if args:
            raise TypeError("pass save() options by keyword")
        if self._state.adding:
            if self.state != EpisodeState.GRACE:
                raise ValidationError(_("An overage episode's state changes only through its transitions."))
        else:
            if self._loaded_revision is None:
                # Read without its revision (defer or only): nothing to fence a stale write against.
                raise ConcurrentTransition("This overage episode was read without its revision; read it in full.")
            self.revision = self._loaded_revision + 1
            if kwargs.get("update_fields") is not None:
                kwargs["update_fields"] = {*kwargs["update_fields"], "revision"}
        super().save(*args, **kwargs)
        self._loaded_revision = self.revision

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        # A protected FSM field refuses the reload's assignment unless the cached value is gone first.
        saved = self.__dict__.pop("state", None) if fields is None or "state" in fields else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved is not None:
                self.__dict__["state"] = saved
            raise
        if fields is None:
            # Only a full reload makes the whole copy current; a partial one keeps the copy's old baseline.
            self._loaded_revision = self.revision

    def _do_update(self, base_qs: Any, using: Any, pk_val: Any, *args: Any, **kwargs: Any) -> bool:
        updated = super()._do_update(base_qs.filter(revision=self._loaded_revision), using, pk_val, *args, **kwargs)
        if not updated and base_qs.filter(pk=pk_val).using(using).exists():
            # The row exists but moved on since this copy was read: never fall back to an insert.
            raise ConcurrentTransition("This overage episode changed since it was read.")
        return bool(updated)

    @transition(field=state, source=EpisodeState.GRACE, target=EpisodeState.HOLDING)
    def start_hold(self, *, token: UUID, generation: int) -> None:
        """The decision to hold, persisted before the node is asked; a generation only moves forward."""
        self._take_generation(token, generation)

    @transition(field=state, source=EpisodeState.HELD, target=EpisodeState.HOLDING)
    def start_rehold(self, *, token: UUID, generation: int) -> None:
        """Grants drifted under the hold: hold again with a newer generation, over the node's original images."""
        self._take_generation(token, generation)

    def _take_generation(self, token: UUID, generation: int) -> None:
        newest = self.hold_generation
        if self.account_id is not None:
            # The node journal outlives an episode: the generation moves on across the account's episodes.
            others = type(self)._base_manager.filter(account_id=self.account_id).exclude(pk=self.pk)
            newest = max(newest, others.aggregate(newest=models.Max("hold_generation"))["newest"] or 0)
        if generation <= newest:
            raise ValueError("a hold generation must be newer than the account's last one")
        self.hold_token, self.hold_generation, self.held_digest = token, generation, ""

    @transition(field=state, source=EpisodeState.HOLDING, target=EpisodeState.HELD)
    def confirm_held(self, *, digest: str) -> None:
        """Every in-scope row revoked, read back, and every session open at the revoke gone: no drift left."""
        self.held_digest, self.sessions_remaining, self.needs_reconcile = digest, [], False

    @transition(field=state, source=[EpisodeState.HOLDING, EpisodeState.HELD], target=EpisodeState.RELEASING)
    def start_release(self, purpose: str) -> None:
        if purpose not in RELEASE_TO_GRACE | RELEASE_TO_CLOSED:
            raise ValueError(f"unknown release purpose: {purpose}")
        self.release_purpose = purpose

    @transition(field=state, source=EpisodeState.RELEASING, target=EpisodeState.GRACE, conditions=[_releases_to_grace])
    def confirm_released_to_grace(self) -> None:
        """Released for a write window, a migration, or a refused hold: the episode goes on."""
        self.release_purpose, self.held_digest, self.sessions_remaining = "", "", []

    @transition(
        field=state, source=EpisodeState.RELEASING, target=EpisodeState.CLOSED, conditions=[_releases_to_closed]
    )
    def confirm_released_to_closed(self) -> None:
        self.close_reason, self.release_purpose, self.closed_at = self.release_purpose, "", timezone.now()

    @transition(field=state, source=EpisodeState.GRACE, target=EpisodeState.CLOSED)
    def close(self, reason: str) -> None:
        """Nothing was held, so nothing needs releasing."""
        if reason not in CLOSE_FROM_GRACE:
            raise ValueError(f"an episode in grace can't close for: {reason}")
        self.close_reason, self.closed_at = reason, timezone.now()

    @transition(field=state, source=list(OPEN_STATES), target=EpisodeState.CLOSED, conditions=[_account_terminated])
    def node_gone(self) -> None:
        """The node domain was deleted with the account, and any hold on it with it."""
        self.close_reason, self.release_purpose, self.closed_at = "node_deleted", "", timezone.now()


class NoticeKind(models.TextChoices):
    DAY0 = "day0", _("Over the allowance: writes held after the deadline")
    DAY14 = "day14", _("Writes held")


class DatabaseOverageNotice(models.Model):
    """One notice of an episode, by email and on its ticket; the bindings its final send check compares."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    episode = models.ForeignKey(DatabaseOverageEpisode, on_delete=models.CASCADE, related_name="notices")
    kind = models.CharField(max_length=8, choices=NoticeKind.choices)
    recipient_hash = models.CharField(max_length=64)
    held_digest = models.CharField(max_length=128, blank=True)
    # A digest can repeat across holds; the generation names the one hold a day-14 notice reports.
    hold_generation = models.PositiveBigIntegerField(default=0)
    email_log = models.OneToOneField(
        "notifications.EmailLog", null=True, on_delete=models.SET_NULL, related_name="database_overage_notice"
    )
    ticket = models.ForeignKey("tickets.Ticket", null=True, on_delete=models.SET_NULL, related_name="+")
    accepted_at = models.DateTimeField(null=True)
    # What was sent, kept for the audit trail: the email log itself is purged before the claims period ends.
    content = models.JSONField(default=dict)
    refusal_reason = models.CharField(max_length=40, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_database_overage_notice"
        db_table_comment = "Day 0 and day 14 notices of a database overage episode, one of each per episode."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("episode", "kind"), name="database_overage_one_notice_per_kind"),
            models.CheckConstraint(
                condition=models.Q(kind__in=NoticeKind.values), name="database_overage_notice_kind_valid"
            ),
        ]
