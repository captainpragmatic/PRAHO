"""Persistent migration evidence, fencing, and capacity reservations."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminAccount, VirtualminServer

_TERMINAL_STATUSES = ("completed", "failed", "rolled_back")
# Before the point of no return (ADR-0061 Phase 2): only A holds the writable copy, so a failure here
# compensates. From `activating` on, B does, and only keep-target actions exist.
PRE_COMMIT_STATUSES = (
    "lowering_ttl",
    "quiescing",
    "backing_up",
    "fetching",
    "pushing",
    "restoring",
    "verifying",
)
# The forward graph. Any live row may also park for review, and any write may keep its state (a
# lease release); a terminal row never moves.
TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"lowering_ttl", "quiescing", "fetching", "failed"}),
    "lowering_ttl": frozenset({"quiescing", "compensating", "rolled_back"}),
    "quiescing": frozenset({"backing_up", "compensating", "rolled_back"}),
    "backing_up": frozenset({"fetching", "compensating", "rolled_back"}),
    "fetching": frozenset({"pushing", "compensating", "rolled_back"}),
    "pushing": frozenset({"restoring", "compensating", "rolled_back"}),
    "restoring": frozenset({"verifying", "compensating", "rolled_back"}),
    "verifying": frozenset({"activating", "compensating"}),
    "activating": frozenset({"bridging", "repointing"}),
    "bridging": frozenset({"repointing"}),
    "repointing": frozenset({"completed"}),
    "compensating": frozenset({"rolled_back"}),
    "fencing": frozenset(),
    "needs_review": frozenset({"failed", "compensating", "activating", "bridging", "repointing"}),
}


def migration_transition_allowed(from_status: str, to_status: str) -> bool:
    """Whether the graph allows the move; the commit time is checked by `transition` itself."""
    if from_status == to_status:
        return True
    if from_status in _TERMINAL_STATUSES:
        return False
    return to_status == "needs_review" or to_status in TRANSITIONS.get(from_status, frozenset())


class VirtualminMigration(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", _("Pending")
        QUIESCING = "quiescing", _("Quiescing")
        BACKING_UP = "backing_up", _("Backing Up")
        FETCHING = "fetching", _("Fetching")
        PUSHING = "pushing", _("Pushing")
        RESTORING = "restoring", _("Restoring")
        VERIFYING = "verifying", _("Verifying")
        ACTIVATING = "activating", _("Activating")
        REPOINTING = "repointing", _("Repointing")
        LOWERING_TTL = "lowering_ttl", _("Lowering TTL")
        BRIDGING = "bridging", _("Bridging")
        COMPENSATING = "compensating", _("Compensating")
        FENCING = "fencing", _("Fencing")
        COMPLETED = "completed", _("Completed")
        FAILED = "failed", _("Failed")
        NEEDS_REVIEW = "needs_review", _("Needs Review")
        ROLLED_BACK = "rolled_back", _("Rolled Back")

    class Reason(models.TextChoices):
        MANUAL = "manual", _("Manual")
        DRAIN = "drain", _("Drain")
        RECOVERY = "recovery", _("Recovery")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey("provisioning.VirtualminAccount", on_delete=models.PROTECT, related_name="migrations")
    source_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="migrations_out"
    )
    target_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="migrations_in"
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    reason = models.CharField(max_length=10, choices=Reason.choices, default=Reason.MANUAL)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    error_detail = models.TextField(blank=True)

    lease_token = models.UUIDField(null=True, blank=True)
    worker_lease_expires_at = models.DateTimeField(null=True, blank=True)

    archive_name = models.CharField(max_length=255, editable=False)
    archive_sha256 = models.CharField(max_length=64, blank=True)
    source_disabled_at = models.DateTimeField(null=True, blank=True)
    restore_issued = models.BooleanField(default=False)
    routing_note_shown = models.BooleanField(default=False)
    pre_migration_snapshot = models.JSONField(default=dict, blank=True)

    class Contract(models.TextChoices):
        CUTOVER = "cutover", _("Cutover")  # The account has a live published name: DNS and bridge steps run
        LEGACY = "legacy", _("Legacy")
        RECOVERY = "recovery", _("Recovery from backup")

    # ADR-0061 Phase 2: the cutover's own evidence.
    contract = models.CharField(max_length=10, choices=Contract.choices, blank=True)
    drain = models.ForeignKey(
        "provisioning.NodeDrain", on_delete=models.SET_NULL, null=True, blank=True, related_name="migrations"
    )
    cutover_committed_at = models.DateTimeField(null=True, blank=True)  # The point of no return
    dns_converged_at = models.DateTimeField(null=True, blank=True)
    resume_after = models.DateTimeField(null=True, blank=True)  # A deferred step waits until then
    parked_phase = models.CharField(max_length=20, blank=True)
    barrier_state = models.JSONField(default=dict, blank=True)
    cancel_requested = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_virtualmin_migrations"
        verbose_name = _("Virtualmin Migration")
        verbose_name_plural = _("Virtualmin Migrations")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("account",),
                condition=~models.Q(status__in=_TERMINAL_STATUSES),
                name="unique_active_virtualmin_migration",
            )
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if self._state.adding:
            self.archive_name = f"migration_{self.pk}.tar.gz"
        super().save(*args, **kwargs)

    def acquire_lease(self, token: uuid.UUID, ttl: timedelta) -> bool:
        """Claim an unowned or expired lease in one conditional UPDATE."""
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        now = timezone.now()
        return bool(
            type(self)
            .objects.filter(pk=self.pk)
            .filter(models.Q(lease_token__isnull=True) | models.Q(worker_lease_expires_at__lte=now))
            .update(lease_token=token, worker_lease_expires_at=now + ttl, updated_at=now)
        )

    def renew_lease(self, token: uuid.UUID, ttl: timedelta) -> bool:
        """Only the current, unexpired owner may renew."""
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        now = timezone.now()
        return bool(
            type(self)
            .objects.filter(pk=self.pk, lease_token=token, worker_lease_expires_at__gt=now)
            .update(worker_lease_expires_at=now + ttl, updated_at=now)
        )

    def transition(self, token: uuid.UUID, from_status: str, to_status: str, **fields: object) -> bool:
        """Persist state and evidence only for the matching token and state, along the graph.

        An edge outside the graph is refused (False), and so is compensation once the commit is
        recorded: after the point of no return only keep-target actions exist.
        """
        if not migration_transition_allowed(from_status, to_status):
            return False
        rows = type(self).objects.filter(pk=self.pk, lease_token=token, status=from_status)
        if from_status == "pending" and to_status == "fetching":
            rows = rows.filter(contract="recovery")
        if to_status == "compensating":
            rows = rows.filter(cutover_committed_at__isnull=True)
        if from_status == "needs_review" and to_status in {"activating", "bridging", "repointing"}:
            rows = rows.filter(cutover_committed_at__isnull=False)
        fields.update(status=to_status, updated_at=timezone.now())  # fsm-bypass: a dict for the guarded UPDATE
        return bool(rows.update(**fields))  # fsm-bypass: this method is the guarded writer (graph + commit check)

    @classmethod
    def active_reservations(cls, server: VirtualminServer) -> int:
        """Reservation rows are authoritative; needs_review retains capacity.

        A committed row's domain is already counted on the target, so it no longer reserves it.
        """
        return (
            cls.objects.filter(target_server=server, cutover_committed_at__isnull=True)
            .exclude(status__in=_TERMINAL_STATUSES)
            .count()
        )


class MigrationBridge(ConcurrentTransitionMixin, models.Model):
    """The source node's reverse proxy to the target during a cutover (ADR-0061 P2.5).

    It starts `pending`, serves once `active`, keeps serving while the retained source content is
    removed (`removing_source`), and is `torn_down` only when the source no longer answers for the
    domain. A bridge that cannot be proven or removed is `failed` and blocks a new move.
    """

    class Status(models.TextChoices):
        PENDING = "pending", _("Pending")
        ACTIVE = "active", _("Active")
        REMOVING_SOURCE = "removing_source", _("Removing source")
        TORN_DOWN = "torn_down", _("Torn down")
        FAILED = "failed", _("Failed")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    migration = models.OneToOneField(VirtualminMigration, on_delete=models.PROTECT, related_name="bridge")
    source_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="bridges_out"
    )
    target_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="bridges_in"
    )
    domain = models.CharField(max_length=253)
    status = FSMField(max_length=20, choices=Status.choices, default=Status.PENDING, protected=True, db_index=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    torn_down_at = models.DateTimeField(null=True, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_migration_bridges"
        db_table_comment = "The source node's reverse proxy to the target during a cutover (ADR-0061 Phase 2)."
        verbose_name = _("Migration Bridge")
        verbose_name_plural = _("Migration Bridges")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(status__in=["pending", "active", "removing_source", "torn_down", "failed"]),
                name="migration_bridge_valid_status",
            )
        ]

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Any = None,
        from_queryset: Any = None,
    ) -> None:
        """Allow refresh_from_db with FSMField(protected=True), as the other FSM models do."""
        saved = {name: self.__dict__.pop(name) for name in ("status",) if name in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @transition(field=status, source=Status.PENDING, target=Status.ACTIVE)
    def activate(self) -> None:
        self.activated_at = timezone.now()

    @transition(field=status, source=Status.ACTIVE, target=Status.REMOVING_SOURCE)
    def start_removing_source(self) -> None:
        """The retained source content is being removed; the proxy keeps answering meanwhile."""

    @transition(field=status, source=Status.REMOVING_SOURCE, target=Status.TORN_DOWN)
    def tear_down(self) -> None:
        self.torn_down_at = timezone.now()

    @transition(
        field=status,
        source=(Status.PENDING, Status.ACTIVE, Status.REMOVING_SOURCE),
        target=Status.FAILED,
    )
    def fail(self) -> None:
        """A bridge whose state cannot be proven or removed; it blocks a new move until resolved."""

    @transition(field=status, source=Status.FAILED, target=Status.ACTIVE)
    def retry_cleanup(self) -> None:
        """Staff retries forward cleanup, retaining every previously verified checkpoint."""


class NodeDrain(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", _("Pending")
        RUNNING = "running", _("Running")
        PAUSED = "paused_needs_review", _("Paused: needs review")
        COMPLETED = "completed", _("Completed")
        CANCELLED = "cancelled", _("Cancelled")
        FAILED = "failed", _("Failed")

    class Reason(models.TextChoices):
        MANUAL = "manual", _("Manual")
        AUTO_HEALTH = "auto_health", _("Automatic health trigger")

    TERMINAL: ClassVar[tuple[str, ...]] = ("completed", "cancelled", "failed")
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.ForeignKey("provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="drains")
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.PENDING)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    reason = models.CharField(max_length=12, choices=Reason.choices, default=Reason.MANUAL)
    accounts_total = models.PositiveIntegerField(default=0)
    accounts_migrated = models.PositiveIntegerField(default=0)
    accounts_skipped = models.PositiveIntegerField(default=0)
    error_detail = models.TextField(blank=True)
    routing_confirmed = models.BooleanField(default=False)
    cancel_requested = models.BooleanField(default=False)
    task_token = models.UUIDField(default=uuid.uuid4, editable=False)
    current_migration = models.ForeignKey(VirtualminMigration, on_delete=models.PROTECT, null=True, blank=True)
    worker_started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("server",),
                condition=~models.Q(status__in=("completed", "cancelled", "failed")),
                name="unique_active_node_drain",
            )
        ]


def account_has_active_migration(account: VirtualminAccount) -> bool:
    """Needs-review migrations retain ownership until explicitly resolved."""
    return VirtualminMigration.objects.filter(account_id=account.pk).exclude(status__in=_TERMINAL_STATUSES).exists()


# Job statuses that hold the account-operation exclusion.
# "attention" is non-terminal by design: an uncertain mutation keeps ownership
# until an operator resolves it.
_ACTIVE_JOB_STATUSES = ("pending", "running", "attention")
ACTIVE_JOB_STATUSES = _ACTIVE_JOB_STATUSES

# Operations that take the account exclusion: backups and restores, and deletion
# (a delete mutates the very domain a backup or restore is reading or writing).
_EXCLUSIVE_JOB_OPERATIONS = ("backup_domain", "restore_domain", "delete_domain")


def account_has_active_operation(account: VirtualminAccount, *, ignore_job_id: uuid.UUID | None = None) -> bool:
    """Two-sided admission: migrations, backups, restores and deletes mutually exclude.

    ``ignore_job_id`` names the job asking: a retried job is itself the account's
    operation and must not refuse itself.
    """
    from .virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415  # Circular

    if account_has_active_migration(account):
        return True
    active = VirtualminProvisioningJob.objects.filter(
        account_id=account.pk,
        operation__in=_EXCLUSIVE_JOB_OPERATIONS,
        status__in=_ACTIVE_JOB_STATUSES,
    )
    if ignore_job_id is not None:
        active = active.exclude(pk=ignore_job_id)
    return active.exists()


def account_blocks_reconcile(account: VirtualminAccount) -> bool:
    """True when the state reconciler must leave the account alone.

    Narrower than ``account_has_active_operation`` (which admission uses): the reconciler writes
    the domain's enabled state, so it yields to what writes or deletes the domain - a migration,
    a restore or delete in any active state, any job currently running - and to a restore hold (a
    half-restored domain that only staff may release). A backup that is
    queued, or a chain job parked in attention, does not write the domain, so a suspend or an
    unsuspend after payment must not wait for an operator to resolve it.
    """
    from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob  # noqa: PLC0415  # Circular

    if account_has_active_migration(account):
        return True
    # A half-restored domain stays disabled until staff decide (re-enable it, or restore the safety backup).
    # Read from the database, not from the possibly stale instance the caller holds.
    if VirtualminAccount.objects.filter(pk=account.pk).exclude(restore_hold="").exists():
        return True
    return VirtualminProvisioningJob.objects.filter(
        models.Q(operation__in=("restore_domain", "delete_domain"), status__in=_ACTIVE_JOB_STATUSES)
        | models.Q(operation__in=_EXCLUSIVE_JOB_OPERATIONS, status="running"),
        account_id=account.pk,
    ).exists()


class SpoolRoot(models.Model):
    """Singleton lock row: spool-capacity admission serializes on it.

    select_for_update() on this row makes competing reservation admissions
    (backup fetch, migration fetch, restore download) mutually exclusive even
    when zero reservation rows exist — a sum-then-insert without it is write
    skew waiting to overrun the spool disk.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Unique marker makes concurrent first-time get_or_create race-safe.
    singleton = models.BooleanField(default=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SpoolReservation(models.Model):
    """Capacity reservation for one spool archive; lives until release/expiry."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    archive_name = models.CharField(max_length=120, unique=True)
    expected_bytes = models.BigIntegerField()
    owner = models.CharField(max_length=120)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
