"""Persistent migration evidence, fencing, and capacity reservations."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminAccount, VirtualminServer

_TERMINAL_STATUSES = ("completed", "failed", "rolled_back")


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
        COMPLETED = "completed", _("Completed")
        FAILED = "failed", _("Failed")
        NEEDS_REVIEW = "needs_review", _("Needs Review")
        ROLLED_BACK = "rolled_back", _("Rolled Back")

    class Reason(models.TextChoices):
        MANUAL = "manual", _("Manual")
        DRAIN = "drain", _("Drain")

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
        """Persist state and evidence only for the matching token and state."""
        fields.update(status=to_status, updated_at=timezone.now())
        return bool(type(self).objects.filter(pk=self.pk, lease_token=token, status=from_status).update(**fields))

    @classmethod
    def active_reservations(cls, server: VirtualminServer) -> int:
        """Reservation rows are authoritative; needs_review retains capacity."""
        return cls.objects.filter(target_server=server).exclude(status__in=_TERMINAL_STATUSES).count()


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


# Backup/restore job statuses that hold the account-operation exclusion.
# "attention" is non-terminal by design: an uncertain mutation keeps ownership
# until an operator resolves it.
_ACTIVE_JOB_STATUSES = ("pending", "running", "attention")


def account_has_active_operation(account: VirtualminAccount) -> bool:
    """Two-sided admission: migrations and backup/restore jobs mutually exclude."""
    from .virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415  # Circular

    if account_has_active_migration(account):
        return True
    return VirtualminProvisioningJob.objects.filter(
        account_id=account.pk,
        operation__in=("backup_domain", "restore_domain"),
        status__in=_ACTIVE_JOB_STATUSES,
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
