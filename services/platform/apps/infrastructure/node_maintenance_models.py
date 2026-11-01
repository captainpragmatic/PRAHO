"""Persistent scheduling, execution, affected-service and delivery identities for node windows."""

from __future__ import annotations

import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import F, Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

LAST_WEEKDAY = 6
MAX_DEFER_MINUTES = 24 * 60


class MaintenanceRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class WindowStatus(models.TextChoices):
    SCHEDULED = "scheduled", _("Scheduled")
    RUNNING = "running", _("Running")
    OVERRAN = "overran", _("Taking longer than planned")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")
    CANCELLED = "cancelled", _("Cancelled")


class WindowKind(models.TextChoices):
    REBOOT = "reboot", _("Restart")
    PANEL_UPDATE = "panel_update", _("Hosting software updates")
    EMERGENCY = "emergency", _("Emergency maintenance")


class NodeMaintenancePolicy(MaintenanceRecord):
    node = models.OneToOneField(
        "provisioning.VirtualminServer", on_delete=models.CASCADE, related_name="maintenance_policy"
    )
    timezone = models.CharField(max_length=63)
    weekdays = models.JSONField(default=list)
    starts_time = models.TimeField()
    ends_time = models.TimeField()
    max_defer_minutes = models.PositiveSmallIntegerField(default=15)
    revision = models.PositiveIntegerField(default=1)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        db_table = "infrastructure_nodemaintenancepolicy"
        db_table_comment = "Operator-approved per-node permitted maintenance calendar and latest-start policy."

    def clean(self) -> None:
        super().clean()
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValidationError({"timezone": _("Choose a valid IANA timezone.")}) from exc
        days = self.weekdays
        if (
            not isinstance(days, list)
            or not days
            or any(type(day) is not int or not 0 <= day <= LAST_WEEKDAY for day in days)
            or len(set(days)) != len(days)
        ):
            raise ValidationError({"weekdays": _("Choose distinct weekdays from Monday through Sunday.")})
        if self.starts_time == self.ends_time:
            raise ValidationError({"ends_time": _("The permitted interval must have a nonzero duration.")})
        if not 0 <= self.max_defer_minutes <= MAX_DEFER_MINUTES:
            raise ValidationError({"max_defer_minutes": _("Latest-start deferral must be between 0 and 1440 minutes.")})


class NodeMaintenanceWindow(ConcurrentTransitionMixin, MaintenanceRecord):
    node = models.ForeignKey(
        "provisioning.VirtualminServer", null=True, on_delete=models.SET_NULL, related_name="maintenance_windows"
    )
    node_uuid = models.UUIDField(editable=False)
    policy = models.ForeignKey(NodeMaintenancePolicy, null=True, blank=True, on_delete=models.SET_NULL)
    policy_revision = models.PositiveIntegerField(default=0)
    policy_timezone = models.CharField(max_length=63)
    kind = models.CharField(max_length=20, choices=WindowKind.choices)
    execution_mode = models.CharField(max_length=24, default="manual")
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    start_by = models.DateTimeField()
    status = FSMField(max_length=20, choices=WindowStatus.choices, default=WindowStatus.SCHEDULED, protected=True)
    revision = models.PositiveIntegerField(default=1)
    origin = models.CharField(max_length=12, default="staff")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    expects_downtime = models.BooleanField(default=True)
    expected_downtime_minutes = models.PositiveIntegerField(null=True, blank=True)
    customer_note = models.TextField(max_length=1000)
    public_outcome = models.TextField(max_length=2000, blank=True)
    internal_outcome = models.JSONField(default=dict, blank=True)
    completion_source = models.CharField(max_length=16, blank=True)
    was_overrun = models.BooleanField(default=False)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    current_execution = models.ForeignKey(
        "infrastructure.NodeMaintenanceExecution", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        db_table = "infrastructure_nodemaintenancewindow"
        db_table_comment = (
            "Revision-fenced planned or emergency node work and truthful customer-visible outcome history."
        )
        constraints = (
            models.CheckConstraint(
                condition=Q(status__in=["scheduled", "running", "overran", "completed", "failed", "cancelled"]),
                name="maintenance_window_valid_state",
            ),
            models.UniqueConstraint(
                fields=["node"],
                condition=Q(status__in=["scheduled", "running", "overran"]),
                name="maintenance_one_applicable_node",
            ),
            models.CheckConstraint(condition=Q(ends_at__gt=F("starts_at")), name="maintenance_window_positive"),
            models.CheckConstraint(
                condition=Q(start_by__gte=F("starts_at"), start_by__lte=F("ends_at")),
                name="maintenance_latest_start_within",
            ),
            models.CheckConstraint(
                condition=~Q(status__in=["scheduled", "running", "overran"])
                | Q(node__isnull=False, node_id=F("node_uuid")),
                name="maintenance_active_window_bound",
            ),
        )
        indexes = (models.Index(fields=["status", "starts_at"], name="maintenance_window_due"),)

    @transition(field=status, source=WindowStatus.SCHEDULED, target=WindowStatus.RUNNING)
    def begin(self) -> None:
        self.started_at = timezone.now()

    @transition(field=status, source=WindowStatus.RUNNING, target=WindowStatus.OVERRAN)
    def mark_overrun(self) -> None:
        self.was_overrun = True

    @transition(field=status, source=(WindowStatus.RUNNING, WindowStatus.OVERRAN), target=WindowStatus.COMPLETED)
    def complete(self) -> None:
        self.finished_at = timezone.now()

    @transition(
        field=status,
        source=(WindowStatus.SCHEDULED, WindowStatus.RUNNING, WindowStatus.OVERRAN),
        target=WindowStatus.FAILED,
    )
    def fail(self) -> None:
        self.finished_at = timezone.now()

    @transition(field=status, source=WindowStatus.SCHEDULED, target=WindowStatus.CANCELLED)
    def cancel(self) -> None:
        self.finished_at = timezone.now()


class NodeMaintenanceExecution(ConcurrentTransitionMixin, MaintenanceRecord):
    node = models.ForeignKey(
        "provisioning.VirtualminServer", null=True, on_delete=models.SET_NULL, related_name="maintenance_executions"
    )
    node_uuid = models.UUIDField(null=True, blank=True, editable=False)
    window = models.ForeignKey(
        NodeMaintenanceWindow, null=True, blank=True, on_delete=models.PROTECT, related_name="executions"
    )
    window_revision = models.PositiveIntegerField(default=0)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    phase = FSMField(max_length=24, default="claimed", protected=True)
    action = models.CharField(max_length=32)
    adapter = models.CharField(max_length=24)
    deployment = models.ForeignKey("infrastructure.NodeDeployment", null=True, blank=True, on_delete=models.SET_NULL)
    deployment_correlation_id = models.UUIDField(null=True, blank=True)
    provider_resource_id = models.CharField(max_length=128, blank=True)
    existing_job_type = models.CharField(max_length=64, blank=True)
    existing_job_id = models.CharField(max_length=64, blank=True)
    q_task_id = models.CharField(max_length=64, blank=True)
    issued_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    lease_until = models.DateTimeField(null=True, blank=True)
    internal_result = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "infrastructure_nodemaintenanceexecution"
        db_table_comment = (
            "Exact native resource ownership; issued or uncertain commands retain their exclusion until verified."
        )
        constraints = (
            models.CheckConstraint(
                condition=Q(phase__in=["claimed", "issued", "awaiting_recovery", "uncertain", "verified", "failed"]),
                name="maintenance_exec_valid_phase",
            ),
            models.UniqueConstraint(
                fields=["node"],
                condition=Q(phase__in=["claimed", "issued", "awaiting_recovery", "uncertain"]),
                name="maintenance_one_node_execution",
            ),
            models.UniqueConstraint(
                fields=["deployment"],
                condition=Q(phase__in=["claimed", "issued", "awaiting_recovery", "uncertain"]),
                name="maintenance_one_deployment_exec",
            ),
            models.CheckConstraint(
                condition=~Q(phase__in=["claimed", "issued", "awaiting_recovery", "uncertain"])
                | Q(node__isnull=False, node_uuid__isnull=False, node_id=F("node_uuid"))
                | Q(
                    node__isnull=True,
                    node_uuid__isnull=True,
                    window__isnull=True,
                    deployment__isnull=False,
                    deployment_correlation_id__isnull=False,
                ),
                name="maintenance_active_exec_bound",
            ),
        )

    @transition(field=phase, source="claimed", target="issued")
    def issue(self) -> None:
        self.issued_at = timezone.now()

    @transition(field=phase, source="issued", target="awaiting_recovery")
    def await_recovery(self) -> None:
        """Command acceptance does not prove the affected services recovered."""

    @transition(field=phase, source=("issued", "awaiting_recovery"), target="uncertain")
    def mark_uncertain(self) -> None:
        """Retain node ownership until an operator reconciles the issued command."""

    @transition(field=phase, source=("claimed", "issued", "awaiting_recovery", "uncertain"), target="verified")
    def verify(self) -> None:
        self.finished_at = timezone.now()

    @transition(field=phase, source=("claimed", "issued", "awaiting_recovery", "uncertain"), target="failed")
    def fail(self) -> None:
        self.finished_at = timezone.now()


class NodeMaintenanceAudience(MaintenanceRecord):
    window = models.ForeignKey(NodeMaintenanceWindow, on_delete=models.CASCADE, related_name="audience")
    service = models.ForeignKey("provisioning.Service", null=True, on_delete=models.SET_NULL)
    service_id_snapshot = models.PositiveBigIntegerField()
    provenance = models.CharField(max_length=16)
    captured_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "infrastructure_nodemaintenanceaudience"
        db_table_comment = (
            "Independent planned and executed service identities, retained regardless of email eligibility."
        )
        constraints = (
            models.UniqueConstraint(fields=["window", "service_id_snapshot"], name="maintenance_audience_identity"),
        )


class NodeMaintenanceDelivery(ConcurrentTransitionMixin, MaintenanceRecord):
    window = models.ForeignKey(NodeMaintenanceWindow, on_delete=models.CASCADE, related_name="deliveries")
    revision = models.PositiveIntegerField()
    customer = models.ForeignKey("customers.Customer", null=True, on_delete=models.SET_NULL)
    customer_id_snapshot = models.PositiveBigIntegerField()
    kind = models.CharField(max_length=24)
    channel = models.CharField(max_length=12, default="email")
    selected_service_ids = models.JSONField(default=list)
    public_snapshot = models.JSONField(default=dict)
    due_at = models.DateTimeField()
    phase = FSMField(max_length=20, default="pending", protected=True)
    refusal_reason = models.CharField(max_length=255, blank=True)
    first_dispatch_claimed_at = models.DateTimeField(null=True, blank=True)
    email_log = models.OneToOneField("notifications.EmailLog", null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        db_table = "infrastructure_nodemaintenancedelivery"
        db_table_comment = (
            "Deduplicated maintenance notice intentions linked to the existing encrypted email transport."
        )
        constraints = (
            models.CheckConstraint(
                condition=Q(phase__in=["pending", "linked", "dispatching", "refused", "superseded"]),
                name="maintenance_delivery_valid_phase",
            ),
            models.UniqueConstraint(
                fields=["window", "revision", "customer_id_snapshot", "kind", "channel"],
                name="maintenance_delivery_identity",
            ),
        )
        indexes = (models.Index(fields=["phase", "due_at"], name="maintenance_delivery_due"),)

    @transition(field=phase, source="pending", target="linked")
    def link(self) -> None:
        """One normal EmailLog owns all transport retries for this intent."""

    @transition(field=phase, source=("pending", "linked", "dispatching"), target="refused")
    def refuse(self, reason: str) -> None:
        self.refusal_reason = reason

    @transition(field=phase, source=("pending", "linked"), target="superseded")
    def supersede(self) -> None:
        """Definitely unsent content from a previous window revision is obsolete."""

    @transition(field=phase, source=("linked", "dispatching"), target="dispatching")
    def claim_dispatch(self) -> None:
        if self.first_dispatch_claimed_at is None:
            self.first_dispatch_claimed_at = timezone.now()
