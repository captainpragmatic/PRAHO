"""Bounded technical observations; no business audit event is emitted per poll."""

import uuid
from typing import ClassVar

from django.db import models
from django.utils import timezone


class UsageModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class NodeUsageSyncState(UsageModel):
    server = models.OneToOneField("provisioning.VirtualminServer", on_delete=models.CASCADE, related_name="usage_sync")
    token = models.UUIDField(null=True)
    lease_until = models.DateTimeField(null=True)
    next_run = models.DateTimeField(default=timezone.now, db_index=True)
    last_attempt_at = models.DateTimeField(null=True)
    last_success_at = models.DateTimeField(null=True)
    outcome = models.CharField(max_length=40, default="unknown")
    input_identity = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "provisioning_node_usage_sync"
        db_table_comment = "Hourly usage poll claim and last transport outcome; contains no remote payload."


class AccountUsageState(UsageModel):
    account = models.OneToOneField(
        "provisioning.VirtualminAccount", on_delete=models.CASCADE, related_name="usage_state"
    )
    owner_scope = models.UUIDField(default=uuid.uuid4)
    service_id_snapshot = models.PositiveBigIntegerField()
    customer_id_snapshot = models.PositiveBigIntegerField()
    server_id_snapshot = models.UUIDField()
    owner_started_at = models.DateTimeField(default=timezone.now)
    owner_start_known = models.BooleanField(default=False)
    gauge_not_before = models.DateTimeField(default=timezone.now)
    chain_epoch_snapshot = models.PositiveBigIntegerField(default=0)
    domain_id = models.CharField(max_length=30, blank=True)
    installation = models.UUIDField(null=True)
    disk_reading = models.ForeignKey("UsageReading", null=True, on_delete=models.SET_NULL, related_name="+")
    bandwidth_reading = models.ForeignKey("UsageReading", null=True, on_delete=models.SET_NULL, related_name="+")
    bandwidth_incomplete_since = models.DateTimeField(null=True)

    class Meta:
        db_table = "provisioning_account_usage_state"
        db_table_comment = "Current ownership scope, mutation watermark and independent last-good usage pointers."


class UsageInterval(UsageModel):
    account = models.ForeignKey(
        "provisioning.VirtualminAccount", on_delete=models.CASCADE, related_name="usage_intervals"
    )
    owner_scope = models.UUIDField(db_index=True)
    server = models.ForeignKey("provisioning.VirtualminServer", null=True, on_delete=models.SET_NULL)
    server_id_snapshot = models.UUIDField(null=True)
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True)
    domain_id = models.CharField(max_length=30, blank=True)
    installation = models.UUIDField(null=True)
    # Finalized month intersections survive the source node's disappearance.
    totals = models.JSONField(default=dict)

    class Meta:
        db_table = "provisioning_usage_interval"
        db_table_comment = (
            "Canonical node and owner time intervals with retained finalized monthly response-byte totals."
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("account",), condition=models.Q(ended_at__isnull=True), name="usage_open_interval"
            ),
        ]


class UsageReading(UsageModel):
    account = models.ForeignKey(
        "provisioning.VirtualminAccount", on_delete=models.CASCADE, related_name="usage_readings"
    )
    owner_scope = models.UUIDField(db_index=True)
    sync_token = models.UUIDField()
    server_id_snapshot = models.UUIDField()
    chain_epoch = models.PositiveBigIntegerField()
    taken_at = models.DateTimeField(db_index=True)
    scan_started_at = models.DateTimeField(null=True)
    disk_files_bytes = models.PositiveBigIntegerField(null=True)
    disk_db_bytes = models.PositiveBigIntegerField(null=True)
    disk_total_bytes = models.PositiveBigIntegerField(null=True)
    databases = models.PositiveIntegerField(null=True)
    mailboxes = models.PositiveIntegerField(null=True)
    bandwidth_bytes = models.PositiveBigIntegerField(null=True)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    period_timezone = models.CharField(max_length=80)
    bandwidth_complete = models.BooleanField(default=False)

    class Meta:
        db_table = "provisioning_usage_reading"
        db_table_comment = "Immutable measured usage observations, owner scoped and retained for ninety days."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("account", "sync_token"), name="usage_account_attempt"),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=("account", "taken_at"), name="usage_account_time")
        ]
