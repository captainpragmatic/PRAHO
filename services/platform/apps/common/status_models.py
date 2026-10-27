"""Bounded operational evidence, separate from business audit records."""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.db import models
from django.db.models import Q
from django.utils import timezone

INTERNAL_CHECK_KEYS = ("status_refresh", "hosting_backup_scheduler", "platform_backup")


class SystemCheckState(models.Model):
    """Latest observation for an installation-wide check or a registered node."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    check_key = models.CharField(max_length=64)
    node = models.ForeignKey("provisioning.VirtualminServer", null=True, blank=True, on_delete=models.CASCADE)
    level = models.CharField(max_length=16, default="unknown")
    reason = models.CharField(max_length=80, blank=True)
    details = models.JSONField(default=dict)
    configuration_generation = models.PositiveBigIntegerField(default=1)
    verified_generation = models.PositiveBigIntegerField(null=True)
    input_identity = models.CharField(max_length=64, blank=True)
    sequence = models.PositiveBigIntegerField(default=0)
    claim_token = models.UUIDField(null=True)
    lease_until = models.DateTimeField(null=True)
    last_attempt_at = models.DateTimeField(null=True)
    observed_at = models.DateTimeField(null=True)
    last_success_at = models.DateTimeField(null=True)
    changed_at = models.DateTimeField(default=timezone.now)
    last_scheduled_slot = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "common_system_check_state"
        db_table_comment = "Latest configuration-bound health evidence and execution claim per check or node."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("check_key",), condition=Q(node__isnull=True), name="status_global_key"),
            models.UniqueConstraint(
                fields=("check_key", "node"), condition=Q(node__isnull=False), name="status_node_key"
            ),
        ]


class NodeResourceHourlySummary(models.Model):
    """At most one small aggregate per node per UTC hour; individual samples are never stored."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    node = models.ForeignKey("provisioning.VirtualminServer", on_delete=models.CASCADE)
    hour = models.DateTimeField(db_index=True)
    cpu_sum = models.FloatField(default=0)
    cpu_count = models.PositiveIntegerField(default=0)
    cpu_peak = models.FloatField(null=True)
    memory_sum = models.FloatField(default=0)
    memory_count = models.PositiveIntegerField(default=0)
    memory_peak = models.FloatField(null=True)
    disk_sum = models.FloatField(default=0)
    disk_count = models.PositiveIntegerField(default=0)
    disk_peak = models.FloatField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "common_node_resource_hourly"
        db_table_comment = "Hourly node resource sums, counts and peaks retained for thirty days; no raw samples."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("node", "hour"), name="status_node_hour")
        ]

    @property
    def cpu_average(self) -> float | None:
        return self.cpu_sum / self.cpu_count if self.cpu_count else None

    @property
    def memory_average(self) -> float | None:
        return self.memory_sum / self.memory_count if self.memory_count else None

    @property
    def disk_average(self) -> float | None:
        return self.disk_sum / self.disk_count if self.disk_count else None
