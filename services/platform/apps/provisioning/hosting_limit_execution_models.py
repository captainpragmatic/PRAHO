"""Native execution ownership is created only by the Account→Server→Service worker."""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.db import models


class HostingLimitExecution(models.Model):
    """A single native token and its capacity claim survive worker/queue failures.

    Assignment records intentionally contain no Account/Server foreign keys. This
    reverse-owned execution is published later, outside every money transaction.
    Expired execution leases never release reservations or account ownership.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(
        "provisioning.VirtualminProvisioningJob", on_delete=models.PROTECT, related_name="hosting_limit_execution"
    )
    service_revision = models.PositiveBigIntegerField()
    overlay_revision = models.PositiveBigIntegerField(default=0)
    owner_id = models.PositiveBigIntegerField()
    account_epoch = models.PositiveBigIntegerField()
    node_policy_revision = models.PositiveBigIntegerField()
    connection_identity = models.CharField(max_length=64)
    identity = models.JSONField(default=dict)
    request = models.JSONField(default=dict)
    receipt = models.JSONField(default=dict)
    phase = models.CharField(
        max_length=16,
        default="prepared",
        choices=[(value, value) for value in ("prepared", "issued", "attention", "completed", "fenced", "superseded")],
    )
    reserved_bytes = models.PositiveBigIntegerField(default=0)
    reservation_released_at = models.DateTimeField(null=True)
    issued_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_hosting_limit_execution"
        db_table_comment = "Token-fenced native quota attempts and unresolved capacity reservations."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(account_epoch__gte=1), name="hosting_execution_epoch_positive"),
        ]
