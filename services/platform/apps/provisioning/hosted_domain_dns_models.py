"""Cached customer DNS observations, active incidents and fenced background work."""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.db import models
from django.utils import timezone


class HostedDomainDnsStatus(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.OneToOneField(
        "provisioning.VirtualminAccount", on_delete=models.CASCADE, related_name="dns_status"
    )
    dns_path = models.CharField(max_length=80, default="unknown")
    results = models.JSONField(default=dict, blank=True)
    component_history = models.JSONField(default=dict, blank=True)
    healthy = models.BooleanField(null=True, blank=True)
    expected_generation = models.CharField(max_length=64, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    last_healthy_at = models.DateTimeField(null=True, blank=True)
    first_failed_at = models.DateTimeField(null=True, blank=True)
    incident_id = models.UUIDField(null=True, blank=True, unique=True)
    incident_components = models.JSONField(default=list, blank=True)
    notification_pending = models.BooleanField(default=False)
    notified_at = models.DateTimeField(null=True, blank=True)
    alert_email_log = models.ForeignKey("notifications.EmailLog", on_delete=models.SET_NULL, null=True, blank=True)
    next_check_at = models.DateTimeField(default=timezone.now, db_index=True)
    requested_at = models.DateTimeField(null=True, blank=True)
    lease_token = models.UUIDField(null=True, blank=True)
    lease_until = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_hosted_domain_dns_status"
        db_table_comment = (
            "Lease-fenced customer DNS observations and incident notification evidence for a hosting account"
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(
                    models.Q(lease_token__isnull=True, lease_until__isnull=True)
                    | models.Q(lease_token__isnull=False, lease_until__isnull=False)
                ),
                name="hosted_dns_complete_lease",
            ),
        ]

    def __str__(self) -> str:
        return f"DNS status for {self.account_id}"
