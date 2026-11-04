"""Bounded source summaries and durable ownership; never raw authentication events."""

from __future__ import annotations

import ipaddress
import uuid
from typing import ClassVar

from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

__all__ = [
    "CustomerIPObservation",
    "SecurityActionRequest",
    "SecurityActionTarget",
    "SecurityAlert",
    "SecurityAllowlist",
    "SecurityCoverageApproval",
    "SecurityDecision",
    "SecurityDecisionSuppression",
    "SecurityManagedDecision",
    "SecurityModel",
    "SecurityReplication",
    "SecurityReplicationScan",
    "SecuritySource",
    "SecuritySyncState",
]

IPV4_FAMILY = 4

_DIGEST = RegexValidator(r"^[0-9a-f]{64}$", _("A complete lowercase SHA-256 digest is required."))


class SecurityModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class SecuritySource(SecurityModel):
    kind = models.CharField(max_length=6, choices=[("node", _("Node")), ("portal", _("Portal"))])
    transport = models.CharField(max_length=5, choices=[("ssh", _("SSH")), ("local", _("Local"))])
    virtualmin_server = models.ForeignKey(
        "provisioning.VirtualminServer",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_sources",
    )
    hostname = models.CharField(max_length=253)
    port = models.PositiveIntegerField(default=9876)
    host_keys = models.TextField(blank=True)
    installation_id = models.UUIDField(unique=True, editable=False)
    configuration_digest = models.CharField(max_length=64, validators=[_DIGEST])
    sync_enabled = models.BooleanField(default=False)
    generation = models.PositiveBigIntegerField(default=1, editable=False)
    key_identity = models.CharField(max_length=64, blank=True, editable=False)
    virtualmin_identity = models.CharField(max_length=64, blank=True, editable=False)
    retired_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        db_table = "security_source"
        db_table_comment = "Explicitly enrolled physical LAPI installations; retired identities are never reused."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(kind__in=("node", "portal")), name="security_source_kind"),
            models.CheckConstraint(
                condition=models.Q(transport__in=("ssh", "local")), name="security_source_transport"
            ),
            models.CheckConstraint(condition=models.Q(generation__gte=1), name="security_source_generation"),
            models.UniqueConstraint(
                fields=("transport", "hostname", "port"),
                condition=models.Q(retired_at__isnull=True),
                name="security_live_endpoint",
            ),
            models.UniqueConstraint(
                fields=("virtualmin_server",),
                condition=models.Q(retired_at__isnull=True, virtualmin_server__isnull=False),
                name="security_live_node",
            ),
        ]


class SecurityDecision(SecurityModel):
    source = models.ForeignKey(SecuritySource, on_delete=models.PROTECT, related_name="decisions")
    remote_id = models.PositiveBigIntegerField()
    source_created_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    scenario = models.CharField(max_length=200)
    type = models.CharField(max_length=200)
    scope = models.CharField(max_length=5)
    value = models.CharField(max_length=64)
    address_family = models.PositiveSmallIntegerField()
    network_start = models.BinaryField(max_length=16)
    network_end = models.BinaryField(max_length=16)
    origin = models.CharField(max_length=200)
    simulated = models.BooleanField(default=False)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        db_table = "security_decision"
        db_table_comment = (
            "Complete current and ended decision summaries, immutable per physical installation and remote ID."
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("source", "remote_id"), name="security_decision_source_id"),
            models.CheckConstraint(condition=models.Q(address_family__in=(4, 6)), name="security_decision_family"),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=("source", "ended_at", "expires_at"), name="security_decision_active"),
            models.Index(
                fields=("address_family", "ended_at", "network_start", "network_end"), name="security_decision_bounds"
            ),
        ]


class SecurityAlert(SecurityModel):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.ForeignKey(SecuritySource, on_delete=models.PROTECT, related_name="alerts")
    remote_id = models.PositiveBigIntegerField()
    source_created_at = models.DateTimeField(db_index=True)
    scenario = models.CharField(max_length=200)
    event_count = models.PositiveBigIntegerField()
    scope = models.CharField(max_length=5, blank=True)
    value = models.CharField(max_length=64, blank=True)
    address_family = models.PositiveSmallIntegerField(null=True, blank=True)
    network_start = models.BinaryField(max_length=16, null=True, blank=True)
    network_end = models.BinaryField(max_length=16, null=True, blank=True)
    simulated = models.BooleanField(default=False)

    class Meta:
        db_table = "security_alert"
        db_table_comment = (
            "Immutable sanitized alert summaries retained for thirty days; no event samples or account identifiers."
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("source", "remote_id"), name="security_alert_source_id"),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        address_family__isnull=True,
                        network_start__isnull=True,
                        network_end__isnull=True,
                        scope="",
                        value="",
                    )
                    | models.Q(
                        address_family__isnull=False,
                        address_family__in=(4, 6),
                        network_start__isnull=False,
                        network_end__isnull=False,
                    )
                    & ~models.Q(scope="")
                    & ~models.Q(value="")
                ),
                name="security_alert_address",
            ),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=("address_family", "network_start", "network_end"), name="security_alert_bounds")
        ]


class SecuritySyncState(SecurityModel):
    source = models.OneToOneField(SecuritySource, on_delete=models.CASCADE, related_name="sync_state")
    claim_token = models.UUIDField(null=True, blank=True)
    claim_phase = models.CharField(max_length=8, blank=True)
    lease_until = models.DateTimeField(null=True, blank=True)
    claimed_generation = models.PositiveBigIntegerField(default=0)
    last_published_generation = models.PositiveBigIntegerField(default=0)
    input_identity = models.CharField(max_length=64, blank=True)
    next_run = models.DateTimeField(default=timezone.now, db_index=True)
    alert_cursor = models.PositiveBigIntegerField(default=0)
    has_more = models.BooleanField(default=False)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_decision_sync_at = models.DateTimeField(null=True, blank=True)
    last_alert_batch_at = models.DateTimeField(null=True, blank=True)
    last_alert_sync_at = models.DateTimeField(null=True, blank=True)
    health = models.JSONField(default=dict, blank=True)
    outcome = models.CharField(max_length=24, default="never")

    class Meta:
        db_table = "security_sync_state"
        db_table_comment = "Coalesced minute work, fenced queue and publication leases, independent decision freshness and alert catch-up."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(
                    models.Q(claim_token__isnull=True, lease_until__isnull=True, claim_phase="")
                    | models.Q(
                        claim_token__isnull=False, lease_until__isnull=False, claim_phase__in=("queued", "running")
                    )
                ),
                name="security_claim_complete",
            ),
        ]


class CustomerIPObservation(SecurityModel):
    """A completed login's address for every active customer membership, retained seven days."""

    user = models.ForeignKey("users.User", on_delete=models.CASCADE, related_name="security_ip_observations")
    customer = models.ForeignKey(
        "customers.Customer", on_delete=models.CASCADE, related_name="security_ip_observations"
    )
    address_family = models.PositiveSmallIntegerField()
    address = models.BinaryField(max_length=16)
    last_seen_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "security_customer_ip_observation"
        db_table_comment = (
            "Seven-day customer IP safety observations after complete authentication; no raw event samples."
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(address_family__in=(4, 6)), name="security_customer_ip_family"),
            models.UniqueConstraint(
                fields=("user", "customer", "address_family", "address"), name="security_customer_ip_identity"
            ),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=("address_family", "address", "last_seen_at"), name="security_customer_ip_recent"),
        ]

    @property
    def ip_address(self) -> str:
        packed = bytes(self.address)
        return str(ipaddress.ip_address(packed[-4:] if self.address_family == IPV4_FAMILY else packed))


from .action_models import (  # noqa: E402 -- Django discovers these after the shared base is defined.
    SecurityActionRequest,
    SecurityActionTarget,
    SecurityAllowlist,
    SecurityCoverageApproval,
    SecurityDecisionSuppression,
    SecurityManagedDecision,
    SecurityReplication,
    SecurityReplicationScan,
)
