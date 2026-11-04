"""Durable issuance and provenance; a missing remote receipt never clears uncertainty."""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone

from .models import SecurityModel


class SecurityActionRequest(SecurityModel):
    kind = models.CharField(max_length=16)
    idempotency_key = models.UUIDField(unique=True)
    payload = models.JSONField()
    payload_digest = models.CharField(max_length=64)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="security_actions"
    )
    reason = models.CharField(max_length=2000)
    decision = models.ForeignKey(
        "security.SecurityDecision", null=True, on_delete=models.SET_NULL, related_name="actions"
    )
    status = models.CharField(max_length=16, default="pending")

    class Meta:
        db_table = "security_action_request"
        db_table_comment = "Audited canonical action issuance persisted before any host mutation."


class SecurityActionTarget(SecurityModel):
    action = models.ForeignKey(SecurityActionRequest, on_delete=models.PROTECT, related_name="targets")
    source = models.ForeignKey("security.SecuritySource", on_delete=models.PROTECT, related_name="action_targets")
    operation = models.CharField(max_length=24)
    request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    provenance_id = models.UUIDField(null=True)
    revision = models.PositiveBigIntegerField(default=1)
    expires_at = models.DateTimeField(null=True)
    payload = models.JSONField()
    payload_digest = models.CharField(max_length=64)
    source_generation = models.PositiveBigIntegerField()
    connection_identity = models.CharField(max_length=64)
    state = models.CharField(max_length=16, default="issued", db_index=True)
    claim_token = models.UUIDField(null=True)
    claim_phase = models.CharField(max_length=8, blank=True)
    lease_until = models.DateTimeField(null=True)
    dispatched_at = models.DateTimeField(null=True)
    reconciled_at = models.DateTimeField(null=True)
    next_run = models.DateTimeField(default=timezone.now, db_index=True)
    evidence = models.JSONField(default=dict)

    class Meta:
        db_table = "security_action_target"
        db_table_comment = "Fenced target request identities, immutable expiry and sanitized reconciliation evidence."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("action", "source", "provenance_id"), name="security_target_provenance"),
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="security_target_revision"),
            models.CheckConstraint(
                condition=models.Q(claim_token__isnull=True, lease_until__isnull=True)
                | models.Q(claim_token__isnull=False, lease_until__isnull=False),
                name="security_target_lease",
            ),
        ]


class SecurityAllowlist(SecurityModel):
    source = models.OneToOneField("security.SecuritySource", on_delete=models.PROTECT, related_name="staff_allowlist")
    cidrs = models.JSONField(default=list)
    revision = models.PositiveBigIntegerField(default=0)

    class Meta:
        db_table = "security_allowlist"
        db_table_comment = "Complete desired staff LAPI allowlist; immutable host inventory protections are separate."


class SecurityDecisionSuppression(SecurityModel):
    decision = models.OneToOneField(
        "security.SecurityDecision", null=True, on_delete=models.SET_NULL, related_name="suppression"
    )
    source = models.ForeignKey("security.SecuritySource", on_delete=models.PROTECT, related_name="suppressions")
    remote_id = models.PositiveBigIntegerField()
    action = models.ForeignKey(SecurityActionRequest, on_delete=models.PROTECT, related_name="suppressions")

    class Meta:
        db_table = "security_decision_suppression"
        db_table_comment = "Permanent suppression of a revoked original remote ID and all later PRAHO copies."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("source", "remote_id"), name="security_suppression_remote_id"),
        ]


class SecurityReplication(SecurityModel):
    decision = models.ForeignKey(
        "security.SecurityDecision", null=True, on_delete=models.SET_NULL, related_name="replications"
    )
    origin_installation_id = models.UUIDField()
    origin_remote_id = models.PositiveBigIntegerField()
    target_source = models.ForeignKey("security.SecuritySource", on_delete=models.PROTECT, related_name="replications")
    provenance_id = models.UUIDField(default=uuid.uuid4, unique=True)
    revision = models.PositiveBigIntegerField(default=1)
    expires_at = models.DateTimeField()
    create_target = models.OneToOneField(
        SecurityActionTarget, null=True, on_delete=models.PROTECT, related_name="created_replication"
    )
    revoke_target = models.OneToOneField(
        SecurityActionTarget, null=True, on_delete=models.PROTECT, related_name="revoked_replication"
    )

    class Meta:
        db_table = "security_replication"
        db_table_comment = "One nonrenewable admission per original decision and target physical installation."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("decision", "target_source"), name="security_replication_admission"),
            models.UniqueConstraint(
                fields=("origin_installation_id", "origin_remote_id", "target_source"),
                name="security_replication_origin",
            ),
        ]


class SecurityReplicationScan(SecurityModel):
    decision = models.OneToOneField(
        "security.SecurityDecision", on_delete=models.CASCADE, related_name="replication_scan"
    )
    checked_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "security_replication_scan"
        db_table_comment = (
            "Fair bounded replication scans rotate past already admitted or temporarily unqualified decisions."
        )


class SecurityCoverageApproval(SecurityModel):
    source = models.ForeignKey("security.SecuritySource", on_delete=models.PROTECT, related_name="coverage_approvals")
    generation = models.PositiveBigIntegerField()
    configuration_digest = models.CharField(max_length=64)
    connection_identity = models.CharField(max_length=64)
    review = models.ForeignKey(
        "provisioning.NodeSecurityReview", null=True, on_delete=models.PROTECT, related_name="crowdsec_approvals"
    )
    evidence_digest = models.CharField(max_length=64)
    native_evidence = models.JSONField()
    scenarios = models.JSONField()
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="security_coverage_approvals"
    )
    reason = models.CharField(max_length=2000)
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "security_coverage_approval"
        db_table_comment = (
            "Explicit reviewed native detection provenance bound to current configuration and connection identity."
        )


class SecurityManagedDecision(SecurityModel):
    source = models.ForeignKey("security.SecuritySource", on_delete=models.PROTECT, related_name="managed_decisions")
    remote_id = models.PositiveBigIntegerField()
    provenance_id = models.UUIDField()
    issuing_target = models.ForeignKey(SecurityActionTarget, on_delete=models.PROTECT, related_name="managed_decisions")

    class Meta:
        db_table = "security_managed_decision"
        db_table_comment = "Positive receipt mapping from native decision IDs to audited PRAHO provenance."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("source", "remote_id"), name="security_managed_remote_id"),
        ]
