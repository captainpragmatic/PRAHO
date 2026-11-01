"""Durable resource provenance, exact destroy approvals and resumable provider outcomes."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

Record = TypeVar("Record", bound="ImmutableCloudRecord")


class ImmutableCloudQuerySet(models.QuerySet[Record]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Provider resource history cannot be overwritten."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Provider resource history cannot be deleted."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Provider resource history cannot be overwritten."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[Record]:
        raise ValidationError(_("Provider resource history must be recorded individually."))


class ImmutableCloudRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ImmutableCloudQuerySet.as_manager()

    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding or type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError(_("Provider resource history cannot be overwritten."))
        self.clean()
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Provider resource history cannot be deleted."))


class CloudResourceOwnership(ImmutableCloudRecord):
    deployment = models.ForeignKey(
        "infrastructure.NodeDeployment", on_delete=models.PROTECT, related_name="resource_ownership"
    )
    provider = models.ForeignKey("infrastructure.CloudProvider", on_delete=models.PROTECT)
    token_fingerprint = models.CharField(max_length=64)
    deployment_correlation_id = models.UUIDField()
    kind = models.CharField(max_length=20)
    resource_id = models.CharField(max_length=128)
    provenance = models.CharField(max_length=40)

    class Meta:
        db_table = "infrastructure_cloud_resource_ownership"
        db_table_comment = "Exact provider resources attributed to a deployment and creating credential."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("provider", "token_fingerprint", "kind", "resource_id"),
                name="unique_cloud_resource_owner",
            )
        ]

    def clean(self) -> None:
        super().clean()
        if self.provider_id != self.deployment.provider_id:
            raise ValidationError(_("Resource ownership must use the deployment's provider."))
        if self.deployment_correlation_id != self.deployment.correlation_id:
            raise ValidationError(_("Resource ownership must identify the exact deployment lifetime."))


class NodeDestroyPlan(ImmutableCloudRecord):
    deployment = models.ForeignKey(
        "infrastructure.NodeDeployment", on_delete=models.PROTECT, related_name="destroy_plans"
    )
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    provider = models.ForeignKey("infrastructure.CloudProvider", on_delete=models.PROTECT)
    provider_type = models.CharField(max_length=20)
    hostname = models.CharField(max_length=253)
    token_fingerprint = models.CharField(max_length=64)
    deployment_correlation_id = models.UUIDField()
    digest = models.CharField(max_length=64)
    restore_point_policy = models.CharField(max_length=10)
    server_ids = models.JSONField()
    inventory = models.JSONField()
    decisions = models.JSONField()
    retention_mappings = models.JSONField(default=dict)
    reason = models.CharField(max_length=2000, blank=True)

    class Meta:
        db_table = "infrastructure_node_destroy_plan"
        db_table_comment = "Immutable operator approval of provider cleanup and restore point retention."
        ordering = ("-created_at",)

    def clean(self) -> None:
        super().clean()
        if (
            self.provider_id != self.deployment.provider_id
            or self.provider_type != self.deployment.provider.provider_type
        ):
            raise ValidationError(_("Destroy approval must use the deployment's exact provider identity."))
        if self.restore_point_policy not in {"keep", "delete", "preserve"}:
            raise ValidationError(_("Choose how provider restore points will be retained."))
        if self.restore_point_policy != "preserve" and self.actor_id is None:
            raise ValidationError(_("An operator must approve the provider restore-point choice."))
        if self.hostname != self.deployment.hostname:
            raise ValidationError(_("Destroy approval must identify the deployment hostname exactly."))
        if self.deployment_correlation_id != self.deployment.correlation_id:
            raise ValidationError(_("Destroy approval must identify the exact deployment lifetime."))


class CloudResourceRetention(ImmutableCloudRecord):
    plan = models.ForeignKey(NodeDestroyPlan, on_delete=models.PROTECT, related_name="retained_resources")
    provider = models.ForeignKey("infrastructure.CloudProvider", on_delete=models.PROTECT)
    token_fingerprint = models.CharField(max_length=64)
    kind = models.CharField(max_length=20)
    resource_id = models.CharField(max_length=128)

    class Meta:
        db_table = "infrastructure_cloud_resource_retention"
        db_table_comment = "Provider restore points retained independently of node destruction."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("provider", "token_fingerprint", "kind", "resource_id"),
                name="unique_cloud_resource_retention",
            )
        ]

    def clean(self) -> None:
        super().clean()
        if self.provider_id != self.plan.provider_id or self.token_fingerprint != self.plan.token_fingerprint:
            raise ValidationError(_("Retention must use the exact approved provider identity."))


class CloudResourceCleanup(models.Model):
    class State(models.TextChoices):
        PENDING = "pending", _("Pending")
        DELETED = "deleted", _("Confirmed absent")
        RETAINED = "retained", _("Durable snapshot retained")
        PRESERVED = "preserved", _("Preserved for manual reconciliation")
        AWAITING_EXPIRY = "awaiting_expiry", _("Awaiting provider expiry")
        UNRESOLVED = "unresolved", _("Outcome unconfirmed")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    plan = models.ForeignKey(NodeDestroyPlan, on_delete=models.PROTECT, related_name="cleanup_outcomes")
    kind = models.CharField(max_length=20)
    resource_id = models.CharField(max_length=128)
    state = models.CharField(max_length=20, choices=State.choices, default=State.PENDING)
    detail = models.CharField(max_length=2000, blank=True)
    durable_snapshot_id = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "infrastructure_cloud_resource_cleanup"
        db_table_comment = "Resumable outcomes for each approved provider resource cleanup."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("plan", "kind", "resource_id"),
                name="unique_cloud_resource_cleanup",
            )
        ]
