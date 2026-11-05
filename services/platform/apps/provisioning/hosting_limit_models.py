"""Pinned customer entitlement and separately verified native enforcement."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils.translation import gettext_lazy as _


class HostingLimitApplicationQuerySet(models.QuerySet["HostingLimitApplication"]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Accepted hosting assignments cannot be overwritten."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Accepted hosting assignments cannot be overwritten."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[HostingLimitApplication]:
        raise ValidationError(_("Hosting assignments must be accepted and audited individually."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Accepted hosting assignments cannot be deleted."))


class ServiceHostingLimits(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.OneToOneField("provisioning.Service", on_delete=models.CASCADE, related_name="hosting_limits")
    revision = models.PositiveBigIntegerField(default=1)
    policy_version = models.PositiveIntegerField(default=1)
    assigned_plan_id = models.PositiveBigIntegerField()
    disk_allowance_mib = models.PositiveBigIntegerField(null=True)
    bandwidth_allowance_mib = models.PositiveBigIntegerField(null=True)
    disk_source = models.CharField(max_length=24)
    bandwidth_source = models.CharField(max_length=24)
    # Keep the operational allowance while a newer paid/explicit assignment is
    # pending. Native verification is represented separately below.
    operational_revision = models.PositiveBigIntegerField(null=True)
    operational_disk_allowance_mib = models.PositiveBigIntegerField(null=True)
    operational_bandwidth_allowance_mib = models.PositiveBigIntegerField(null=True)
    # Last verified state is deliberately separate from desired state. A successful
    # metadata write or a catalog change must not certify kernel enforcement.
    applied_revision = models.PositiveBigIntegerField(null=True)
    applied_overlay_revision = models.PositiveBigIntegerField(default=0)
    applied_disk_allowance_mib = models.PositiveBigIntegerField(null=True)
    applied_bandwidth_allowance_mib = models.PositiveBigIntegerField(null=True)
    verified_receipt = models.JSONField(default=dict)
    verified_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_service_hosting_limits"
        db_table_comment = "Pinned purchased allowances and the last independently verified native revision."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="hosting_limits_revision_positive"),
            models.CheckConstraint(
                condition=models.Q(applied_revision__isnull=True)
                | models.Q(applied_revision__lte=models.F("revision")),
                name="hosting_limits_applied_not_future",
            ),
        ]


class HostingLimitApplication(models.Model):
    """Service-owned durable outbox. Financial transactions need no Account FK or lock."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.ForeignKey("provisioning.Service", on_delete=models.CASCADE, related_name="limit_applications")
    revision = models.PositiveBigIntegerField()
    overlay_revision = models.PositiveBigIntegerField(default=0)
    overlay_extra_mib = models.PositiveIntegerField(default=0)
    overlay_expires_at = models.DateTimeField(null=True)
    submission_id = models.UUIDField()
    expected_plan_id = models.PositiveBigIntegerField()
    target_plan_id = models.PositiveBigIntegerField()
    disk_allowance_mib = models.PositiveBigIntegerField(null=True)
    bandwidth_allowance_mib = models.PositiveBigIntegerField(null=True)
    policy_version = models.PositiveIntegerField(default=1)
    reason = models.TextField()
    authority = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = HostingLimitApplicationQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_hosting_limit_application"
        db_table_comment = "Durable accepted resource assignments, independent of native account locks and retries."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("service", "revision", "overlay_revision"), name="hosting_application_base_overlay_unique"
            ),
            models.UniqueConstraint(fields=("service", "submission_id"), name="hosting_application_submission_unique"),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if not self._state.adding or type(self).objects.using(using).filter(pk=self.pk).exists():
            raise ValidationError(_("Accepted hosting assignments cannot be overwritten."))
        # Never let Django fall back to UPDATE for a newly constructed object
        # whose UUID appeared concurrently after the existence check.
        kwargs["force_insert"] = True
        kwargs["using"] = using
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Accepted hosting assignments cannot be deleted."))
