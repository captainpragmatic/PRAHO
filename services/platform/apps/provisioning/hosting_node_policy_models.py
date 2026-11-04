"""Separate native quota qualification and customer notification ownership."""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

from .virtualmin_security_models import EvidenceQuerySet

ACCEPTED_EXECUTION_FIELDS = frozenset(
    {"server_id", "server_uuid", "review_id", "actor_id", "reason", "authority", "action", "expected_identity"}
)


class HostingExecutionQuerySet(models.QuerySet["NodeHostingExecution"]):
    def update(self, **kwargs: Any) -> int:
        if ACCEPTED_EXECUTION_FIELDS.intersection(kwargs) or {"server", "review", "actor"}.intersection(kwargs):
            raise ValidationError(_("Accepted node hosting authority cannot be overwritten."))
        return super().update(**kwargs)

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Node hosting executions must be transitioned and audited individually."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[NodeHostingExecution]:
        raise ValidationError(_("Node hosting executions must be accepted and audited individually."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Accepted node hosting history cannot be deleted."))


class NodeHostingPolicy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.OneToOneField(
        "provisioning.VirtualminServer", on_delete=models.CASCADE, related_name="hosting_policy"
    )
    policy_version = models.CharField(max_length=40, default="hosting-node-v1")
    revision = models.PositiveBigIntegerField(default=1)
    connection_identity = models.CharField(max_length=64, default="", editable=False)
    quota_adopted = models.BooleanField(default=False)
    quota_verified_at = models.DateTimeField(null=True)
    quota_evidence = models.JSONField(default=dict)
    notification_owner = models.CharField(
        max_length=16,
        default="unknown",
        choices=[
            ("unknown", _("Not inspected")),
            ("native", _("Native node")),
            ("platform", _("Platform")),
        ],
    )
    notifications_verified_at = models.DateTimeField(null=True)
    notification_evidence = models.JSONField(default=dict)
    operation = models.UUIDField(null=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_node_hosting_policy"
        db_table_comment = (
            "Independent identity-bound quota adoption and customer-mail handover; import changes neither."
        )


class NodeHostingReview(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.SET_NULL, null=True, related_name="hosting_reviews"
    )
    server_uuid = models.UUIDField(editable=False)
    policy_version = models.CharField(max_length=40)
    identity = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = EvidenceQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_node_hosting_review"
        db_table_comment = "Immutable native quota and notification inventory reviewed before explicit node adoption."

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if not self._state.adding or type(self).objects.using(using).filter(pk=self.pk).exists():
            raise ValidationError(_("Hosting review history cannot be overwritten."))
        kwargs.update(using=using, force_insert=True)
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Hosting review history cannot be deleted."))


class NodeHostingExecution(ConcurrentTransitionMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.SET_NULL, null=True, related_name="hosting_executions"
    )
    server_uuid = models.UUIDField(editable=False)
    review = models.ForeignKey(NodeHostingReview, on_delete=models.PROTECT, related_name="executions")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    reason = models.CharField(max_length=2000)
    authority = models.JSONField(default=dict)
    action = models.CharField(
        max_length=24,
        choices=[
            ("adopt_quota", _("Adopt verified quotas")),
            ("requalify_quota", _("Requalify an adopted node after reboot")),
            ("handover_mail", _("Hand over customer mail")),
            ("prepare_helpers", _("Prepare read-only inspection helpers")),
        ],
    )
    expected_identity = models.CharField(max_length=64)
    status = FSMField(
        max_length=20,
        default="running",
        protected=True,
        choices=[
            ("running", _("Running")),
            ("attention", _("Needs reconciliation")),
            ("verified", _("Verified")),
        ],
    )
    verification = models.ForeignKey(
        NodeHostingReview, on_delete=models.PROTECT, null=True, related_name="verified_executions"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = HostingExecutionQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_node_hosting_execution"
        db_table_comment = (
            "Durable node-global policy ownership; uncertain native work retains exclusion until fenced proof."
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if not self._state.adding:
            original = type(self).objects.using(using).get(pk=self.pk)
            if any(getattr(original, field) != getattr(self, field) for field in ACCEPTED_EXECUTION_FIELDS):
                raise ValidationError(_("Accepted node hosting authority cannot be overwritten."))
        else:
            kwargs["force_insert"] = True
        kwargs["using"] = using
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Accepted node hosting history cannot be deleted."))

    @transition(field=status, source="running", target="attention")
    def require_attention(self) -> None:
        pass

    @transition(field=status, source=("running", "attention"), target="verified")
    def mark_verified(self) -> None:
        pass

    def refresh_from_db(self, *args: Any, **kwargs: Any) -> None:
        self.__dict__.pop("status", None)
        super().refresh_from_db(*args, **kwargs)
