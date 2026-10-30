"""Append-only operator evidence; recording a decision never runs node commands."""

from __future__ import annotations

import uuid
from typing import Any, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

Evidence = TypeVar("Evidence", bound="SecurityEvidence")


class EvidenceQuerySet(models.QuerySet[Evidence]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Security review history cannot be overwritten."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Security review history cannot be deleted."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Security review history cannot be overwritten."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[Evidence]:
        raise ValidationError(_("Security reviews must be recorded individually."))


class SecurityEvidence(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EvidenceQuerySet.as_manager()

    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding or type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError(_("Security review history cannot be overwritten."))
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Security review history cannot be deleted."))


class NodeSecurityReview(SecurityEvidence):
    server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.SET_NULL, null=True, related_name="security_reviews"
    )
    server_uuid = models.UUIDField(editable=False)
    policy_version = models.CharField(max_length=40)
    identity = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    evidence = models.JSONField()

    class Meta:
        db_table = "provisioning_node_security_review"
        db_table_comment = "Immutable bounded inspection and proposed access changes reviewed by an operator."


class NodeSecurityDecision(SecurityEvidence):
    review = models.OneToOneField(NodeSecurityReview, on_delete=models.PROTECT, related_name="decision")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    action = models.CharField(max_length=32, choices=[("acknowledge_source", _("Keep as migration source"))])
    reason = models.CharField(max_length=2000)

    class Meta:
        db_table = "provisioning_node_security_decision"
        db_table_comment = "Immutable operator responsibility acknowledgment bound to one inspected node state."
