"""Durable financial fact journal, safe to append while only Payment is locked."""

from __future__ import annotations

from typing import Any, ClassVar
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils.translation import gettext_lazy as _


class PlanChangeReviewEventQuerySet(models.QuerySet["PlanChangeReviewEvent"]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Financial review facts require their audited processing service."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Financial review evidence cannot be deleted."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Financial review evidence cannot be rewritten in bulk."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[PlanChangeReviewEvent]:
        raise ValidationError(_("Financial review facts must be recorded and audited individually."))


class PlanChangeReviewEvent(models.Model):
    IMMUTABLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "fact_key",
        "source_kind",
        "source_id",
        "reason",
        "customer_id",
        "payment_id",
        "invoice_id",
        "proforma_id",
    )
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    fact_key = models.CharField(max_length=64, unique=True)
    source_kind = models.CharField(max_length=12, choices=(("payment", "Payment"), ("refund", "Refund")))
    source_id = models.CharField(max_length=64)
    reason = models.CharField(max_length=12, choices=(("dispute", "Dispute"), ("refund", "Refund")))
    # Scalars deliberately introduce no Customer/Document/PlanChange key-share
    # dependency into a Payment-first authenticated webhook transaction.
    customer_id = models.PositiveBigIntegerField()
    payment_id = models.PositiveBigIntegerField(null=True)
    invoice_id = models.PositiveBigIntegerField(null=True)
    proforma_id = models.PositiveBigIntegerField(null=True)
    reviewed_changes = models.JSONField(default=list)
    processed_at = models.DateTimeField(null=True)
    refusal_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = PlanChangeReviewEventQuerySet.as_manager()

    class Meta:
        db_table = "billing_plan_change_review_events"
        db_table_comment = "Immutable financial invalidation facts and document-first hosting plan review progress."
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["processed_at", "created_at"])]

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        original = type(self).objects.using(using).filter(pk=self.pk).values(*self.IMMUTABLE_FIELDS).first()
        if original is not None and (
            self._state.adding or any(getattr(self, field) != original[field] for field in self.IMMUTABLE_FIELDS)
        ):
            raise ValidationError(_("A recorded financial review fact cannot be replaced or retargeted."))
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Financial review evidence cannot be deleted."))
