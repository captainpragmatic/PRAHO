"""One durable on-session provider identity for an accepted standalone plan quote."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils.translation import gettext_lazy as _


class PlanChangePaymentAttemptQuerySet(models.QuerySet["PlanChangePaymentAttempt"]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Plan payment attempts require their durable submission service."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Plan payment attempts cannot be rewritten in bulk."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Plan payment evidence cannot be deleted."))


class PlanChangePaymentAttempt(models.Model):
    class State(models.TextChoices):
        RESERVED = "reserved", "Reserved"
        SUBMITTING = "submitting", "Submitting"
        UNKNOWN = "unknown", "Unknown"
        READY = "ready", "Ready"
        SUCCEEDED = "succeeded", "Succeeded"
        CANCELLED = "cancelled", "Cancelled"
        REFUSED = "refused", "Refused"
        REVIEW = "review", "Review"

    IMMUTABLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "change_id",
        "payment_id",
        "payload",
        "payload_hash",
        "idempotency_key",
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    change = models.OneToOneField("billing.PlanChange", on_delete=models.PROTECT, related_name="payment_attempt")
    payment = models.OneToOneField("billing.Payment", on_delete=models.PROTECT, related_name="plan_change_attempt")
    payload = models.JSONField()
    payload_hash = models.CharField(max_length=64)
    idempotency_key = models.CharField(max_length=64, unique=True)
    state = models.CharField(max_length=16, choices=State.choices, default=State.RESERVED)
    gateway_intent_id = models.CharField(max_length=255, blank=True)
    client_secret_ciphertext = models.TextField(blank=True)
    provider_status = models.CharField(max_length=40, blank=True)
    first_submitted_at = models.DateTimeField(null=True)
    replay_until = models.DateTimeField(null=True)
    lease_token = models.UUIDField(null=True)
    lease_expires_at = models.DateTimeField(null=True)
    submission_count = models.PositiveIntegerField(default=0)
    last_error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = PlanChangePaymentAttemptQuerySet.as_manager()

    class Meta:
        db_table = "billing_plan_change_payment_attempts"
        db_table_comment = (
            "Durable on-session payment attempts and provider replay authority for hosting plan agreements."
        )
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["state", "lease_expires_at"])]

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if not self._state.adding:
            original = type(self).objects.using(using).filter(pk=self.pk).values(*self.IMMUTABLE_FIELDS).get()
            if any(getattr(self, field) != original[field] for field in self.IMMUTABLE_FIELDS):
                raise ValidationError(_("A plan payment's original payload and identity cannot be replaced."))
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Plan payment evidence cannot be deleted."))
