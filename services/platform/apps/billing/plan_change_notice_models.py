"""Durable phase delivery identities; rendered customer data stays in EmailLog."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class PlanChangeNoticeQuerySet(models.QuerySet["PlanChangeNotice"]):
    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Plan-change phase delivery ownership cannot be deleted."))

    def update(self, **kwargs: Any) -> int:
        # Django's SET_NULL collector may detach a deleted EmailLog. The linked
        # state remains terminal, so deletion never grants a fresh send.
        if set(kwargs) not in ({"email_log"}, {"email_log_id"}) or any(value is not None for value in kwargs.values()):
            raise ValidationError(_("Plan-change notices require their durable delivery service."))
        return super().update(**kwargs)

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Plan-change delivery evidence cannot be rewritten in bulk."))


class PlanChangeNotice(models.Model):
    class Phase(models.TextChoices):
        PROFORMA = "proforma", "Proforma"
        INVOICE_ISSUED = "invoice_issued", "Invoice issued"
        PAYMENT_RECEIVED = "payment_received", "Payment received"
        SCHEDULED = "scheduled", "Scheduled"
        COMPLETED = "completed", "Completed"
        ATTENTION = "attention", "Attention"

    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        LINKED = "linked", "Linked to delivery"
        SUPPRESSED = "suppressed", "Suppressed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    change = models.ForeignKey("billing.PlanChange", on_delete=models.PROTECT, related_name="phase_notices")
    phase = models.CharField(max_length=20, choices=Phase.choices)
    state = models.CharField(max_length=12, choices=State.choices, default=State.PENDING)
    due_at = models.DateTimeField(default=timezone.now)
    email_log = models.OneToOneField(
        "notifications.EmailLog", on_delete=models.SET_NULL, null=True, blank=True, related_name="plan_change_notice"
    )
    refusal_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = PlanChangeNoticeQuerySet.as_manager()

    class Meta:
        db_table = "billing_plan_change_notices"
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("change", "phase"), name="plan_change_notice_phase_unique")
        ]
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=("state", "due_at"))]

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if not self._state.adding:
            original = (
                type(self).objects.using(using).values("change_id", "phase", "state", "email_log_id").get(pk=self.pk)
            )
            if self.change_id != original["change_id"] or self.phase != original["phase"]:
                raise ValidationError(_("A notice cannot be retargeted to another customer agreement or phase."))
            if original["state"] != "pending" and (
                self.state != original["state"] or self.email_log_id != original["email_log_id"]
            ):
                raise ValidationError(_("A closed notification phase cannot authorize another message."))
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Plan-change phase delivery ownership cannot be deleted."))
