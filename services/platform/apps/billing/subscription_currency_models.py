"""Durable notices and commitments for future subscription currency changes."""

import uuid
from datetime import timedelta
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition

from .currency_transition_notice import NOTICE_DAYS


class SubscriptionCurrencyTransition(models.Model):
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending notice"),
        ("notified", "Notice accepted"),
        ("committed", "Renewal document prepared"),
        ("superseded", "Superseded"),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subscription = models.ForeignKey(
        "billing.Subscription", on_delete=models.PROTECT, related_name="currency_transitions"
    )
    policy_revision = models.PositiveIntegerField()
    old_terms = models.JSONField()
    target_terms = models.JSONField()
    target_fingerprint = models.CharField(max_length=64)
    status = FSMField(max_length=20, choices=STATUS_CHOICES, default="pending", protected=True)
    notice_recipient = models.EmailField(blank=True)
    notice_subject = models.CharField(max_length=255)
    notice_body = models.TextField()
    notice_email = models.ForeignKey("notifications.EmailLog", on_delete=models.PROTECT, null=True, blank=True)
    notice_attempted_at = models.DateTimeField(null=True, blank=True)
    notice_accepted_at = models.DateTimeField(null=True, blank=True)
    preparation_not_before = models.DateTimeField(null=True, blank=True)
    effective_period_start = models.DateTimeField(null=True, blank=True)
    committed_cycle = models.OneToOneField("billing.BillingCycle", on_delete=models.PROTECT, null=True, blank=True)
    hold_reason = models.CharField(max_length=255, blank=True)
    last_error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_subscription_currency_transitions"
        ordering = ("created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["subscription"],
                condition=models.Q(status__in=["pending", "notified"]),
                name="one_open_subscription_currency_offer",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["pending", "notified", "committed", "superseded"]),
                name="subscription_currency_transition_status",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            original = type(self).objects.filter(pk=self.pk, notice_accepted_at__isnull=False).first()
            if original and any(
                getattr(original, field) != getattr(self, field)
                for field in (
                    "subscription_id",
                    "policy_revision",
                    "old_terms",
                    "target_terms",
                    "target_fingerprint",
                    "notice_recipient",
                    "notice_subject",
                    "notice_body",
                    "notice_email_id",
                    "notice_accepted_at",
                    "preparation_not_before",
                )
            ):
                raise ValidationError(_("An accepted currency-change notice cannot be rewritten; create a new offer"))
        super().save(*args, **kwargs)

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        """Refresh the protected FSM field using the billing models' established pattern."""
        saved = self.__dict__.pop("status", None) if fields is None or "status" in fields else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved is not None:
                self.__dict__["status"] = saved
            raise

    @transition(field=status, source="pending", target="notified")
    def accept_notice(self) -> None:
        log = self.notice_email
        if log is None or log.status not in {"sent", "delivered"}:
            raise ValidationError(_("A provider-accepted email is required"))
        if (
            log.to_addr != self.notice_recipient
            or log.subject != self.notice_subject
            or log.customer_id != self.subscription.customer_id
            or log.get_decrypted_body_text() != self.notice_body
        ):
            raise ValidationError(_("The accepted email does not match the exact currency offer"))
        self.notice_accepted_at = log.sent_at
        self.preparation_not_before = log.sent_at + timedelta(days=NOTICE_DAYS)

    @transition(field=status, source="notified", target="committed")
    def commit(self) -> None:
        if not self.committed_cycle_id or not self.effective_period_start:
            raise ValidationError(_("A prepared cycle and its effective period are required"))

    @transition(field=status, source=["pending", "notified"], target="superseded")
    def supersede(self) -> None:
        """Keep the exact earlier notice as historical evidence."""
