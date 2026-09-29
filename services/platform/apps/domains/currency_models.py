"""Exact domain renewal offers, accepted notices, and document commitments."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import timedelta
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition

from apps.billing.currency_transition_notice import NOTICE_DAYS


class DomainCurrencyTransition(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.ForeignKey("domains.Domain", on_delete=models.PROTECT, related_name="currency_transitions")
    policy_revision = models.PositiveIntegerField()
    old_terms = models.JSONField()
    target_terms = models.JSONField()
    target_fingerprint = models.CharField(max_length=64)
    status = FSMField(
        max_length=20,
        default="pending",
        protected=True,
        choices=(
            ("pending", "Pending notice"),
            ("notified", "Notice accepted"),
            ("committed", "Renewal document prepared"),
            ("superseded", "Superseded"),
        ),
    )
    notice_recipient = models.EmailField()
    notice_subject = models.CharField(max_length=255)
    notice_body = models.TextField()
    notice_email = models.ForeignKey("notifications.EmailLog", on_delete=models.PROTECT, null=True, blank=True)
    notice_attempted_at = models.DateTimeField(null=True, blank=True)
    notice_sent_at = models.DateTimeField(null=True, blank=True)
    preparation_not_before = models.DateTimeField(null=True, blank=True)
    committed_item = models.OneToOneField("domains.DomainOrderItem", on_delete=models.PROTECT, null=True, blank=True)
    effective_period_start = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_currency_transitions"
        ordering = ("created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["domain"],
                condition=models.Q(status__in=["pending", "notified"]),
                name="one_open_domain_currency_offer",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["pending", "notified", "committed", "superseded"]),
                name="domain_currency_transition_status",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            original = type(self).objects.filter(pk=self.pk, notice_sent_at__isnull=False).first()
            protected = (
                "domain_id",
                "policy_revision",
                "old_terms",
                "target_terms",
                "target_fingerprint",
                "notice_recipient",
                "notice_subject",
                "notice_body",
                "notice_email_id",
                "notice_sent_at",
                "preparation_not_before",
            )
            if original and any(getattr(original, field) != getattr(self, field) for field in protected):
                raise ValidationError(_("An accepted domain currency offer cannot be rewritten"))
            if (
                original
                and original.status == "committed"
                and (
                    original.committed_item_id != self.committed_item_id
                    or original.effective_period_start != self.effective_period_start
                    or self.status != "committed"
                )
            ):
                raise ValidationError(_("A committed domain renewal document cannot be replaced"))
        super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[DomainCurrencyTransition] | None = None,
    ) -> None:
        """Refresh the protected FSM field using the existing Domain convention."""
        saved = {}
        if (fields is None or "status" in fields) and "status" in self.__dict__:
            saved["status"] = self.__dict__.pop("status")
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @transition(field=status, source="pending", target="notified")
    def accept_notice(self) -> None:
        email = self.notice_email
        if email is None or email.status not in {"sent", "delivered"}:
            raise ValidationError(_("A provider-accepted email is required"))
        if (
            email.to_addr != self.notice_recipient
            or email.subject != self.notice_subject
            or email.customer_id != self.domain.customer_id
            or email.get_decrypted_body_text() != self.notice_body
            or email.template_key != f"domain_currency_notice:{self.pk}"
            or self.notice_attempted_at is None
            or email.sent_at < self.notice_attempted_at
        ):
            raise ValidationError(_("The accepted email does not match this exact domain offer"))
        # EmailLog.sent_at may be the queue time. Acceptance observed now is the
        # conservative start of the notice period, never an earlier queue timestamp.
        self.notice_sent_at = max(email.sent_at, timezone.now())
        self.preparation_not_before = self.notice_sent_at + timedelta(days=NOTICE_DAYS)

    @transition(field=status, source="notified", target="committed")
    def commit(self) -> None:
        if not self.committed_item_id or not self.effective_period_start:
            raise ValidationError(_("A prepared domain item and its effective period are required"))

    @transition(field=status, source=["pending", "notified"], target="superseded")
    def supersede(self) -> None:
        """Retain the earlier notice unchanged as evidence."""
