"""Models that record customer authority for PRAHO-managed recurring payments."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition


class RecurringPaymentAuthorization(models.Model):
    """Auditable customer mandate for off-session charges to one saved method."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("active", _("Active")),
        ("withdrawn", _("Withdrawn")),
        ("revoked", _("Revoked")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.PROTECT,
        related_name="recurring_payment_authorizations",
    )
    payment_method = models.ForeignKey(
        "customers.CustomerPaymentMethod",
        on_delete=models.PROTECT,
        related_name="recurring_payment_authorizations",
    )
    status = FSMField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
        protected=True,
        db_index=True,
    )
    setup_intent_id = models.CharField(max_length=100, blank=True, null=True, unique=True)
    terms_version = models.CharField(max_length=50)
    terms_text = models.TextField()
    terms_text_hash = models.CharField(max_length=64)
    granted_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="granted_recurring_payment_authorizations",
    )
    granted_by_role = models.CharField(max_length=50)
    granted_at = models.DateTimeField(null=True, blank=True)
    grant_ip_address = models.GenericIPAddressField(null=True, blank=True)
    grant_user_agent = models.CharField(max_length=500, blank=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    withdrawn_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="withdrawn_recurring_payment_authorizations",
    )
    withdrawal_reason = models.CharField(max_length=255, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_recurring_payment_authorizations",
    )
    revocation_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_recurring_payment_authorizations"
        ordering = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=("customer", "payment_method"),
                condition=Q(status="active"),
                name="unique_active_recurring_auth_method",
            ),
            models.CheckConstraint(
                condition=Q(status__in=["pending", "active", "withdrawn", "revoked"]),
                name="recurring_payment_auth_status_valid",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(status="active")
                    | (
                        Q(setup_intent_id__isnull=False)
                        & ~Q(setup_intent_id="")
                        & Q(granted_at__isnull=False)
                        & ~Q(terms_version="")
                        & ~Q(terms_text="")
                        & ~Q(terms_text_hash="")
                    )
                ),
                name="active_recurring_auth_has_consent_proof",
            ),
        ]
        indexes = (
            models.Index(fields=("customer", "status")),
            models.Index(fields=("payment_method", "status")),
        )

    def __str__(self) -> str:
        return f"{self.customer_id}:{self.payment_method_id}:{self.status}"

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Any = None,
        from_queryset: Any = None,
    ) -> None:
        """Refresh protected FSM state through Django's normal model API."""
        refresh_status = fields is None or "status" in fields
        saved_status = self.__dict__.pop("status", None) if refresh_status else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved_status is not None:
                self.__dict__["status"] = saved_status
            raise

    @transition(field=status, source="pending", target="active")
    def activate(self) -> None:
        """Activate a mandate after its complete consent proof is verified."""

    @transition(field=status, source="active", target="withdrawn")
    def withdraw(self, *, actor: Any, reason: str, at: datetime | None = None) -> None:
        """Record immediate withdrawal by a customer billing principal."""
        self.withdrawn_at = at or timezone.now()
        self.withdrawn_by = actor
        self.withdrawal_reason = reason[:255]

    @transition(field=status, source="active", target="revoked")
    def revoke(self, *, actor: Any, reason: str, at: datetime | None = None) -> None:
        """Record staff revocation without representing it as customer consent."""
        self.revoked_at = at or timezone.now()
        self.revoked_by = actor
        self.revocation_reason = reason[:255]

    def clean(self) -> None:
        super().clean()
        if self.payment_method_id and self.customer_id:
            method_customer_id = self.payment_method.customer_id
            if method_customer_id != self.customer_id:
                raise ValidationError({"payment_method": _("Payment method must belong to the mandate customer.")})
        if self.status == "active" and (
            not self.setup_intent_id
            or not self.granted_at
            or not self.terms_version
            or not self.terms_text
            or not self.terms_text_hash
        ):
            raise ValidationError(_("Active recurring-payment authorization requires complete consent proof."))
        if self.terms_text and self.terms_text_hash != hashlib.sha256(self.terms_text.encode("utf-8")).hexdigest():
            raise ValidationError({"terms_text_hash": _("Terms text hash does not match the recorded agreement.")})

    @property
    def is_active(self) -> bool:
        """Return true only while the mandate and its saved method remain usable."""
        return bool(
            self.status == "active"
            and self.granted_at
            and self.granted_at <= timezone.now()
            and self.terms_text_hash == hashlib.sha256(self.terms_text.encode("utf-8")).hexdigest()
            and self.payment_method.is_active
            and self.payment_method.deleted_at is None
        )
