"""
Proforma models for PRAHO Platform
Proforma invoices - estimates/quotes before actual invoicing.
"""

from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, ClassVar, TypedDict

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .currency_models import Currency

logger = logging.getLogger(__name__)

# Import validation functions - simplified placeholders to avoid circular imports
MAX_ADDRESS_FIELD_LENGTH = 500  # Constant


# TypedDict definitions for private tracking attributes
class _ProformaSnapshot(TypedDict, total=False):
    """Snapshot of proforma state for change tracking"""

    status: str
    total_cents: int


def validate_financial_amount(amount_cents: int, field_name: str = "Amount") -> None:
    """Placeholder - actual validation will be done via main models"""


def validate_financial_json(data: Any, field_name: str = "Financial JSON field") -> None:
    """Placeholder - actual validation will be done via main models"""


def validate_financial_text_field(text: str, field_name: str, max_length: int | None = None) -> None:
    """Placeholder - actual validation will be done via main models"""


def log_security_event(
    event_type: str, details: dict[str, Any], request_ip: str | None = None, user_email: str | None = None
) -> None:
    """Placeholder - actual logging will be done via main models"""
    logger.info(f"🔒 [Billing Security] {event_type}: {details}")


# ===============================================================================
# PROFORMA SEQUENCING
# ===============================================================================


class ProformaSequence(models.Model):
    """Proforma invoice number sequencing"""

    scope = models.CharField(max_length=50, default="default", unique=True)
    last_value = models.BigIntegerField(default=0)

    class Meta:
        db_table = "proforma_sequence"
        verbose_name = _("Proforma Sequence")
        verbose_name_plural = _("Proforma Sequences")

    def get_next_number(self, prefix: str = "PRO", user_email: str | None = None) -> str:
        """Get next proforma number and increment sequence atomically with security logging"""
        with transaction.atomic():
            # Atomic increment using F() expression to prevent race conditions
            old_value = self.last_value
            ProformaSequence.objects.filter(pk=self.pk).update(last_value=F("last_value") + 1)
            # Refresh the instance to get the updated value
            self.refresh_from_db()
            new_number = f"{prefix}-{self.last_value:06d}"

            # Enhanced security logging for audit trail
            log_security_event(
                event_type="proforma_number_generated",
                details={
                    "sequence_scope": self.scope,
                    "old_value": old_value,
                    "new_value": self.last_value,
                    "generated_number": new_number,
                    "prefix": prefix,
                    "critical_financial_operation": True,
                },
                user_email=user_email,
            )

            # Use dynamic logger to support tests that patch logging.getLogger
            logging.getLogger(__name__).info(
                f"🔢 Generated proforma number {new_number} (was {old_value}, now {self.last_value})"
            )
            return new_number


# ===============================================================================
# PROFORMA MODELS (SEPARATE FROM INVOICES)
# ===============================================================================


class ProformaInvoice(models.Model):
    """
    Proforma invoices - estimates/quotes before actual invoicing.
    Separate from Invoice model with different business logic.
    """

    # Core identification
    customer = models.ForeignKey("customers.Customer", on_delete=models.RESTRICT, related_name="proforma_invoices")
    number = models.CharField(max_length=50, unique=True, default="PRO-000")  # From ProformaSequence

    # Currency and amounts (cents for precision)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    subtotal_cents = models.BigIntegerField(default=0)
    tax_cents = models.BigIntegerField(default=0)
    total_cents = models.BigIntegerField(default=0)

    # Proforma-specific fields
    STATUS_CHOICES: ClassVar = [
        ("draft", _("Draft")),
        ("sent", _("Sent")),
        ("accepted", _("Accepted")),
        ("expired", _("Expired")),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    valid_until = models.DateTimeField(default=timezone.now, help_text=_("Proforma expires after this date"))
    created_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True, help_text=_("Additional notes for the proforma"))

    # Billing address snapshot
    bill_to_name = models.CharField(max_length=255, default="")
    bill_to_tax_id = models.CharField(max_length=50, blank=True)
    bill_to_email = models.EmailField(blank=True)
    bill_to_address1 = models.CharField(max_length=255, blank=True)
    bill_to_address2 = models.CharField(max_length=255, blank=True)
    bill_to_city = models.CharField(max_length=100, blank=True)
    bill_to_region = models.CharField(max_length=100, blank=True)
    bill_to_postal = models.CharField(max_length=20, blank=True)
    bill_to_country = models.CharField(max_length=2, blank=True)

    # Files
    pdf_file = models.FileField(upload_to="proformas/pdf/", blank=True, null=True)

    # Private attributes for change tracking (not DB fields - annotations only)
    _original_proforma_values: _ProformaSnapshot | None = None

    class Meta:
        db_table = "proforma_invoice"
        verbose_name = _("Proforma Invoice")
        verbose_name_plural = _("Proforma Invoices")
        indexes = (
            models.Index(fields=["customer"]),
            models.Index(fields=["valid_until"]),
            models.Index(fields=["created_at"]),
        )

    def __str__(self) -> str:
        return f"{self.number} - {self.customer}"

    @property
    def is_expired(self) -> bool:
        if not self.valid_until:
            return False
        # Handle both date and datetime objects
        if hasattr(self.valid_until, "time"):
            # It's a datetime object
            return timezone.now() > self.valid_until
        else:
            # It's a date object, convert to datetime
            valid_until_datetime = timezone.make_aware(datetime.combine(self.valid_until, datetime.min.time()))
            return timezone.now() > valid_until_datetime

    @property
    def subtotal(self) -> Decimal:
        return Decimal(self.subtotal_cents) / 100

    @property
    def tax_amount(self) -> Decimal:
        return Decimal(self.tax_cents) / 100

    @property
    def total(self) -> Decimal:
        return Decimal(self.total_cents) / 100

    def clean(self) -> None:
        """🔒 Validate proforma data and log security events"""
        super().clean()

        # Validate financial amounts
        validate_financial_amount(self.subtotal_cents, "Subtotal")
        validate_financial_amount(self.tax_cents, "Tax amount")
        validate_financial_amount(self.total_cents, "Total amount")

        # Log security validation event
        log_security_event(
            event_type="proforma_validation",
            details={
                "proforma_number": self.number,
                "customer_id": self.customer_id,
                "total_cents": self.total_cents,
                "has_metadata": bool(self.meta),
                "validation_passed": True,
            },
            user_email=None,  # No user context in model validation
        )

        # Validate JSON metadata
        validate_financial_json(self.meta, "Proforma metadata")

        # Validate text fields
        validate_financial_text_field(self.bill_to_name, "Bill to name", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_address1, "Address line 1", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_address2, "Address line 2", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_city, "City", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_region, "Region", MAX_ADDRESS_FIELD_LENGTH)

        # Validate total calculation integrity
        if self.subtotal_cents + self.tax_cents != self.total_cents and self.total_cents != 0:
            raise ValidationError("Financial calculation error: subtotal + tax must equal total")

        # Validate expiration date
        if self.valid_until and self.valid_until <= timezone.now():
            raise ValidationError("Proforma valid until date must be in the future")

        # Log security validation
        log_security_event(
            event_type="proforma_validation",
            details={
                "proforma_number": self.number,
                "customer_id": self.customer.id if self.customer else None,
                "total_cents": self.total_cents,
                "has_metadata": bool(self.meta),
                "validation_passed": True,
            },
        )

    def convert_to_invoice(self) -> None:
        """Convert this proforma to an actual invoice"""
        # Will implement this method in business logic
        # Explicit pass for clarity


class ProformaLine(models.Model):
    """Proforma line items"""

    KIND_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("service", _("Service")),
        ("setup", _("Setup Fee")),
        ("discount", _("Discount")),
        ("misc", _("Miscellaneous")),
    )

    proforma = models.ForeignKey(ProformaInvoice, on_delete=models.CASCADE, related_name="lines")
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    service = models.ForeignKey("provisioning.Service", on_delete=models.SET_NULL, null=True, blank=True)

    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=12, decimal_places=3, default=Decimal("1.000"))
    unit_price_cents = models.BigIntegerField(default=0)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=4, default=Decimal("0.0000"))
    line_total_cents = models.BigIntegerField(default=0)

    class Meta:
        db_table = "proforma_line"
        indexes = (models.Index(fields=["service"]),)

    @property
    def unit_price(self) -> Decimal:
        return Decimal(self.unit_price_cents) / 100

    @property
    def line_total(self) -> Decimal:
        return Decimal(self.line_total_cents) / 100
