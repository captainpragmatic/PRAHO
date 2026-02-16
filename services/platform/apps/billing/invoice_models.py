"""
Invoice models for PRAHO Platform
Romanian compliant invoice model with address snapshots and immutable ledger.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.billing.validators import (
    MAX_ADDRESS_FIELD_LENGTH,
    validate_financial_amount,
    validate_financial_json,
    validate_financial_text_field,
)
from apps.common.validators import log_security_event

from .currency_models import Currency

logger = logging.getLogger(__name__)


# ===============================================================================
# INVOICE & PROFORMA SEQUENCING
# ===============================================================================


class InvoiceSequence(models.Model):
    """Invoice number sequencing for legal compliance"""

    scope = models.CharField(max_length=50, default="default", unique=True)
    last_value = models.BigIntegerField(default=0)

    class Meta:
        db_table = "invoice_sequence"
        verbose_name = _("Invoice Sequence")
        verbose_name_plural = _("Invoice Sequences")

    def get_next_number(self, prefix: str = "INV", user_email: str | None = None) -> str:
        """Get next invoice number and increment sequence atomically with security logging"""
        with transaction.atomic():
            # Log critical financial operation
            old_value = self.last_value

            # Atomic increment using F() expression to prevent race conditions
            InvoiceSequence.objects.filter(pk=self.pk).update(last_value=F("last_value") + 1)
            # Refresh the instance to get the updated value
            self.refresh_from_db()
            new_number = f"{prefix}-{self.last_value:06d}"

            # Comprehensive security logging for audit trail
            log_security_event(
                event_type="invoice_number_generated",
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

            return new_number


# ===============================================================================
# INVOICE MODELS (IMMUTABLE LEDGER)
# ===============================================================================


class Invoice(models.Model):
    """
    Romanian compliant invoice model with address snapshots.
    Immutable once issued - separate from proforma invoices.
    Updated status choices as requested.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("draft", _("Draft")),
        ("issued", _("Issued")),  # Changed from 'sent' to 'issued'
        ("paid", _("Paid")),
        ("overdue", _("Overdue")),
        ("void", _("Void")),  # Changed from 'cancelled' to 'void'
        ("refunded", _("Refunded")),
    )

    # Core identification
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.RESTRICT,  # Cannot delete customer with invoices
        related_name="invoices",
    )
    number = models.CharField(max_length=50, unique=True, default="TMP-000")  # From InvoiceSequence
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")

    # Currency and amounts (cents for precision)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    exchange_to_ron = models.DecimalField(
        max_digits=18, decimal_places=6, null=True, blank=True, help_text=_("Exchange rate to RON at time of invoice")
    )
    subtotal_cents = models.BigIntegerField(default=0)
    tax_cents = models.BigIntegerField(default=0)
    total_cents = models.BigIntegerField(default=0)

    # Dates
    issued_at = models.DateTimeField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    locked_at = models.DateTimeField(null=True, blank=True, help_text=_("When invoice became immutable"))

    # Timestamps
    sent_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)

    # Billing address snapshot (immutable once issued)
    bill_to_name = models.CharField(max_length=255, default="")
    bill_to_tax_id = models.CharField(max_length=50, blank=True)
    bill_to_email = models.EmailField(blank=True)
    bill_to_address1 = models.CharField(max_length=255, blank=True)
    bill_to_address2 = models.CharField(max_length=255, blank=True)
    bill_to_city = models.CharField(max_length=100, blank=True)
    bill_to_region = models.CharField(max_length=100, blank=True)
    bill_to_postal = models.CharField(max_length=20, blank=True)
    bill_to_country = models.CharField(max_length=2, blank=True)  # ISO 3166-1

    # Romanian e-Factura compliance
    efactura_id = models.CharField(max_length=100, blank=True)
    efactura_sent = models.BooleanField(default=False)
    efactura_sent_date = models.DateTimeField(null=True, blank=True)
    efactura_response = models.JSONField(default=dict, blank=True)

    # File attachments
    pdf_file = models.FileField(upload_to="invoices/pdf/", blank=True, null=True)
    xml_file = models.FileField(upload_to="invoices/xml/", blank=True, null=True)

    # Audit & Relationships
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, related_name="created_invoices")
    converted_from_proforma = models.ForeignKey(
        "billing.ProformaInvoice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_("Proforma that was converted to this invoice"),
    )

    class Meta:
        db_table = "invoice"
        verbose_name = _("Invoice")
        verbose_name_plural = _("Invoices")
        indexes = (
            models.Index(fields=["customer", "-created_at"]),
            models.Index(
                fields=["customer"], condition=models.Q(status__in=["issued", "overdue"]), name="bill_inv_cust_pending"
            ),
            models.Index(fields=["status", "-due_at"]),
            models.Index(fields=["number"]),
        )

    def __str__(self) -> str:
        return f"{self.number} - {self.customer}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Calculate subtotal from total and tax on save with validation"""
        # Call clean to trigger validation
        self.clean()

        if self.total_cents and self.tax_cents:
            self.subtotal_cents = self.total_cents - self.tax_cents
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """🔒 Validate invoice data for security issues"""
        super().clean()

        # Validate financial amounts
        validate_financial_amount(self.subtotal_cents, "Subtotal")
        validate_financial_amount(self.tax_cents, "Tax amount")
        validate_financial_amount(self.total_cents, "Total amount")

        # Validate JSON fields
        validate_financial_json(self.meta, "Invoice metadata")
        validate_financial_json(self.efactura_response, "e-Factura response")

        # Validate text fields
        validate_financial_text_field(self.bill_to_name, "Bill to name", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_address1, "Address line 1", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_address2, "Address line 2", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_city, "City", MAX_ADDRESS_FIELD_LENGTH)
        validate_financial_text_field(self.bill_to_region, "Region", MAX_ADDRESS_FIELD_LENGTH)

        # Validate financial calculation integrity
        # Only enforce when all components are non-zero. This allows
        # creating invoices with partial amounts (e.g., only total_cents)
        # which will be populated by lines or later calculations.
        if (
            self.total_cents != 0
            and self.subtotal_cents != 0
            and self.tax_cents != 0
            and (self.subtotal_cents + self.tax_cents != self.total_cents)
        ):
            raise ValidationError("Financial calculation error: subtotal + tax must equal total")

        # Validate invoice immutability rules
        # Keep strict validation when explicitly validating an invoice
        # that is locked and not in draft. Views creating invoices that
        # must be locked immediately should lock post-save.
        if self.locked_at and self.status not in ["draft"]:
            raise ValidationError("Cannot modify locked invoice")

        # Validate date consistency
        if self.issued_at and self.due_at and self.due_at <= self.issued_at:
            raise ValidationError("Due date must be after issue date")

        # Log security validation
        log_security_event(
            event_type="invoice_validation",
            details={
                "invoice_number": self.number,
                "customer_id": self.customer.id if self.customer else None,
                "status": self.status,
                "total_cents": self.total_cents,
                "is_locked": bool(self.locked_at),
                "has_metadata": bool(self.meta),
                "validation_passed": True,
            },
        )

    @property
    def subtotal(self) -> Decimal:
        """Convert cents to decimal"""
        return Decimal(self.subtotal_cents) / 100

    @property
    def tax_amount(self) -> Decimal:
        """Convert cents to decimal"""
        return Decimal(self.tax_cents) / 100

    @property
    def total(self) -> Decimal:
        """Convert cents to decimal"""
        return Decimal(self.total_cents) / 100

    def recalculate_totals(self) -> None:
        """
        Recalculate document totals from line items.
        Ensures end-to-end consistency: subtotal = Σ(line subtotals), tax = Σ(line taxes)
        """
        lines = self.lines.all()

        # Calculate subtotals and tax amounts by summing line items
        self.subtotal_cents = sum(line.subtotal_cents for line in lines)
        self.tax_cents = sum(line.tax_cents for line in lines)

        # Total = subtotal + tax (no discount handling for now)
        self.total_cents = self.subtotal_cents + self.tax_cents

    def is_overdue(self) -> bool:
        """Check if invoice is overdue"""
        return self.due_at is not None and timezone.now() > self.due_at and self.status == "issued"

    def get_remaining_amount(self) -> int:
        """Calculate remaining unpaid amount in cents"""
        paid_amount = self.payments.filter(status="succeeded").aggregate(total=models.Sum("amount_cents"))["total"] or 0
        return max(0, self.total_cents - paid_amount)

    def mark_as_paid(self) -> None:
        """Mark invoice as paid"""
        self.status = "paid"
        self.paid_at = timezone.now()
        self.save()

    @property
    def amount_due(self) -> int:
        """Calculate remaining amount due after payments"""
        # TODO: Implement actual payment tracking
        # For now, assume unpaid invoices have full amount due
        if self.status == "paid":
            return 0
        return self.total_cents

    def update_status_from_payments(self) -> None:
        """Update invoice status based on associated payments"""
        # TODO: Implement payment-based status update logic
        if self.amount_due <= 0:
            self.mark_as_paid()


class InvoiceLine(models.Model):
    """
    Invoice line items with enhanced categorization.
    Replaces old InvoiceItem model with better structure from schema.
    """

    KIND_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("service", _("Service")),
        ("setup", _("Setup Fee")),
        ("credit", _("Credit")),
        ("discount", _("Discount")),
        ("refund", _("Refund")),
        ("misc", _("Miscellaneous")),
    )

    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name="lines")
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_("Related service if applicable"),
    )

    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=12, decimal_places=3, default=Decimal("1.000"))
    unit_price_cents = models.BigIntegerField(default=0)
    tax_rate = models.DecimalField(
        max_digits=5, decimal_places=4, default=Decimal("0.0000"), help_text=_("Tax rate as decimal (0.21 for 21%)")
    )
    tax_cents = models.BigIntegerField(default=0, help_text=_("Tax amount in cents"))
    line_total_cents = models.BigIntegerField(default=0)

    class Meta:
        db_table = "invoice_line"
        verbose_name = _("Invoice Line")
        verbose_name_plural = _("Invoice Lines")
        indexes = (
            models.Index(fields=["service"]),
            models.Index(fields=["invoice", "kind"]),
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Calculate totals before saving
        self.calculate_totals()
        super().save(*args, **kwargs)

    def calculate_totals(self) -> int:
        """Calculate tax and line total with proper banker's rounding for Romanian VAT compliance"""
        from decimal import ROUND_HALF_EVEN

        subtotal = self.subtotal_cents
        # Use banker's rounding for VAT compliance (same as OrderItem)
        vat_amount = Decimal(subtotal) * Decimal(str(self.tax_rate))
        self.tax_cents = int(vat_amount.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))
        self.line_total_cents = subtotal + self.tax_cents
        return self.line_total_cents

    @property
    def subtotal_cents(self) -> int:
        """Calculate subtotal (quantity x unit_price) in cents"""
        return int(self.quantity * self.unit_price_cents)

    @property
    def subtotal(self) -> Decimal:
        """Return subtotal in currency units"""
        return Decimal(self.subtotal_cents) / 100

    @property
    def unit_price(self) -> Decimal:
        return Decimal(self.unit_price_cents) / 100

    @property
    def line_total(self) -> Decimal:
        return Decimal(self.line_total_cents) / 100
