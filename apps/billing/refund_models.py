"""
Refund models for PRAHO Platform
Comprehensive refund tracking with Romanian compliance and audit trails.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import ClassVar

from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .currency_models import Currency
from .validators import validate_financial_amount, validate_financial_json, validate_financial_text_field

# ===============================================================================
# REFUND MODELS
# ===============================================================================


class Refund(models.Model):
    """
    Comprehensive refund tracking model.
    Supports both order and invoice refunds with audit trails and Romanian compliance.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", _("Pending")),
        ("processing", _("Processing")),
        ("approved", _("Approved")),
        ("completed", _("Completed")),
        ("rejected", _("Rejected")),
        ("failed", _("Failed")),
        ("cancelled", _("Cancelled")),
    )

    TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("full", _("Full Refund")),
        ("partial", _("Partial Refund")),
    )

    REASON_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("customer_request", _("Customer Request")),
        ("error_correction", _("Error Correction")),
        ("dispute", _("Dispute")),
        ("service_failure", _("Service Failure")),
        ("duplicate_payment", _("Duplicate Payment")),
        ("fraud", _("Fraud")),
        ("cancellation", _("Cancellation")),
        ("downgrade", _("Downgrade")),
        ("administrative", _("Administrative")),
    )

    # Primary key
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Core relationships - either order OR invoice (not both)
    customer = models.ForeignKey("customers.Customer", on_delete=models.RESTRICT, related_name="refunds")
    order = models.ForeignKey("orders.Order", on_delete=models.RESTRICT, null=True, blank=True, related_name="refunds")
    invoice = models.ForeignKey(
        "billing.Invoice", on_delete=models.RESTRICT, null=True, blank=True, related_name="refunds"
    )
    payment = models.ForeignKey(
        "billing.Payment", on_delete=models.SET_NULL, null=True, blank=True, related_name="refunds"
    )

    # Refund details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    refund_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default="full")
    reason = models.CharField(max_length=50, choices=REASON_CHOICES, default="customer_request")

    # Financial amounts
    amount_cents = models.BigIntegerField(validators=[MinValueValidator(1)])
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    original_amount_cents = models.BigIntegerField(help_text=_("Original transaction amount for reference"))

    # External references
    gateway_refund_id = models.CharField(max_length=255, blank=True, help_text=_("Payment gateway refund ID"))
    reference_number = models.CharField(max_length=100, unique=True, help_text=_("Unique refund reference number"))

    # Descriptive fields
    reason_description = models.TextField(blank=True, help_text=_("Detailed reason for refund"))
    internal_notes = models.TextField(blank=True, help_text=_("Internal notes not visible to customer"))

    # Processing details
    processed_at = models.DateTimeField(null=True, blank=True, help_text=_("When refund was actually processed"))
    gateway_processed_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When gateway confirmed processing")
    )

    # Metadata and audit
    metadata = models.JSONField(default=dict, blank=True, help_text=_("Additional refund metadata"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Audit fields
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, related_name="created_refunds")
    approved_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_refunds"
    )
    processed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="processed_refunds"
    )

    class Meta:
        db_table = "refunds"
        verbose_name = _("Refund")
        verbose_name_plural = _("Refunds")
        indexes = (
            models.Index(fields=["customer", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["refund_type"]),
            models.Index(fields=["reason"]),
            models.Index(fields=["gateway_refund_id"]),
            models.Index(fields=["reference_number"]),
            models.Index(fields=["order"]),
            models.Index(fields=["invoice"]),
            models.Index(fields=["payment"]),
        )
        constraints: ClassVar[list] = [
            # Ensure either order OR invoice is specified, not both
            models.CheckConstraint(
                check=(
                    (models.Q(order__isnull=False) & models.Q(invoice__isnull=True))
                    | (models.Q(order__isnull=True) & models.Q(invoice__isnull=False))
                ),
                name="refund_order_or_invoice_not_both",
            ),
            # Ensure refund amount is positive
            models.CheckConstraint(check=models.Q(amount_cents__gt=0), name="refund_amount_positive"),
        ]

    def __str__(self) -> str:
        entity = f"Order {self.order.id}" if self.order else f"Invoice {self.invoice.id}"
        return f"Refund {self.reference_number} - {entity} - {self.amount} {self.currency.code}"

    def clean(self) -> None:
        """Validate refund data"""
        super().clean()

        # Validate financial amounts
        validate_financial_amount(self.amount_cents, "Refund amount")
        validate_financial_amount(self.original_amount_cents, "Original amount")

        # Validate text fields
        validate_financial_text_field(self.reason_description, "Reason description")
        validate_financial_text_field(self.internal_notes, "Internal notes")
        validate_financial_text_field(self.reference_number, "Reference number", 100)

        # Validate metadata
        validate_financial_json(self.metadata, "Refund metadata")

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Auto-generate reference number if not provided
        if not self.reference_number:
            self.reference_number = f"REF-{timezone.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Set processed_at when status changes to completed
        if self.status == "completed" and not self.processed_at:
            self.processed_at = timezone.now()

        super().save(*args, **kwargs)

    @property
    def amount(self) -> Decimal:
        """Refund amount as Decimal"""
        return Decimal(self.amount_cents) / 100

    @property
    def original_amount(self) -> Decimal:
        """Original amount as Decimal"""
        return Decimal(self.original_amount_cents) / 100

    @property
    def is_partial(self) -> bool:
        """Check if this is a partial refund"""
        return self.refund_type == "partial"

    @property
    def is_full(self) -> bool:
        """Check if this is a full refund"""
        return self.refund_type == "full"

    @property
    def entity_type(self) -> str:
        """Get the type of entity being refunded"""
        return "order" if self.order else "invoice"

    @property
    def entity_id(self) -> str:
        """Get the ID of the entity being refunded"""
        return str(self.order.id) if self.order else str(self.invoice.id)

    def get_entity(self) -> Any:
        """Get the actual entity being refunded"""
        return self.order if self.order else self.invoice


class RefundNote(models.Model):
    """
    Notes and comments on refunds for audit trail and communication.
    Supports both internal notes and customer-visible comments.
    """

    NOTE_TYPES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("internal", _("Internal Note")),
        ("customer", _("Customer Communication")),
        ("gateway", _("Gateway Response")),
        ("system", _("System Generated")),
    )

    # Primary key
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationships
    refund = models.ForeignKey(Refund, on_delete=models.CASCADE, related_name="notes")
    
    # Note details
    note_type = models.CharField(max_length=20, choices=NOTE_TYPES, default="internal")
    title = models.CharField(max_length=200, blank=True, help_text=_("Optional note title"))
    content = models.TextField(help_text=_("Note content"))
    
    # Visibility
    is_customer_visible = models.BooleanField(default=False, help_text=_("Whether customer can see this note"))
    
    # Metadata
    metadata = models.JSONField(default=dict, blank=True, help_text=_("Additional note metadata"))
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Audit
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, related_name="refund_notes")

    class Meta:
        db_table = "refund_notes"
        verbose_name = _("Refund Note")
        verbose_name_plural = _("Refund Notes")
        indexes = (
            models.Index(fields=["refund", "-created_at"]),
            models.Index(fields=["note_type", "-created_at"]),
            models.Index(fields=["is_customer_visible", "-created_at"]),
        )
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"Note on {self.refund.reference_number} - {self.note_type} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    def clean(self) -> None:
        """Validate note data"""
        super().clean()
        
        # Validate text fields
        validate_financial_text_field(self.title, "Note title", 200)
        validate_financial_text_field(self.content, "Note content")
        
        # Validate metadata
        validate_financial_json(self.metadata, "Note metadata")


class RefundStatusHistory(models.Model):
    """
    Track status changes for refunds for complete audit trail.
    Critical for Romanian compliance and dispute resolution.
    """

    # Primary key
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationships
    refund = models.ForeignKey(Refund, on_delete=models.CASCADE, related_name="status_history")

    # Status change details
    previous_status = models.CharField(max_length=20, choices=Refund.STATUS_CHOICES, blank=True, default='')
    new_status = models.CharField(max_length=20, choices=Refund.STATUS_CHOICES)
    change_reason = models.TextField(blank=True, help_text=_("Reason for status change"))

    # Metadata
    metadata = models.JSONField(default=dict, blank=True, help_text=_("Additional status change metadata"))

    # Timestamps
    changed_at = models.DateTimeField(auto_now_add=True)

    # Audit
    changed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, related_name="refund_status_changes"
    )

    class Meta:
        db_table = "refund_status_history"
        verbose_name = _("Refund Status History")
        verbose_name_plural = _("Refund Status Histories")
        indexes = (
            models.Index(fields=["refund", "-changed_at"]),
            models.Index(fields=["new_status", "-changed_at"]),
        )
        ordering = ("-changed_at",)

    def __str__(self) -> str:
        change = f"{self.previous_status} → {self.new_status}" if self.previous_status else f"Initial → {self.new_status}"
        return f"{self.refund.reference_number}: {change}"

    def clean(self) -> None:
        """Validate status history data"""
        super().clean()
        
        # Validate text fields
        validate_financial_text_field(self.change_reason, "Change reason")
        
        # Validate metadata
        validate_financial_json(self.metadata, "Status change metadata")
