"""
Invoice models for PRAHO Platform
Romanian compliant invoice model with address snapshots and immutable ledger.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import date, datetime
from decimal import Decimal
from typing import Any, ClassVar, cast

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, TransitionNotAllowed, transition

from apps.billing.document_adjustments import (
    UnsupportedDocumentAdjustmentError,
    validate_no_unsupported_adjustments,
)
from apps.billing.validators import (
    MAX_ADDRESS_FIELD_LENGTH,
    validate_financial_amount,
    validate_financial_json,
    validate_financial_text_field,
)
from apps.common.cnp_validator import validate_cnp
from apps.common.financial_arithmetic import HasLineTotals, calculate_document_totals, calculate_line_totals
from apps.common.validators import log_security_event

from .currency_models import Currency

logger = logging.getLogger(__name__)


# ===============================================================================
# INVOICE & PROFORMA SEQUENCING
# ===============================================================================


class InvoiceSequence(models.Model):
    """Invoice number sequencing for legal compliance"""

    scope = models.CharField(max_length=50, default="default", unique=True)
    prefix = models.CharField(
        max_length=30,
        default="INV",
        help_text=_("Persisted legal series prefix used for every number issued from this sequence"),
    )
    last_value = models.BigIntegerField(default=0)

    class Meta:
        db_table = "billing_invoice_sequences"
        verbose_name = _("Invoice Sequence")
        verbose_name_plural = _("Invoice Sequences")

    def get_next_number(self, *, user_email: str | None = None) -> str:
        """Get next invoice number and increment sequence atomically with security logging"""
        with transaction.atomic():
            # Log critical financial operation
            old_value = self.last_value

            # Atomic increment using F() expression to prevent race conditions
            InvoiceSequence.objects.filter(pk=self.pk).update(last_value=F("last_value") + 1)
            # Refresh the instance to get the updated value
            self.refresh_from_db()
            new_number = f"{self.prefix}-{self.last_value:06d}"

            # Comprehensive security logging for audit trail
            log_security_event(
                event_type="invoice_number_generated",
                details={
                    "sequence_scope": self.scope,
                    "old_value": old_value,
                    "new_value": self.last_value,
                    "generated_number": new_number,
                    "prefix": self.prefix,
                    "critical_financial_operation": True,
                },
                user_email=user_email,
            )

            return new_number

    @property
    def next_number_preview(self) -> str:
        """Return the next formatted number without consuming it."""
        return f"{self.prefix}-{self.last_value + 1:06d}"

    @property
    def is_archived(self) -> bool:
        """Archived snapshots are evidence, never issuable sequences."""
        return self.scope.startswith("archived:")


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
        ("partially_refunded", _("Partially Refunded")),
    )

    # Core identification
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.RESTRICT,  # Cannot delete customer with invoices
        related_name="invoices",
    )
    number = models.CharField(max_length=50, unique=True, default="TMP-000")  # From InvoiceSequence
    status = FSMField(max_length=20, choices=STATUS_CHOICES, default="draft", protected=True)

    # Currency and amounts (cents for precision)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    exchange_to_ron = models.DecimalField(
        max_digits=18, decimal_places=8, null=True, blank=True, help_text=_("Exchange rate to RON at time of invoice")
    )
    exchange_rate_as_of = models.DateField(null=True, blank=True)
    exchange_rate_source = models.CharField(max_length=32, blank=True)
    exchange_rate_source_reference = models.CharField(max_length=500, blank=True)
    subtotal_cents = models.BigIntegerField(default=0)
    tax_cents = models.BigIntegerField(default=0)
    total_cents = models.BigIntegerField(default=0)
    discount_cents = models.BigIntegerField(
        default=0, help_text=_("Document-level discount in cents (EN16931 BT-92/BT-107)")
    )

    # Dates
    issued_at = models.DateTimeField(null=True, blank=True)
    tax_point_date = models.DateField(
        null=True,
        blank=True,
        help_text=_("VAT tax point used to select the immutable exchange-rate snapshot"),
    )
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
    bill_to_cnp = models.CharField(
        max_length=13,
        blank=True,
        validators=[validate_cnp],
        help_text=_("Romanian personal fiscal identifier snapshotted when the invoice is created"),
    )
    bill_to_registration_number = models.CharField(max_length=50, blank=True)  # Nr. Reg. Com. / J number
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
        db_table = "billing_invoices"
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
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(subtotal_cents__gte=0),
                name="invoice_subtotal_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(tax_cents__gte=0),
                name="invoice_tax_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(total_cents__gte=0),
                name="invoice_total_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(discount_cents__gte=0),
                name="invoice_discount_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=["draft", "issued", "paid", "overdue", "void", "refunded", "partially_refunded"]
                ),
                name="invoice_status_valid_values",
            ),
            models.CheckConstraint(
                condition=models.Q(bill_to_tax_id="") | models.Q(bill_to_cnp=""),
                name="invoice_one_fiscal_id",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.number} - {self.customer}"

    # Fields frozen once invoice is locked (issued).
    _FINANCIAL_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "total_cents",
            "subtotal_cents",
            "tax_cents",
            "discount_cents",
        }
    )
    _BILLING_SNAPSHOT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "bill_to_name",
            "bill_to_tax_id",
            "bill_to_cnp",
            "bill_to_registration_number",
            "bill_to_email",
            "bill_to_address1",
            "bill_to_address2",
            "bill_to_city",
            "bill_to_region",
            "bill_to_postal",
            "bill_to_country",
        }
    )
    _FISCAL_SNAPSHOT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "currency_id",
            "exchange_to_ron",
            "exchange_rate_as_of",
            "exchange_rate_source",
            "exchange_rate_source_reference",
            "issued_at",
            "tax_point_date",
        }
    )
    _LOCKED_FIELDS: ClassVar[frozenset[str]] = _FINANCIAL_FIELDS | _BILLING_SNAPSHOT_FIELDS | _FISCAL_SNAPSHOT_FIELDS

    _ISSUE_TRANSITION_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "issued_at",
            "locked_at",
            "tax_point_date",
            "exchange_to_ron",
            "exchange_rate_as_of",
            "exchange_rate_source",
            "exchange_rate_source_reference",
        }
    )

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Calculate subtotal from total and tax on save with validation"""
        update_fields = kwargs.get("update_fields")
        if update_fields and self.status == "issued" and "status" in update_fields and self.locked_at is not None:
            # A status-only save after issue() must not create an issued row without
            # the fiscal timestamps and exchange-rate evidence set by the transition.
            update_fields = set(update_fields) | self._ISSUE_TRANSITION_FIELDS
            kwargs["update_fields"] = update_fields
        # H2 fix: Skip clean() when update_fields contains no locked fields.
        # This avoids the immutability DB query on status/meta-only saves.
        normalized_update_fields = set(update_fields or ())
        if "currency" in normalized_update_fields:
            normalized_update_fields.add("currency_id")
        if update_fields and not (normalized_update_fields & self._LOCKED_FIELDS):
            self._validate_mutable_update(normalized_update_fields)
            super().save(*args, **kwargs)
            return

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
        validate_financial_amount(self.discount_cents, "Discount amount")

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
            raise ValidationError(_("Financial calculation error: subtotal + tax must equal total"))

        # Validate invoice immutability rules — financial fields are frozen
        # once locked. Status transitions (mark_as_paid, void) are still
        # allowed because they don't alter monetary values.
        if self.locked_at and self.pk:
            locked_field_names = sorted(self._LOCKED_FIELDS)
            db_vals = type(self).objects.filter(pk=self.pk).values("locked_at", *locked_field_names).first()
            if (
                db_vals
                and db_vals["locked_at"] is not None
                and any(getattr(self, field_name) != db_vals[field_name] for field_name in locked_field_names)
            ):
                raise ValidationError(
                    _("Cannot modify financial data on a locked invoice or alter its billing snapshot")
                )

        self._validate_date_consistency()
        self._log_security_validation()

    def _validate_mutable_update(self, update_fields: set[str]) -> None:
        """Validate fields allowed to bypass the locked-invoice database check."""
        if "meta" in update_fields:
            validate_financial_json(self.meta, "Invoice metadata")
        if "efactura_response" in update_fields:
            validate_financial_json(self.efactura_response, "e-Factura response")
        if "due_at" in update_fields:
            self._validate_date_consistency()
        self._log_security_validation()

    def _validate_date_consistency(self) -> None:
        """Keep issue and due dates chronologically valid on every relevant save path."""
        if self.issued_at and self.due_at and self.due_at <= self.issued_at:
            raise ValidationError(_("Due date must be after issue date"))

    def _log_security_validation(self) -> None:
        """Record successful validation for both full and optimized partial saves."""
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
        if self.status != "draft" or self.locked_at is not None:
            raise ValidationError(_("Only an unlocked draft invoice can be recalculated."))
        if self.discount_cents:
            raise ValidationError(_("A discounted invoice cannot be recalculated from undiscounted line totals."))

        lines = list(self.lines.all())
        try:
            validate_no_unsupported_adjustments(
                meta=self.meta,
                line_discount_cents=(line.discount_amount_cents for line in lines),
            )
        except UnsupportedDocumentAdjustmentError as exc:
            raise ValidationError(str(exc)) from exc

        totals = calculate_document_totals(cast(list[HasLineTotals], lines))
        self.subtotal_cents = totals.subtotal_cents
        self.tax_cents = totals.tax_cents
        self.total_cents = totals.total_cents

    def is_overdue(self) -> bool:
        """Check if invoice is overdue"""
        if self.due_at is None or self.status != "issued":
            return False
        now = timezone.now()
        due: date | datetime = self.due_at
        # Handle date vs datetime mismatch (fixtures may store date objects)
        if not isinstance(due, datetime):
            due = datetime.combine(due, datetime.min.time(), tzinfo=now.tzinfo)
        elif timezone.is_naive(due):
            due = timezone.make_aware(due)
        return now > due

    def get_remaining_amount(self) -> int:
        """Calculate remaining unpaid amount in cents, net of completed refunds.

        'succeeded', 'partially_refunded' and 'refunded' payments all represent funds
        that were received; completed refunds are funds returned. Net retained =
        collected - refunded, and the balance due is the invoice total minus that.
        Refunds live in a separate Refund model, so a partially-refunded payment keeps
        its full amount_cents - without this subtraction the balance would understate
        what is still owed after a partial refund.
        """
        from apps.billing.refund_models import Refund  # noqa: PLC0415  -- local import avoids an import cycle

        collected = (
            self.payments.filter(status__in=["succeeded", "partially_refunded", "refunded"]).aggregate(
                total=models.Sum("amount_cents")
            )["total"]
            or 0
        )
        refunded = (
            Refund.objects.filter(
                models.Q(invoice=self) | models.Q(payment__invoice=self),
                status="completed",
            ).aggregate(total=models.Sum("amount_cents"))["total"]
            or 0
        )
        net_collected = max(0, collected - refunded)
        return max(0, self.total_cents - net_collected)

    @transition(field=status, source="draft", target="issued")
    def issue(self) -> None:
        """Issue the invoice and freeze its tax point and FX evidence."""
        if not self.issued_at:
            self.issued_at = timezone.now()
        if self.tax_point_date is None:
            issued_at = self.issued_at
            assert issued_at is not None  # Set immediately above for a draft invoice.
            if timezone.is_naive(issued_at):
                issued_at = timezone.make_aware(issued_at)
            self.tax_point_date = timezone.localdate(issued_at)

        if self.currency_id == "RON":
            self.exchange_to_ron = None
            self.exchange_rate_as_of = None
            self.exchange_rate_source = ""
            self.exchange_rate_source_reference = ""
        else:
            from apps.billing.exchange_rate_service import ExchangeRateError, ExchangeRateService  # noqa: PLC0415

            try:
                snapshot = ExchangeRateService.resolve(self.currency_id, "RON", self.tax_point_date)
            except ExchangeRateError as exc:
                raise ValidationError(
                    {"exchange_to_ron": _("Cannot issue foreign-currency invoice: %(error)s") % {"error": str(exc)}}
                ) from exc
            self.exchange_to_ron = snapshot.rate
            self.exchange_rate_as_of = snapshot.as_of
            self.exchange_rate_source = snapshot.source
            self.exchange_rate_source_reference = snapshot.source_reference
        self.locked_at = timezone.now()

    @transition(field=status, source=["issued", "overdue"], target="paid")
    def mark_as_paid(self) -> None:
        """Mark invoice as paid."""
        self.paid_at = timezone.now()

    @transition(field=status, source="issued", target="overdue")
    def mark_overdue(self) -> None:
        """Mark invoice as overdue."""

    @transition(field=status, source=["draft", "issued", "overdue"], target="void")
    def void(self) -> None:
        """Void the invoice."""

    @transition(field=status, source=["paid", "partially_refunded"], target="refunded")
    def refund_invoice(self) -> None:
        """Mark invoice as fully refunded."""

    @transition(field=status, source=["paid", "partially_refunded"], target="partially_refunded")
    def mark_partially_refunded(self) -> None:
        """Mark invoice as partially refunded."""

    @transition(field=status, source=["partially_refunded", "refunded"], target="paid")
    def restore_after_refund_reversal(self) -> None:
        """Restore an invoice when no completed refund remains."""

    @transition(field=status, source="refunded", target="partially_refunded")
    def restore_partial_after_refund_reversal(self) -> None:
        """Restore an invoice when only part of its completed refund remains."""

    @property
    def amount_due(self) -> int:
        """Calculate remaining amount due after succeeded payments."""
        if self.status == "paid":
            return 0  # Fast path: skip DB aggregate for paid invoices
        return self.get_remaining_amount()

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[Invoice] | None = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        django-fsm protected fields block setattr via the descriptor. Django's
        refresh_from_db uses setattr internally, which would raise AttributeError
        if the field is already in __dict__. Temporarily removing the protected
        field from __dict__ lets Django's setattr path bypass the descriptor
        guard and populate the field from the database.
        """
        fsm_fields = ["status"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    def update_status_from_payments(self) -> None:
        """Update invoice status based on associated payments."""
        if self.status in ("paid", "void", "refunded"):
            return  # Terminal states — do not touch

        remaining = self.amount_due
        if remaining <= 0:
            try:
                self.mark_as_paid()
                self.save(update_fields=["status", "paid_at"])
            except TransitionNotAllowed:
                logger.warning(f"⚠️ [Invoice] Cannot transition {self.number} to paid from status '{self.status}'")
        elif remaining < self.total_cents:
            logger.info(
                f"💰 [Invoice] {self.number} partially paid: {self.total_cents - remaining}/{self.total_cents} cents"
            )


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
    billing_cycle = models.ForeignKey(
        "billing.BillingCycle",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="invoice_lines",
    )

    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=12, decimal_places=3, default=Decimal("1.000"))
    unit_price_cents = models.BigIntegerField(default=0)
    tax_rate = models.DecimalField(
        max_digits=5, decimal_places=4, default=Decimal("0.0000"), help_text=_("Tax rate as decimal (0.21 for 21%)")
    )
    tax_cents = models.BigIntegerField(default=0, help_text=_("Tax amount in cents"))
    line_total_cents = models.BigIntegerField(default=0)

    # EN16931 compliance fields
    domain_name = models.CharField(max_length=255, blank=True, default="", help_text=_("Hosting domain for this line"))
    period_start = models.DateField(null=True, blank=True, help_text=_("Service period start (BT-134)"))
    period_end = models.DateField(null=True, blank=True, help_text=_("Service period end (BT-135)"))
    unit_code = models.CharField(
        max_length=10, blank=True, default="C62", help_text=_("UN/ECE Rec. 20 unit code (BT-130)")
    )
    tax_category_code = models.CharField(
        max_length=5, blank=True, default="S", help_text=_("EU VAT category: S/Z/E/AE/O (BT-151)")
    )
    note = models.TextField(blank=True, default="", help_text=_("Per-line memo (BT-127)"))
    discount_amount_cents = models.BigIntegerField(default=0, help_text=_("Line-level discount in cents (BT-147)"))
    seller_item_id = models.CharField(
        max_length=100, blank=True, default="", help_text=_("Seller product code/SKU (BT-155)")
    )
    sort_order = models.PositiveSmallIntegerField(default=0, help_text=_("Display/XML sequence (BT-126)"))

    class Meta:
        db_table = "billing_invoice_lines"
        verbose_name = _("Invoice Line")
        verbose_name_plural = _("Invoice Lines")
        indexes = (
            models.Index(fields=["service"]),
            models.Index(fields=["billing_cycle"]),
            models.Index(fields=["invoice", "kind"]),
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(unit_price_cents__gte=0),
                name="invoiceline_unit_price_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(tax_cents__gte=0),
                name="invoiceline_tax_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(line_total_cents__gte=0),
                name="invoiceline_line_total_non_negative",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Calculate totals before saving
        self.calculate_totals()
        super().save(*args, **kwargs)

    def calculate_totals(self) -> int:
        """Calculate tax and line total with proper banker's rounding for Romanian VAT compliance."""
        totals = calculate_line_totals(self.subtotal_cents, self.tax_rate)
        self.tax_cents = totals.tax_cents
        self.line_total_cents = totals.line_total_cents
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
