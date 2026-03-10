"""
e-Factura document model for tracking ANAF submission lifecycle.

This model tracks the complete lifecycle of e-Factura submissions:
- XML generation
- Upload to ANAF
- Status polling
- Acceptance/Rejection handling
- Retry logic with exponential backoff
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition

if TYPE_CHECKING:
    pass


from apps.settings.services import SettingsService


class EFacturaStatus(StrEnum):
    """e-Factura document status enumeration."""

    DRAFT = "draft"  # XML generated, not submitted
    QUEUED = "queued"  # In Django-Q queue waiting for submission
    SUBMITTED = "submitted"  # Sent to ANAF, awaiting validation
    PROCESSING = "processing"  # ANAF is validating
    ACCEPTED = "accepted"  # ANAF accepted (valid e-Factura)
    REJECTED = "rejected"  # ANAF rejected (validation errors)
    ERROR = "error"  # System error (network, auth, etc.)

    @classmethod
    def choices(cls) -> list[tuple[str, str]]:
        return [(status.value, status.name.replace("_", " ").title()) for status in cls]

    @classmethod
    def terminal_statuses(cls) -> set[str]:
        """Statuses that don't require further processing."""
        return {cls.ACCEPTED.value, cls.REJECTED.value}

    @classmethod
    def retryable_statuses(cls) -> set[str]:
        """Statuses that can be retried."""
        return {cls.ERROR.value, cls.QUEUED.value}


class EFacturaDocumentType(StrEnum):
    """e-Factura document type enumeration."""

    INVOICE = "invoice"
    CREDIT_NOTE = "credit_note"
    DEBIT_NOTE = "debit_note"

    @classmethod
    def choices(cls) -> list[tuple[str, str]]:
        return [(dt.value, dt.name.replace("_", " ").title()) for dt in cls]


class EFacturaDocument(models.Model):
    """
    Track e-Factura submission lifecycle for Romanian compliance.

    This model follows the ANAF API flow:
    generate → validate → upload → poll status → download response

    Integration points:
    - Invoice model (one-to-one relationship)
    - Audit system (via signals)
    - ComplianceLog (for regulatory reporting)
    - WebhookEvent (for deduplication)
    """

    # Retry configuration — class-level fallbacks
    MAX_RETRIES: ClassVar[int] = 5
    RETRY_DELAYS: ClassVar[list[int]] = [300, 900, 3600, 7200, 21600]  # 5m, 15m, 1h, 2h, 6h

    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationship to invoice
    invoice = models.OneToOneField(
        "billing.Invoice",
        on_delete=models.CASCADE,
        related_name="efactura_document",
        help_text=_("The invoice this e-Factura document represents"),
    )

    # Document metadata
    document_type = models.CharField(
        max_length=20,
        choices=EFacturaDocumentType.choices(),
        default=EFacturaDocumentType.INVOICE.value,
        help_text=_("Type of e-Factura document"),
    )

    status = FSMField(
        max_length=20,
        choices=EFacturaStatus.choices(),
        default=EFacturaStatus.DRAFT.value,
        protected=True,
        db_index=True,
        help_text=_("Current status in the submission lifecycle"),
    )

    # ANAF identifiers
    anaf_upload_index = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text=_("ANAF index_incarcare - returned after upload"),
    )

    anaf_download_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("ANAF id_descarcare - available after acceptance"),
    )

    anaf_response_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("ANAF response message ID"),
    )

    # XML storage
    xml_content = models.TextField(
        blank=True,
        help_text=_("Generated UBL 2.1 XML content"),
    )

    xml_file = models.FileField(
        upload_to="efactura/xml/%Y/%m/",
        blank=True,
        null=True,
        help_text=_("Stored XML file path"),
    )

    xml_hash = models.CharField(
        max_length=64,
        blank=True,
        help_text=_("SHA-256 hash of XML content for integrity verification"),
    )

    # Response storage
    anaf_response = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Complete ANAF API response data"),
    )

    validation_errors = models.JSONField(
        default=list,
        blank=True,
        help_text=_("List of validation errors from ANAF"),
    )

    signed_pdf = models.FileField(
        upload_to="efactura/pdf/%Y/%m/",
        blank=True,
        null=True,
        help_text=_("ANAF-signed PDF visualization"),
    )

    # Timestamps
    xml_generated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the XML was generated"),
    )

    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the document was submitted to ANAF"),
    )

    response_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When ANAF responded (accepted/rejected)"),
    )

    # Retry tracking
    retry_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of submission attempts"),
    )

    next_retry_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the next retry should be attempted"),
    )

    last_error = models.TextField(
        blank=True,
        help_text=_("Last error message for debugging"),
    )

    # Environment tracking
    environment = models.CharField(
        max_length=20,
        default="test",
        choices=[("test", "Test/Sandbox"), ("production", "Production")],
        help_text=_("ANAF environment used for submission"),
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_efactura_document"
        verbose_name = _("e-Factura Document")
        verbose_name_plural = _("e-Factura Documents")
        ordering = ["-created_at"]

        indexes = [
            # Query pending/processing documents for status polling
            models.Index(
                fields=["status", "submitted_at"],
                name="efactura_status_submitted_idx",
                condition=Q(status__in=["submitted", "processing"]),
            ),
            # Query documents needing retry
            models.Index(
                fields=["status", "next_retry_at"],
                name="efactura_retry_idx",
                condition=Q(status="error", next_retry_at__isnull=False),
            ),
            # Query by ANAF upload index
            models.Index(fields=["anaf_upload_index"], name="efactura_upload_idx"),
            # Query by invoice
            models.Index(fields=["invoice"], name="efactura_invoice_idx"),
        ]

        constraints = [
            # Ensure only one document per invoice
            models.UniqueConstraint(fields=["invoice"], name="unique_efactura_per_invoice"),
            # FSM: valid status values
            models.CheckConstraint(
                condition=Q(status__in=[s.value for s in EFacturaStatus]),
                name="efactura_valid_status",
            ),
        ]

    def __str__(self) -> str:
        return f"e-Factura {self.invoice.number} [{self.status}]"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save with XML hash computation."""
        if self.xml_content and not self.xml_hash:
            self.xml_hash = self._compute_xml_hash()
        super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Any = None,
        from_queryset: Any = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        See orders.Order.refresh_from_db for the full explanation.
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

    def _compute_xml_hash(self) -> str:
        """Compute SHA-256 hash of XML content."""
        return hashlib.sha256(self.xml_content.encode("utf-8")).hexdigest()

    def verify_xml_integrity(self) -> bool:
        """Verify XML content hasn't been tampered with."""
        if not self.xml_content or not self.xml_hash:
            return False
        return self._compute_xml_hash() == self.xml_hash

    # --- FSM Status Transition Methods (ADR-0034) ---

    @transition(
        field=status,
        source=[EFacturaStatus.DRAFT.value, EFacturaStatus.ERROR.value],
        target=EFacturaStatus.QUEUED.value,
    )
    def mark_queued(self) -> None:
        """Queue document for submission. Also used for retry from error state."""

    @transition(field=status, source=EFacturaStatus.QUEUED.value, target=EFacturaStatus.SUBMITTED.value)
    def mark_submitted(self, upload_index: str) -> None:
        """Mark document as submitted to ANAF."""
        self.anaf_upload_index = upload_index
        self.submitted_at = timezone.now()

    @transition(field=status, source=EFacturaStatus.SUBMITTED.value, target=EFacturaStatus.PROCESSING.value)
    def mark_processing(self) -> None:
        """Mark document as being processed by ANAF."""

    @transition(field=status, source=EFacturaStatus.PROCESSING.value, target=EFacturaStatus.ACCEPTED.value)
    def mark_accepted(self, download_id: str, response: dict[str, Any] | None = None) -> None:
        """Mark document as accepted by ANAF."""
        self.anaf_download_id = download_id
        self.response_at = timezone.now()
        if response:
            self.anaf_response = response

    @transition(field=status, source=EFacturaStatus.PROCESSING.value, target=EFacturaStatus.REJECTED.value)
    def mark_rejected(self, errors: list[dict[str, Any]], response: dict[str, Any] | None = None) -> None:
        """Mark document as rejected by ANAF."""
        self.validation_errors = errors
        self.response_at = timezone.now()
        if response:
            self.anaf_response = response

    @transition(
        field=status,
        source=[
            EFacturaStatus.DRAFT.value,
            EFacturaStatus.QUEUED.value,
            EFacturaStatus.SUBMITTED.value,
            EFacturaStatus.PROCESSING.value,
        ],
        target=EFacturaStatus.ERROR.value,
    )
    def mark_error(self, error_message: str) -> None:
        """Mark document as having an error, schedule retry if possible."""
        self.last_error = error_message
        self.retry_count += 1

        # Schedule retry with exponential backoff
        if self.retry_count <= self.MAX_RETRIES:
            delay_index = min(self.retry_count - 1, len(self.RETRY_DELAYS) - 1)
            delay_seconds = self.RETRY_DELAYS[delay_index]
            self.next_retry_at = timezone.now() + timedelta(seconds=delay_seconds)
        else:
            self.next_retry_at = None  # No more retries

    def _update_invoice_on_acceptance(self) -> None:
        """Update the related invoice when e-Factura is accepted."""
        self.invoice.efactura_id = self.anaf_upload_index
        self.invoice.efactura_sent = True
        self.invoice.efactura_sent_date = self.response_at
        self.invoice.efactura_response = self.anaf_response
        self.invoice.save(update_fields=["efactura_id", "efactura_sent", "efactura_sent_date", "efactura_response"])

    # --- Query Methods ---

    @classmethod
    def get_pending_submissions(cls, limit: int = 100) -> models.QuerySet[EFacturaDocument]:
        """Get documents queued for submission."""
        return cls.objects.filter(status=EFacturaStatus.QUEUED.value).order_by("created_at")[:limit]

    @classmethod
    def get_awaiting_response(cls, limit: int = 100) -> models.QuerySet[EFacturaDocument]:
        """Get documents awaiting ANAF response."""
        return cls.objects.filter(
            status__in=[EFacturaStatus.SUBMITTED.value, EFacturaStatus.PROCESSING.value]
        ).order_by("submitted_at")[:limit]

    @classmethod
    def get_ready_for_retry(cls) -> models.QuerySet[EFacturaDocument]:
        """Get documents ready for retry."""
        now = timezone.now()
        return cls.objects.filter(
            status=EFacturaStatus.ERROR.value, next_retry_at__isnull=False, next_retry_at__lte=now
        ).order_by("next_retry_at")

    @classmethod
    def get_stale_submissions(cls, hours: int = 24) -> models.QuerySet[EFacturaDocument]:
        """Get submissions that have been pending for too long."""
        cutoff = timezone.now() - timedelta(hours=hours)
        return cls.objects.filter(
            status__in=[EFacturaStatus.SUBMITTED.value, EFacturaStatus.PROCESSING.value], submitted_at__lt=cutoff
        )

    # --- Business Logic ---

    @property
    def is_terminal(self) -> bool:
        """Check if document is in a terminal state."""
        return self.status in EFacturaStatus.terminal_statuses()

    @property
    def can_retry(self) -> bool:
        """Check if document can be retried."""
        return self.status in EFacturaStatus.retryable_statuses() and self.retry_count < self.MAX_RETRIES

    @property
    def submission_deadline(self) -> datetime.datetime | None:
        """Calculate the submission deadline from invoice issue date."""
        if self.invoice.issued_at:
            deadline_days = SettingsService.get_integer_setting("billing.efactura_submission_deadline_days", 5)
            return self.invoice.issued_at + timedelta(days=deadline_days)
        return None

    @property
    def is_deadline_approaching(self) -> bool:
        """Check if within warning hours of deadline."""
        deadline = self.submission_deadline
        if deadline:
            warning_hours = SettingsService.get_integer_setting("billing.efactura_deadline_warning_hours", 24)
            return bool(timezone.now() >= deadline - timedelta(hours=warning_hours))
        return False

    @property
    def is_deadline_passed(self) -> bool:
        """Check if deadline has passed."""
        deadline = self.submission_deadline
        if deadline:
            return bool(timezone.now() > deadline)
        return False

    def get_environment_base_url(self) -> str:
        """Get the ANAF API base URL for current environment."""
        if self.environment == "production":
            return getattr(settings, "EFACTURA_PROD_URL", "https://api.anaf.ro/prod/FCTEL/rest")
        return getattr(settings, "EFACTURA_TEST_URL", "https://api.anaf.ro/test/FCTEL/rest")
