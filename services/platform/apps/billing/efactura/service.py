"""
e-Factura service for managing the complete submission workflow.

This service orchestrates:
- XML generation
- Validation
- ANAF submission
- Status polling
- Response handling
- Audit logging

Usage:
    from apps.billing.efactura import EFacturaService

    service = EFacturaService()
    result = service.submit_invoice(invoice)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from apps.billing.fiscal_identity import normalize_country_code

from .client import (
    AuthenticationError,
    EFacturaClient,
    EFacturaClientError,
    NetworkError,
)
from .models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from .validator import CIUSROValidator, ValidationResult
from .xml_builder import UBLCreditNoteBuilder, UBLInvoiceBuilder, XMLBuilderError

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)


@dataclass
class SubmissionResult:
    """Result of e-Factura submission."""

    success: bool
    document: EFacturaDocument | None = None
    error_message: str = ""
    errors: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def ok(cls, document: EFacturaDocument) -> SubmissionResult:
        return cls(success=True, document=document)

    @classmethod
    def error(cls, message: str, errors: list[dict[str, Any]] | None = None) -> SubmissionResult:
        return cls(success=False, error_message=message, errors=errors or [])


@dataclass
class StatusCheckResult:
    """Result of status check."""

    status: str
    is_terminal: bool = False
    download_id: str = ""
    errors: list[dict[str, Any]] = field(default_factory=list)


class EFacturaService:
    """
    High-level service for e-Factura operations.

    This service provides a simple interface for:
    - Submitting invoices to ANAF
    - Checking submission status
    - Downloading responses
    - Handling retries
    """

    def __init__(self, client: EFacturaClient | None = None):
        self._client = client or EFacturaClient()
        self._validator = CIUSROValidator()

    @property
    def client(self) -> EFacturaClient:
        return self._client

    # --- Main Workflow Methods ---

    @transaction.atomic
    def submit_invoice(self, invoice: Invoice, validate_first: bool = False) -> SubmissionResult:  # noqa: C901, PLR0911, PLR0912, PLR0915  # Complexity: multi-step business logic
        """
        Submit an invoice to e-Factura.

        This method:
        1. Creates or gets EFacturaDocument
        2. Generates XML
        3. Validates XML (optional)
        4. Submits to ANAF
        5. Updates document status
        6. Logs audit events

        Args:
            invoice: Invoice to submit
            validate_first: Whether to validate XML before submission

        Returns:
            SubmissionResult with success/failure info
        """
        # Check if e-Factura is enabled
        if not self._is_efactura_enabled():
            return SubmissionResult.error("e-Factura is disabled in settings")

        # Check if invoice requires e-Factura
        if not self._requires_efactura(invoice):
            return SubmissionResult.error("Invoice does not require e-Factura submission")

        # Idempotency / lifecycle decisions BEFORE any work.
        existing = self._get_existing_document(invoice)
        if existing and existing.status in {
            EFacturaStatus.SUBMITTED.value,
            EFacturaStatus.PROCESSING.value,
            EFacturaStatus.ACCEPTED.value,
        }:
            # Already in flight at ANAF (or accepted) — never re-POST the same fiscal invoice.
            return SubmissionResult.ok(existing)
        if existing and existing.status == EFacturaStatus.REJECTED.value:
            # ANAF rejected it; the same document must not be re-uploaded (duplicate POST). The
            # invoice must be corrected and a NEW e-Factura document created.
            return SubmissionResult.error(
                "Invoice was rejected by ANAF; correct it and submit a new e-Factura document"
            )

        document = existing  # so the except blocks can mark the just-created document as error
        try:
            # Route classification is compliance-critical. A malformed fiscal
            # snapshot must fail the submission, never silently use /upload.
            is_b2c = self._is_b2c(invoice)

            # Create or update document
            document = self._get_or_create_document(invoice)

            # Queue before upload so the post-upload mark_submitted() transition is valid.
            # FSM: mark_submitted() requires source QUEUED. A freshly created document is DRAFT;
            # without this, a SUCCESSFUL ANAF upload was followed by TransitionNotAllowed, the
            # error was swallowed, and the upload_index was lost -> double-send on retry.
            if document.status in {EFacturaStatus.DRAFT.value, EFacturaStatus.ERROR.value}:
                document.mark_queued()
                document.save()

            # Generate XML
            xml_content = self._generate_xml(invoice, document)
            if not xml_content:
                return SubmissionResult.error("Failed to generate XML")

            # Validate if requested
            if validate_first:
                validation = self._validate_xml(xml_content)
                if not validation.is_valid:
                    error_dicts = [e.to_dict() for e in validation.errors]
                    document.mark_error(f"XML validation failed: {len(validation.errors)} errors")
                    document.save()
                    self._log_audit_event(invoice, document, "efactura_validation_failed")
                    return SubmissionResult.error(
                        f"XML validation failed: {len(validation.errors)} errors",
                        errors=error_dicts,
                    )

            # Consumer invoices use ANAF's dedicated endpoint. Since 1 June 2026, Romanian
            # consumers who do not provide a fiscal identifier are represented in the UBL buyer
            # party with the statutory 13-zero identifier generated by the XML builder.
            is_credit_note = document.document_type == EFacturaDocumentType.CREDIT_NOTE.value
            if is_b2c and is_credit_note:
                response = self._client.upload_b2c(xml_content, standard="CN")
            elif is_b2c:
                response = self._client.upload_b2c(xml_content)
            elif is_credit_note:
                response = self._client.upload_credit_note(xml_content)
            else:
                response = self._client.upload_invoice(xml_content)

            if response.success:
                document.mark_submitted(response.upload_index)
                document.save()
                self._log_audit_event(invoice, document, "efactura_submitted")
                logger.info(f"e-Factura submitted for invoice {invoice.number}: {response.upload_index}")
                return SubmissionResult.ok(document)
            else:
                document.mark_error(response.message)
                document.save()
                self._log_audit_event(invoice, document, "efactura_submission_failed")
                return SubmissionResult.error(response.message, [{"message": e} for e in response.errors])

        except XMLBuilderError as e:
            logger.error(f"XML generation failed for invoice {invoice.number}: {e}")
            if document:
                document.mark_error(str(e))
                document.save()
            return SubmissionResult.error(f"XML generation failed: {e}")

        except AuthenticationError as e:
            logger.error(f"Authentication failed for invoice {invoice.number}: {e}")
            if document:
                document.mark_error(str(e))
                document.save()
            return SubmissionResult.error(f"Authentication failed: {e}")

        except NetworkError as e:
            logger.error(f"Network error for invoice {invoice.number}: {e}")
            if document:
                document.mark_error(str(e))
                document.save()
            return SubmissionResult.error(f"Network error: {e}")

        except Exception as e:
            logger.exception(f"Unexpected error submitting invoice {invoice.number}")
            if document:
                document.mark_error(str(e))
                document.save()
            return SubmissionResult.error(f"Unexpected error: {e}")

    def check_status(self, document: EFacturaDocument) -> StatusCheckResult:
        """
        Check the status of a submitted document.

        Args:
            document: EFacturaDocument to check

        Returns:
            StatusCheckResult with current status
        """
        if not document.anaf_upload_index:
            return StatusCheckResult(status="error", errors=[{"message": "No upload index"}])

        try:
            response = self._client.get_upload_status(document.anaf_upload_index)

            if response.is_accepted:
                with transaction.atomic():
                    document.mark_accepted(response.download_id, response.raw_response)
                    document.save()
                    document._update_invoice_on_acceptance()
                self._log_audit_event(document.invoice, document, "efactura_accepted")
                self._record_webhook_event(document, "accepted", response.raw_response)
                return StatusCheckResult(
                    status="accepted",
                    is_terminal=True,
                    download_id=response.download_id,
                )

            elif response.is_rejected:
                with transaction.atomic():
                    document.mark_rejected(response.errors, response.raw_response)
                    document.save()
                self._log_audit_event(document.invoice, document, "efactura_rejected")
                self._record_webhook_event(document, "rejected", response.raw_response)
                return StatusCheckResult(
                    status="rejected",
                    is_terminal=True,
                    errors=response.errors,
                )

            elif response.is_processing:
                document.mark_processing()
                document.save()
                return StatusCheckResult(status="processing", is_terminal=False)

            else:
                return StatusCheckResult(status=response.status, is_terminal=False)

        except EFacturaClientError as e:
            logger.error(f"Status check failed for document {document.id}: {e}")
            return StatusCheckResult(status="error", errors=[{"message": str(e)}])

    def download_response(self, document: EFacturaDocument) -> bytes | None:
        """
        Download the ANAF response (signed PDF) for accepted document.

        Args:
            document: Accepted EFacturaDocument

        Returns:
            PDF content as bytes, or None if failed
        """
        if not document.anaf_download_id:
            logger.warning(f"No download ID for document {document.id}")
            return None

        try:
            content = self._client.download_response(document.anaf_download_id)

            # Save to document
            filename = f"efactura_{document.invoice.number}.pdf"
            document.signed_pdf.save(filename, ContentFile(content), save=True)

            logger.info(f"Downloaded response for document {document.id}")
            return content

        except EFacturaClientError as e:
            logger.error(f"Download failed for document {document.id}: {e}")
            return None

    def retry_failed_submission(self, document: EFacturaDocument) -> SubmissionResult:
        """
        Retry a failed submission.

        Args:
            document: Failed EFacturaDocument to retry

        Returns:
            SubmissionResult
        """
        if not document.can_retry:
            return SubmissionResult.error("Document cannot be retried (max retries exceeded or wrong status)")

        with transaction.atomic():
            # Use FSM transition to queue for resubmission
            document.mark_queued()
            document.save()
            return self.submit_invoice(document.invoice, validate_first=True)

    # --- Batch Operations ---

    def process_pending_submissions(self, limit: int = 100) -> dict[str, int]:
        """
        Process queued documents waiting for submission.

        Returns:
            Summary of processed documents
        """
        pending = EFacturaDocument.get_pending_submissions(limit)
        results = {"submitted": 0, "failed": 0, "skipped": 0}

        for document in pending:
            result = self.submit_invoice(document.invoice)
            if result.success:
                results["submitted"] += 1
            else:
                results["failed"] += 1

        return results

    def poll_awaiting_documents(self, limit: int = 100) -> dict[str, int]:
        """
        Poll status for documents awaiting ANAF response.

        Returns:
            Summary of polled documents
        """
        awaiting = EFacturaDocument.get_awaiting_response(limit)
        results = {"accepted": 0, "rejected": 0, "processing": 0, "error": 0}

        for document in awaiting:
            status_result = self.check_status(document)
            if status_result.status in results:
                results[status_result.status] += 1
            else:
                results["error"] += 1

        return results

    def process_retries(self) -> dict[str, int]:
        """
        Process documents ready for retry.

        Returns:
            Summary of retried documents
        """
        ready = EFacturaDocument.get_ready_for_retry()
        results = {"retried": 0, "failed": 0}

        for document in ready:
            result = self.retry_failed_submission(document)
            if result.success:
                results["retried"] += 1
            else:
                results["failed"] += 1

        return results

    def check_approaching_deadlines(self, hours: int = 24) -> list[EFacturaDocument]:
        """
        Find invoices approaching the submission deadline.

        Args:
            hours: Hours before deadline to alert

        Returns:
            List of documents approaching deadline
        """
        from apps.billing.invoice_models import Invoice  # noqa: PLC0415  # Deferred: avoids circular import
        from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

        deadline_days = SettingsService.get_integer_setting("billing.efactura_submission_deadline_days", 5)

        # Coarse pre-filter on issue date: a WORKING-day deadline spans MORE calendar days than the
        # raw count (weekends + holidays are skipped), so look back generously and let the precise,
        # working-day-aware per-document deadline check below do the real filtering.
        # NOTE: `+7` buffer assumes deadline_days <= 5. The worst calendar span for 5 working days
        # is the Easter cluster (Good Friday + 2 weekends + Easter Monday) = 5 + 4 skipped = 9 days,
        # plus a 24h warning window comfortably fits in 12 (5+7). If deadline_days is ever raised,
        # widen this buffer proportionally (rule-of-thumb: deadline_days + max(holiday_cluster_span)).
        now = timezone.now()
        warning_days = (max(0, hours) + 23) // 24
        lookback = timedelta(days=deadline_days + 7 + warning_days)

        invoices = Invoice.objects.filter(
            issued_at__gte=now - lookback,
            issued_at__lte=now,
            bill_to_country__iexact="RO",
            status__in=["issued", "paid", "overdue", "void", "refunded", "partially_refunded"],
        ).exclude(efactura_document__status=EFacturaStatus.ACCEPTED.value)

        approaching = []
        for invoice in invoices:
            # Recover visibility when the issue signal or task queue failed
            # before an EFacturaDocument was created.
            doc = self._get_existing_document(invoice) or self._get_or_create_document(invoice)
            deadline = doc.submission_deadline
            if deadline is not None and now >= deadline - timedelta(hours=max(0, hours)):
                approaching.append(doc)

        return approaching

    # --- Helper Methods ---

    def _is_efactura_enabled(self) -> bool:
        """Check if e-Factura is enabled in settings."""
        return getattr(settings, "EFACTURA_ENABLED", False)

    def _is_b2c(self, invoice: Invoice) -> bool:
        """Whether this invoice routes to ANAF's B2C (/uploadb2c) endpoint.

        A Romanian buyer without a business tax identifier is a consumer for endpoint routing.
        Detection errors propagate to submit_invoice(), which records a failed
        submission instead of risking the wrong ANAF endpoint.
        """
        from apps.billing.efactura.b2c import B2CDetector  # noqa: PLC0415  # avoids import cycle

        return B2CDetector().is_b2c_required(invoice)

    def _requires_efactura(self, invoice: Invoice) -> bool:
        """Return whether a PRAHO invoice falls within mandatory Romanian submission.

        PRAHO issues invoices rather than fiscal-register receipts, so the narrow
        simplified-receipt exception does not create an amount threshold here.
        Romanian B2B and B2C invoices are both mandatory regardless of total.
        """
        return normalize_country_code(invoice.bill_to_country) == "RO"

    def _get_existing_document(self, invoice: Invoice) -> EFacturaDocument | None:
        """Get existing e-Factura document for invoice."""
        try:
            return invoice.efactura_document
        except EFacturaDocument.DoesNotExist:
            return None

    def _get_or_create_document(self, invoice: Invoice) -> EFacturaDocument:
        """Get or create EFacturaDocument for invoice."""
        document, _created = EFacturaDocument.objects.get_or_create(
            invoice=invoice,
            defaults={
                "document_type": EFacturaDocumentType.INVOICE.value,
                "status": EFacturaStatus.DRAFT.value,
                "environment": getattr(settings, "EFACTURA_ENVIRONMENT", "test"),
            },
        )
        return document

    def _generate_xml(self, invoice: Invoice, document: EFacturaDocument) -> str | None:
        """Generate UBL XML for invoice."""
        try:
            builder: UBLInvoiceBuilder | UBLCreditNoteBuilder
            if document.document_type == EFacturaDocumentType.CREDIT_NOTE.value:
                # Get original invoice for credit note reference
                original = getattr(invoice, "original_invoice", None)
                builder = UBLCreditNoteBuilder(invoice, original)
            else:
                builder = UBLInvoiceBuilder(invoice)

            xml_content = builder.build()

            # Update document
            document.xml_content = xml_content
            document.xml_generated_at = timezone.now()
            document.save(update_fields=["xml_content", "xml_hash", "xml_generated_at", "updated_at"])

            # Save XML file
            filename = f"{invoice.number}.xml"
            document.xml_file.save(filename, ContentFile(xml_content.encode("utf-8")), save=True)

            return xml_content

        except XMLBuilderError:
            raise
        except Exception as e:
            logger.exception(f"XML generation failed for invoice {invoice.number}")
            raise XMLBuilderError(f"Failed to generate XML: {e}") from e

    def _validate_xml(self, xml_content: str) -> ValidationResult:
        """Validate XML against CIUS-RO rules."""
        return self._validator.validate(xml_content)

    def _log_audit_event(
        self,
        invoice: Invoice,
        document: EFacturaDocument,
        event_type: str,
    ) -> None:
        """Log e-Factura event to audit system."""
        try:
            from apps.audit.services import (  # noqa: PLC0415  # Deferred: circular import
                AuditService,
                ComplianceEventRequest,
            )

            status_map = {
                "efactura_submitted": "success",
                "efactura_accepted": "success",
                "efactura_rejected": "failed",
                "efactura_validation_failed": "validation_failed",
                "efactura_submission_failed": "failed",
            }

            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura {event_type.replace('efactura_', '')}: {invoice.number}",
                status=status_map.get(event_type, "unknown"),
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                    "environment": document.environment,
                    "retry_count": document.retry_count,
                },
            )
            AuditService.log_compliance_event(compliance_request)

        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

    def _record_webhook_event(
        self,
        document: EFacturaDocument,
        status: str,
        response_data: dict[str, Any] | None = None,
    ) -> None:
        """Record ANAF response as WebhookEvent for deduplication and audit."""
        try:
            from apps.integrations.webhooks.efactura import (  # noqa: PLC0415
                record_anaf_response,
            )

            record_anaf_response(
                document_id=str(document.id),
                anaf_upload_index=document.anaf_upload_index,
                status=status,
                response_data=response_data,
            )
        except Exception as e:
            logger.warning(f"⚠️ [e-Factura] Failed to record webhook event: {e}")


# Convenience function for quick submission
def submit_invoice_to_efactura(invoice: Invoice) -> SubmissionResult:
    """
    Submit an invoice to e-Factura.

    Convenience function for use in signals and tasks.

    Args:
        invoice: Invoice to submit

    Returns:
        SubmissionResult
    """
    service = EFacturaService()
    return service.submit_invoice(invoice)
