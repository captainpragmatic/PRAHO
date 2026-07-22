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

import hashlib
import logging
import uuid
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
    validate_response_archive,
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

    @property
    def document_status(self) -> str:
        """Return the persisted lifecycle state, if this result carries a document."""
        return self.document.status if self.document else ""

    @property
    def registered_with_anaf(self) -> bool:
        """Whether PRAHO has recorded proof that ANAF registered this document."""
        return self.document_status in {
            EFacturaStatus.SUBMITTED.value,
            EFacturaStatus.PROCESSING.value,
            EFacturaStatus.ACCEPTED.value,
        }


@dataclass
class StatusCheckResult:
    """Result of status check."""

    status: str
    is_terminal: bool = False
    download_id: str = ""
    errors: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class SubmissionClaim:
    """Committed ownership and immutable bytes for one ANAF upload attempt."""

    document_id: uuid.UUID
    token: uuid.UUID
    xml_content: str
    xml_hash: str
    is_b2c: bool
    is_credit_note: bool


class EFacturaService:
    """
    High-level service for e-Factura operations.

    This service provides a simple interface for:
    - Submitting invoices to ANAF
    - Checking submission status
    - Downloading responses
    - Handling retries
    """

    SUBMISSION_CLAIM_LEASE = timedelta(minutes=10)

    def __init__(self, client: EFacturaClient | None = None):
        self._client = client or EFacturaClient()
        self._validator = CIUSROValidator()

    @property
    def client(self) -> EFacturaClient:
        return self._client

    # --- Main Workflow Methods ---

    def submit_invoice(self, invoice: Invoice) -> SubmissionResult:  # noqa: C901, PLR0911, PLR0912  # Complexity: multi-step business logic
        """
        Submit an invoice to e-Factura.

        This method:
        1. Creates or gets EFacturaDocument
        2. Generates XML
        3. Validates XML with the native CIUS-RO business-rule validator
        4. Submits to ANAF
        5. Updates document status
        6. Logs audit events

        Args:
            invoice: Invoice to submit
        Returns:
            SubmissionResult with success/failure info
        """
        # Check if e-Factura is enabled
        if not self._is_efactura_enabled():
            return SubmissionResult.error("e-Factura is disabled in settings")

        # Check if invoice requires e-Factura
        if not self._requires_efactura(invoice):
            return SubmissionResult.error("Invoice does not require e-Factura submission")

        try:
            claim_or_result = self._prepare_and_claim_submission(invoice)
        except XMLBuilderError as e:
            logger.error(f"XML generation failed for invoice {invoice.number}: {e}")
            return SubmissionResult.error(f"XML generation failed: {e}")
        except Exception as e:
            logger.exception(f"Unexpected local error preparing invoice {invoice.number} for e-Factura")
            return SubmissionResult.error(f"Unexpected local error: {e}")

        if isinstance(claim_or_result, SubmissionResult):
            return claim_or_result
        claim = claim_or_result

        try:
            if claim.is_b2c and claim.is_credit_note:
                response = self._client.upload_b2c(claim.xml_content, standard="CN")
            elif claim.is_b2c:
                response = self._client.upload_b2c(claim.xml_content)
            elif claim.is_credit_note:
                response = self._client.upload_credit_note(claim.xml_content)
            else:
                response = self._client.upload_invoice(claim.xml_content)
        except AuthenticationError as e:
            logger.error(f"Authentication failed for invoice {invoice.number}: {e}")
            return self._finalize_safe_failure(claim, f"Authentication failed: {e}")
        except NetworkError as e:
            logger.error(f"Network error for invoice {invoice.number}: {e}")
            return self._finalize_unknown_outcome(claim, f"ANAF upload outcome unknown: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error submitting invoice {invoice.number}")
            return self._finalize_unknown_outcome(claim, f"ANAF upload outcome unknown: {e}")

        if response.success:
            result = self._finalize_success(claim, response.upload_index)
            if result.success:
                logger.info(f"e-Factura submitted for invoice {invoice.number}: {response.upload_index}")
            return result
        return self._finalize_safe_failure(
            claim,
            response.message,
            errors=[{"message": error} for error in response.errors],
        )

    @transaction.atomic
    def _prepare_and_claim_submission(  # noqa: C901, PLR0911  # Explicit fail-closed lifecycle guards.
        self, invoice: Invoice
    ) -> SubmissionClaim | SubmissionResult:
        """Lock, re-read, prepare immutable XML, and commit exclusive upload ownership."""
        from apps.billing.invoice_models import Invoice  # noqa: PLC0415

        locked_invoice = Invoice.objects.select_for_update(of=("self",)).get(pk=invoice.pk)
        document, _created = EFacturaDocument.objects.select_for_update().get_or_create(
            invoice=locked_invoice,
            defaults={
                "document_type": EFacturaDocumentType.INVOICE.value,
                "status": EFacturaStatus.DRAFT.value,
                "environment": getattr(settings, "EFACTURA_ENVIRONMENT", "test"),
            },
        )
        now = timezone.now()

        if document.status in {
            EFacturaStatus.SUBMITTED.value,
            EFacturaStatus.PROCESSING.value,
            EFacturaStatus.ACCEPTED.value,
        }:
            return SubmissionResult.ok(document)
        if document.status == EFacturaStatus.REJECTED.value:
            return SubmissionResult.error(
                "Invoice was rejected by ANAF; correct it and submit a new e-Factura document"
            )
        if document.status == EFacturaStatus.OUTCOME_UNKNOWN.value:
            return SubmissionResult.error(
                "ANAF upload outcome is unknown; reconcile ANAF messages before any resubmission"
            )
        if document.status == EFacturaStatus.UPLOADING.value:
            if document.submission_claim_expires_at and document.submission_claim_expires_at > now:
                return SubmissionResult.ok(document)
            document.mark_outcome_unknown("Submission worker claim expired before a local ANAF result was recorded")
            document.save()
            self._log_audit_event(locked_invoice, document, "efactura_outcome_unknown")
            return SubmissionResult.error(
                "ANAF upload outcome is unknown; reconcile ANAF messages before any resubmission"
            )

        if document.status not in {
            EFacturaStatus.DRAFT.value,
            EFacturaStatus.ERROR.value,
            EFacturaStatus.QUEUED.value,
        }:
            return SubmissionResult.error(f"Document cannot be submitted from status {document.status}")

        xml_content = document.xml_content
        should_regenerate_after_local_error = (
            document.status == EFacturaStatus.ERROR.value and document.submission_claimed_at is None
        )
        if not xml_content or should_regenerate_after_local_error:
            try:
                xml_content = self._generate_xml(locked_invoice, document)
            except XMLBuilderError as e:
                document.mark_local_error(str(e))
                document.save()
                return SubmissionResult.error(f"XML generation failed: {e}")

            if document.xml_content != xml_content:
                document.xml_content = xml_content
                document.xml_generated_at = timezone.now()
                document.save(update_fields=["xml_content", "xml_hash", "xml_generated_at", "updated_at"])
        elif not document.verify_xml_integrity():
            document.mark_local_error("Stored e-Factura XML failed its SHA-256 integrity check")
            document.save()
            return SubmissionResult.error("Stored e-Factura XML failed its integrity check")

        validation = self._validate_xml(xml_content)
        if not validation.is_valid:
            error_dicts = [error.to_dict() for error in validation.errors]
            error_message = f"XML validation failed: {len(validation.errors)} errors"
            document.mark_local_error(error_message, error_dicts)
            document.save()
            self._log_audit_event(locked_invoice, document, "efactura_validation_failed")
            return SubmissionResult.error(error_message, errors=error_dicts)

        is_b2c = self._is_b2c(locked_invoice)
        if document.status in {EFacturaStatus.DRAFT.value, EFacturaStatus.ERROR.value}:
            document.mark_queued()
        claim_token = uuid.uuid4()
        claimed_at = timezone.now()
        document.mark_uploading(
            claim_token=claim_token,
            claimed_at=claimed_at,
            claim_expires_at=claimed_at + self.SUBMISSION_CLAIM_LEASE,
        )
        document.save()
        self._log_audit_event(locked_invoice, document, "efactura_upload_claimed")
        return SubmissionClaim(
            document_id=document.id,
            token=claim_token,
            xml_content=document.xml_content,
            xml_hash=document.xml_hash,
            is_b2c=is_b2c,
            is_credit_note=document.document_type == EFacturaDocumentType.CREDIT_NOTE.value,
        )

    def _lock_owned_claim(self, claim: SubmissionClaim) -> EFacturaDocument | None:
        document = EFacturaDocument.objects.select_for_update().select_related("invoice").get(pk=claim.document_id)
        if document.status != EFacturaStatus.UPLOADING.value or document.submission_claim_token != claim.token:
            return None
        return document

    @transaction.atomic
    def _finalize_success(self, claim: SubmissionClaim, upload_index: str) -> SubmissionResult:
        document = self._lock_owned_claim(claim)
        if document is None:
            return SubmissionResult.error("e-Factura submission claim is no longer owned by this worker")
        if document.xml_hash != claim.xml_hash or not document.verify_xml_integrity():
            document.mark_outcome_unknown("Claimed XML integrity changed before ANAF success could be recorded")
            document.save()
            self._log_audit_event(document.invoice, document, "efactura_outcome_unknown")
            return SubmissionResult.error("ANAF upload outcome is unknown because the claimed XML changed")
        document.mark_submitted(upload_index)
        document.save()
        self._log_audit_event(document.invoice, document, "efactura_submitted")
        return SubmissionResult.ok(document)

    @transaction.atomic
    def _finalize_safe_failure(
        self,
        claim: SubmissionClaim,
        message: str,
        *,
        errors: list[dict[str, Any]] | None = None,
    ) -> SubmissionResult:
        document = self._lock_owned_claim(claim)
        if document is None:
            return SubmissionResult.error("e-Factura submission claim is no longer owned by this worker")
        document.mark_error(message)
        document.save()
        self._log_audit_event(document.invoice, document, "efactura_submission_failed")
        return SubmissionResult.error(message, errors)

    @transaction.atomic
    def _finalize_unknown_outcome(self, claim: SubmissionClaim, message: str) -> SubmissionResult:
        document = self._lock_owned_claim(claim)
        if document is None:
            return SubmissionResult.error("e-Factura submission claim is no longer owned by this worker")
        document.mark_outcome_unknown(message)
        document.save()
        self._log_audit_event(document.invoice, document, "efactura_outcome_unknown")
        return SubmissionResult.error(message)

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
                if self.download_response(document) is None:
                    logger.error(f"Accepted e-Factura response archive could not be stored for document {document.id}")
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
        Download, validate, and archive the exact ANAF response ZIP.

        Args:
            document: Accepted EFacturaDocument

        Returns:
            Exact ZIP bytes, or None if download/validation failed
        """
        if not document.anaf_download_id:
            logger.warning(f"No download ID for document {document.id}")
            return None
        if document.status != EFacturaStatus.ACCEPTED.value:
            logger.warning(f"Cannot archive ANAF response for non-accepted document {document.id}")
            return None

        try:
            if document.verify_response_archive_integrity():
                with document.response_archive.open("rb") as existing:
                    return bytes(existing.read())

            content = self._client.download_response(document.anaf_download_id)
            validate_response_archive(content)

            filename = f"efactura_{document.id}.zip"
            document.response_archive.save(filename, ContentFile(content), save=False)
            document.response_archive_sha256 = hashlib.sha256(content).hexdigest()
            document.response_archive_downloaded_at = timezone.now()
            document.save(
                update_fields=[
                    "response_archive",
                    "response_archive_sha256",
                    "response_archive_downloaded_at",
                    "updated_at",
                ]
            )

            logger.info(f"Downloaded and archived ANAF response ZIP for document {document.id}")
            return content

        except (EFacturaClientError, OSError) as e:
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
        if not (document.can_retry or document.can_requeue_after_fix):
            return SubmissionResult.error("Document cannot be retried (max retries exceeded or wrong status)")

        # submit_invoice() owns the short claim transaction. Do not wrap the ANAF POST in an
        # outer transaction or pre-transition a stale document instance.
        return self.submit_invoice(document.invoice)

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
            if result.success and result.registered_with_anaf:
                results["submitted"] += 1
            elif result.success:
                results["skipped"] += 1
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

    def process_missing_response_archives(self, limit: int = 100) -> dict[str, int]:
        """Recover accepted ANAF responses not archived on the original status-poll path."""
        missing = EFacturaDocument.get_missing_response_archives(limit)
        results = {"archived": 0, "failed": 0}

        for document in missing:
            if self.download_response(document) is not None:
                results["archived"] += 1
            else:
                results["failed"] += 1

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

    def _generate_xml(self, invoice: Invoice, document: EFacturaDocument) -> str:
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
                "efactura_upload_claimed": "in_progress",
                "efactura_submitted": "success",
                "efactura_accepted": "success",
                "efactura_rejected": "failed",
                "efactura_validation_failed": "validation_failed",
                "efactura_submission_failed": "failed",
                "efactura_outcome_unknown": "needs_reconciliation",
            }

            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura {event_type.replace('efactura_', '')}: {invoice.number}",
                status=status_map.get(event_type, "unknown"),
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "document_status": document.status,
                    "upload_index": document.anaf_upload_index,
                    "xml_hash": document.xml_hash,
                    "submission_claimed_at": (
                        document.submission_claimed_at.isoformat() if document.submission_claimed_at else None
                    ),
                    "submission_claim_expires_at": (
                        document.submission_claim_expires_at.isoformat()
                        if document.submission_claim_expires_at
                        else None
                    ),
                    "environment": document.environment,
                    "retry_count": document.retry_count,
                },
            )
            # The savepoint isolates audit-storage failures from the surrounding claim/finalize
            # transaction. Catching a database error without this nested atomic block would leave
            # the outer transaction rollback-only and could silently discard the durable claim.
            with transaction.atomic():
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
