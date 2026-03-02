"""
Audit integration for e-Factura operations.

Provides comprehensive audit logging for all e-Factura events:
- XML generation
- Submission attempts
- Status changes
- Acceptance/Rejection
- Deadline alerts

Uses the existing PRAHO audit infrastructure.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.utils import timezone

if TYPE_CHECKING:
    from apps.billing.efactura.models import EFacturaDocument
    from apps.billing.efactura.validator import ValidationResult
    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)

CRITICAL_DEADLINE_HOURS = 12


class EFacturaAuditService:
    """
    Audit logging service for e-Factura operations.

    All methods are static and handle their own error handling
    to ensure audit failures don't break business operations.
    """

    @staticmethod
    def log_xml_generated(
        invoice: Invoice,
        document: EFacturaDocument,
        xml_hash: str = "",
    ) -> None:
        """Log successful XML generation."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                BillingAuditService,
                BusinessEventData,
            )

            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="invoice_xml_generated",
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system"),
                description=f"e-Factura XML generated for invoice {invoice.number}",
                metadata={
                    "efactura_document_id": str(document.id),
                    "xml_hash": xml_hash or document.xml_hash,
                    "document_type": document.document_type,
                    "environment": document.environment,
                },
            )
            BillingAuditService.log_invoice_event(event_data)
            logger.debug(f"Audit: XML generated for {invoice.number}")

        except Exception as e:
            logger.warning(f"Failed to log XML generation audit: {e}")

    @staticmethod
    def log_validation_result(
        invoice: Invoice,
        document: EFacturaDocument,
        validation_result: ValidationResult,
    ) -> None:
        """Log XML validation result."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditService,
                ComplianceEventRequest,
            )

            status = "success" if validation_result.is_valid else "validation_failed"
            error_count = len(validation_result.errors)
            warning_count = len(validation_result.warnings)

            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=(
                    f"e-Factura XML validation: {invoice.number} - "
                    f"{'Valid' if validation_result.is_valid else f'{error_count} errors'}"
                ),
                status=status,
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "is_valid": validation_result.is_valid,
                    "error_count": error_count,
                    "warning_count": warning_count,
                    "errors": [e.to_dict() for e in validation_result.errors[:10]],  # Limit to 10
                    "warnings": [w.to_dict() for w in validation_result.warnings[:10]],
                },
            )
            AuditService.log_compliance_event(compliance_request)

        except Exception as e:
            logger.warning(f"Failed to log validation audit: {e}")

    @staticmethod
    def log_submission_attempt(
        invoice: Invoice,
        document: EFacturaDocument,
        success: bool,
        upload_index: str = "",
        error_message: str = "",
    ) -> None:
        """Log e-Factura submission attempt."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                AuditService,
                BillingAuditService,
                BusinessEventData,
                ComplianceEventRequest,
            )

            event_type = "efactura_submitted" if success else "efactura_submission_failed"

            # Log as business event
            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type=event_type,
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system", severity="medium" if success else "high"),  # type: ignore[call-arg]
                description=f"e-Factura {'submitted' if success else 'submission failed'}: {invoice.number}",
                metadata={
                    "document_id": str(document.id),
                    "upload_index": upload_index,
                    "environment": document.environment,
                    "retry_count": document.retry_count,
                    "error_message": error_message if not success else "",
                },
            )
            BillingAuditService.log_invoice_event(event_data)

            # Log as compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura submission {'successful' if success else 'failed'}: {invoice.number}",
                status="success" if success else "failed",
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "upload_index": upload_index,
                    "environment": document.environment,
                    "submission_timestamp": timezone.now().isoformat(),
                    "error_message": error_message,
                },
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(f"Audit: Submission {'success' if success else 'failed'} for {invoice.number}")

        except Exception as e:
            logger.warning(f"Failed to log submission audit: {e}")

    @staticmethod
    def log_status_change(
        invoice: Invoice,
        document: EFacturaDocument,
        old_status: str,
        new_status: str,
    ) -> None:
        """Log e-Factura status change."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                BillingAuditService,
                BusinessEventData,
            )

            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="invoice_status_changed",
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system"),
                old_values={"efactura_status": old_status},
                new_values={"efactura_status": new_status},
                description=f"e-Factura status: {old_status} → {new_status}",
                metadata={
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                },
            )
            BillingAuditService.log_invoice_event(event_data)

        except Exception as e:
            logger.warning(f"Failed to log status change audit: {e}")

    @staticmethod
    def log_accepted(
        invoice: Invoice,
        document: EFacturaDocument,
        download_id: str = "",
    ) -> None:
        """Log e-Factura acceptance by ANAF."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                AuditService,
                BillingAuditService,
                BusinessEventData,
                ComplianceEventRequest,
            )

            # Log as business event
            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="efactura_accepted",
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system"),
                description=f"e-Factura accepted by ANAF: {invoice.number}",
                metadata={
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                    "download_id": download_id or document.anaf_download_id,
                    "environment": document.environment,
                    "processing_time_seconds": (
                        (document.response_at - document.submitted_at).total_seconds()
                        if document.response_at and document.submitted_at
                        else None
                    ),
                },
            )
            BillingAuditService.log_invoice_event(event_data)

            # Log as compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura accepted: {invoice.number}",
                status="success",
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                    "download_id": download_id,
                    "acceptance_timestamp": timezone.now().isoformat(),
                },
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(f"Audit: e-Factura accepted for {invoice.number}")

        except Exception as e:
            logger.warning(f"Failed to log acceptance audit: {e}")

    @staticmethod
    def log_rejected(
        invoice: Invoice,
        document: EFacturaDocument,
        errors: list[dict[str, Any]],
    ) -> None:
        """Log e-Factura rejection by ANAF."""
        try:
            from apps.audit.models import AuditAlert  # noqa: PLC0415
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                AuditService,
                BillingAuditService,
                BusinessEventData,
                ComplianceEventRequest,
            )

            # Log as business event with high severity
            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="efactura_rejected",
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system", severity="high"),  # type: ignore[call-arg]
                description=f"e-Factura rejected by ANAF: {invoice.number} - {len(errors)} errors",
                metadata={
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                    "environment": document.environment,
                    "error_count": len(errors),
                    "errors": errors[:10],  # Limit to 10 errors
                },
            )
            BillingAuditService.log_invoice_event(event_data)

            # Log as compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura rejected: {invoice.number}",
                status="failed",
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "upload_index": document.anaf_upload_index,
                    "errors": errors,
                    "rejection_timestamp": timezone.now().isoformat(),
                },
            )
            AuditService.log_compliance_event(compliance_request)

            # Create audit alert
            AuditAlert.objects.create(
                alert_type="compliance_violation",
                severity="high",
                title=f"e-Factura Rejected: {invoice.number}",
                description=f"ANAF rejected invoice {invoice.number} with {len(errors)} validation errors",
                status="open",
            )

            logger.warning(f"Audit: e-Factura rejected for {invoice.number}")

        except Exception as e:
            logger.warning(f"Failed to log rejection audit: {e}")

    @staticmethod
    def log_retry_scheduled(
        invoice: Invoice,
        document: EFacturaDocument,
        retry_count: int,
        next_retry_at: Any,
    ) -> None:
        """Log retry scheduling."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                BillingAuditService,
                BusinessEventData,
            )

            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="efactura_submitted",  # Reuse existing event type
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system"),
                description=f"e-Factura retry scheduled: {invoice.number} (attempt {retry_count})",
                metadata={
                    "document_id": str(document.id),
                    "retry_count": retry_count,
                    "next_retry_at": next_retry_at.isoformat() if next_retry_at else None,
                    "last_error": document.last_error[:500] if document.last_error else "",
                },
            )
            BillingAuditService.log_invoice_event(event_data)

        except Exception as e:
            logger.warning(f"Failed to log retry audit: {e}")

    @staticmethod
    def log_deadline_warning(
        invoice: Invoice,
        document: EFacturaDocument,
        hours_remaining: float,
    ) -> None:
        """Log deadline warning."""
        try:
            from apps.audit.models import AuditAlert  # noqa: PLC0415
            from apps.audit.services import (  # noqa: PLC0415
                AuditService,
                ComplianceEventRequest,
            )

            # Log as compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=invoice.number,
                description=f"e-Factura deadline approaching: {invoice.number} ({hours_remaining:.1f}h remaining)",
                status="warning",
                evidence={
                    "invoice_id": str(invoice.id),
                    "document_id": str(document.id),
                    "hours_remaining": hours_remaining,
                    "deadline": document.submission_deadline.isoformat() if document.submission_deadline else None,
                    "current_status": document.status,
                },
            )
            AuditService.log_compliance_event(compliance_request)

            # Create or update alert
            severity = "critical" if hours_remaining < CRITICAL_DEADLINE_HOURS else "high"
            AuditAlert.objects.update_or_create(
                alert_type="compliance_violation",
                title=f"e-Factura Deadline: {invoice.number}",
                defaults={
                    "severity": severity,
                    "description": (
                        f"Invoice {invoice.number} must be submitted to e-Factura within {hours_remaining:.1f} hours"
                    ),
                    "status": "open",
                },
            )

        except Exception as e:
            logger.warning(f"Failed to log deadline warning: {e}")

    @staticmethod
    def log_download_completed(
        invoice: Invoice,
        document: EFacturaDocument,
        file_path: str,
    ) -> None:
        """Log successful response download."""
        try:
            from apps.audit.services import (  # noqa: PLC0415
                AuditContext,
                BillingAuditService,
                BusinessEventData,
            )

            event_data = BusinessEventData(  # type: ignore[call-arg]
                event_type="invoice_pdf_generated",  # Reuse existing type
                business_object=invoice,
                user=None,
                context=AuditContext(actor_type="system"),
                description=f"e-Factura PDF downloaded: {invoice.number}",
                metadata={
                    "document_id": str(document.id),
                    "file_path": file_path,
                    "download_id": document.anaf_download_id,
                },
            )
            BillingAuditService.log_invoice_event(event_data)

        except Exception as e:
            logger.warning(f"Failed to log download audit: {e}")
