"""
e-Factura Webhook Processor

Tracks ANAF e-Factura responses via the WebhookEvent system for
deduplication, audit trails, and status monitoring.

Unlike Stripe (which pushes webhooks), ANAF responses are polled.
This processor records polled responses as WebhookEvent records so
the existing deduplication and retry infrastructure applies.
"""

import logging
from typing import Any

from apps.integrations.models import WebhookEvent

from .base import BaseWebhookProcessor

logger = logging.getLogger(__name__)


class EFacturaWebhookProcessor(BaseWebhookProcessor):
    """
    📄 e-Factura webhook processor with deduplication

    Handles ANAF e-Factura response events:
    - efactura.status.accepted  → Document accepted by ANAF
    - efactura.status.rejected  → Document rejected (validation errors)
    - efactura.status.processing → ANAF still validating
    - efactura.status.error     → System error during status check
    """

    source_name = "efactura"

    def extract_event_id(self, payload: dict[str, Any]) -> str | None:
        """Extract ANAF upload index as unique event identifier."""
        upload_index = payload.get("anaf_upload_index", "") or payload.get("index_incarcare", "")
        status = payload.get("status", "unknown")
        if not upload_index:
            return None
        # Combine upload_index + status for unique event ID per status change
        return f"{upload_index}_{status}"

    def extract_event_type(self, payload: dict[str, Any]) -> str | None:
        """Extract event type from ANAF response status."""
        status = payload.get("status", "")
        if not status:
            return None
        return f"efactura.status.{status}"

    def verify_signature(
        self,
        payload: dict[str, Any],
        signature: str,
        headers: dict[str, str],
        raw_body: bytes | None = None,
    ) -> bool:
        """Verify event authenticity by checking upload_index exists in our system.

        ANAF responses are polled (not pushed), so there's no cryptographic
        signature to verify. Instead, we validate that the upload_index
        corresponds to a document in our database, proving the event
        originated from our own polling code.
        """
        upload_index = payload.get("anaf_upload_index", "") or payload.get("index_incarcare", "")
        if not upload_index:
            return False

        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        return EFacturaDocument.objects.filter(anaf_upload_index=upload_index).exists()

    def handle_event(self, webhook_event: WebhookEvent) -> tuple[bool, str]:
        """Process ANAF response event.

        Since status updates are already handled by EFacturaService.check_status(),
        this processor mainly serves as an audit/deduplication record.
        The actual document status transitions happen before the webhook is recorded.
        """
        upload_index = (
            webhook_event.payload.get("anaf_upload_index", "")
            or webhook_event.payload.get("index_incarcare", "")
        )
        status = webhook_event.payload.get("status", "unknown")
        document_id = webhook_event.payload.get("document_id", "")

        logger.info(
            f"✅ [e-Factura] Recorded ANAF response: upload_index={upload_index}, "
            f"status={status}, document={document_id}"
        )
        return True, f"Recorded e-Factura status update: {status} for {upload_index}"


def record_anaf_response(
    document_id: str,
    anaf_upload_index: str,
    status: str,
    response_data: dict[str, Any] | None = None,
) -> WebhookEvent | None:
    """
    Record an ANAF response as a WebhookEvent for audit and deduplication.

    Call this from EFacturaService.check_status() when a terminal status
    (accepted/rejected) is received.

    Args:
        document_id: UUID of the EFacturaDocument
        anaf_upload_index: ANAF index_incarcare
        status: Response status (accepted, rejected, processing, error)
        response_data: Raw ANAF response data

    Returns:
        Created WebhookEvent or None if duplicate
    """
    event_id = f"{anaf_upload_index}_{status}"

    if WebhookEvent.is_duplicate("efactura", event_id):
        logger.info(f"🔄 [e-Factura] Duplicate response skipped: {event_id}")
        return None

    payload = {
        "document_id": str(document_id),
        "anaf_upload_index": anaf_upload_index,
        "status": status,
        **(response_data or {}),
    }

    webhook_event = WebhookEvent.objects.create(
        source="efactura",
        event_id=event_id,
        event_type=f"efactura.status.{status}",
        payload=payload,
        status="processed",
    )

    logger.info(f"✅ [e-Factura] Recorded ANAF response: {event_id}")
    return webhook_event
