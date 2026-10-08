"""
Async tasks for e-Factura operations.

These tasks are designed for use with Django-Q2:
- submit_efactura_task: Submit single invoice
- poll_efactura_status_task: Check status of pending submissions
- process_efactura_retries_task: Retry failed submissions
- check_efactura_deadlines_task: Alert on approaching deadlines

Usage:
    from django_q.tasks import async_task
    async_task('apps.billing.efactura.tasks.submit_efactura_task', invoice_id)
"""

from __future__ import annotations

import logging
from typing import Any, NamedTuple

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.audit.models import AuditAlert

from .settings import EFacturaSettings

logger = logging.getLogger(__name__)

# Expose imports at module scope for patching in tests
try:
    from apps.billing.invoice_models import Invoice

    InvoiceDoesNotExist = Invoice.DoesNotExist
except Exception:  # pragma: no cover - import guard for test/runtime isolation
    Invoice = None  # type: ignore[misc, assignment]
    InvoiceDoesNotExist = Exception  # type: ignore[misc, assignment]

try:
    from django_q.models import Schedule
except Exception:  # pragma: no cover - optional dependency
    Schedule = None

try:
    from django_q.tasks import async_task
except Exception:  # pragma: no cover - optional dependency
    async_task = None

try:
    from .models import EFacturaDocument

    EFacturaDocumentDoesNotExist = EFacturaDocument.DoesNotExist
except Exception:  # pragma: no cover - import guard for test/runtime isolation
    EFacturaDocument = None  # type: ignore[misc, assignment]
    EFacturaDocumentDoesNotExist = Exception  # type: ignore[misc, assignment]

try:
    from .service import EFacturaService
except Exception:  # pragma: no cover - import guard for test/runtime isolation
    EFacturaService = None  # type: ignore[misc, assignment]

# Task timeout in seconds
TASK_TIMEOUT = 300  # 5 minutes

CRITICAL_DEADLINE_HOURS = 12


def submit_efactura_task(invoice_id: str) -> dict[str, Any]:
    """
    Submit a single invoice to e-Factura.

    Args:
        invoice_id: UUID of the invoice to submit

    Returns:
        Dict with result status and details
    """
    if not EFacturaSettings().auto_submit_enabled:
        logger.info("✅ [e-Factura] Automatic submission is disabled for invoice %s", invoice_id)
        return {"success": False, "error": _("Automatic e-Factura submission is disabled"), "invoice_id": invoice_id}

    logger.info(f"[e-Factura Task] Starting submission for invoice {invoice_id}")

    try:
        if Invoice is None:
            raise RuntimeError("Invoice model unavailable")
        invoice = Invoice.objects.get(id=invoice_id)
    except InvoiceDoesNotExist:
        logger.error(f"[e-Factura Task] Invoice {invoice_id} not found")
        return {"success": False, "error": "Invoice not found", "invoice_id": invoice_id}

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    result = service.submit_invoice(invoice)

    if result.success:
        document_status = result.document_status
        message = (
            "e-Factura submission completed"
            if result.registered_with_anaf
            else "e-Factura submission is already in progress"
        )
        logger.info(f"[e-Factura Task] {message} for invoice {invoice.number}")
        return {
            "success": True,
            "invoice_id": invoice_id,
            "invoice_number": invoice.number,
            "status": document_status,
            "message": message,
            "upload_index": (result.document.anaf_upload_index or None) if result.document else None,
        }
    logger.warning(f"[e-Factura Task] Failed to submit invoice {invoice.number}: {result.error_message}")
    return {
        "success": False,
        "invoice_id": invoice_id,
        "invoice_number": invoice.number,
        "error": result.error_message,
        "errors": result.errors,
    }


def poll_efactura_status_task(document_id: str) -> dict[str, Any]:
    """
    Poll status for a single e-Factura document.

    Args:
        document_id: UUID of the EFacturaDocument

    Returns:
        Dict with status result
    """
    logger.info(f"[e-Factura Task] Polling status for document {document_id}")

    try:
        if EFacturaDocument is None:
            raise RuntimeError("EFacturaDocument model unavailable")
        document = EFacturaDocument.objects.select_related("invoice").get(id=document_id)
    except EFacturaDocumentDoesNotExist:
        logger.error(f"[e-Factura Task] Document {document_id} not found")
        return {"success": False, "error": "Document not found", "document_id": document_id}

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    result = service.check_status(document)

    return {
        "success": True,
        "document_id": document_id,
        "invoice_number": document.invoice.number,
        "status": result.status,
        "is_terminal": result.is_terminal,
        "download_id": result.download_id,
        "errors": result.errors,
    }


def poll_all_pending_status_task() -> dict[str, Any]:
    """
    Poll status for all documents awaiting ANAF response.

    This task should be scheduled to run periodically (e.g., every 15 minutes).

    Returns:
        Dict with summary of polled documents
    """
    logger.info("[e-Factura Task] Polling status for all pending documents")

    batch_size = EFacturaSettings().poll_batch_size

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    results = service.poll_awaiting_documents(limit=batch_size)

    logger.info(f"[e-Factura Task] Status poll complete: {results}")
    return {
        "success": True,
        "timestamp": timezone.now().isoformat(),
        **results,
    }


def process_efactura_retries_task() -> dict[str, Any]:
    """
    Process documents ready for retry.

    This task should be scheduled to run periodically (e.g., every hour).

    Returns:
        Dict with summary of retried documents
    """
    logger.info("[e-Factura Task] Processing retries")

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    results = service.process_retries()

    logger.info(f"[e-Factura Task] Retries complete: {results}")
    return {
        "success": True,
        "timestamp": timezone.now().isoformat(),
        **results,
    }


def process_pending_submissions_task() -> dict[str, Any]:
    """
    Process all queued submissions.

    This task should be scheduled to run periodically (e.g., every 5 minutes).

    Returns:
        Dict with summary
    """
    logger.info("[e-Factura Task] Processing pending submissions")

    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    batch_size = SettingsService.get_integer_setting("billing.efactura_batch_size", 100)

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    results = service.process_pending_submissions(limit=batch_size)

    logger.info(f"[e-Factura Task] Submissions complete: {results}")
    return {
        "success": True,
        "timestamp": timezone.now().isoformat(),
        **results,
    }


def check_efactura_deadlines_task() -> dict[str, Any]:
    """
    Check for invoices approaching the submission deadline.

    This task should be scheduled to run daily.

    Returns:
        Dict with list of invoices approaching deadline
    """
    logger.info("[e-Factura Task] Checking e-Factura deadlines")

    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    warning_hours = SettingsService.get_integer_setting("billing.efactura_deadline_warning_hours", 24)

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    approaching = service.check_approaching_deadlines(hours=warning_hours)

    if approaching:
        logger.warning(f"[e-Factura Task] {len(approaching)} invoices approaching deadline!")

        # Create alerts for approaching deadlines
        _create_deadline_alerts(approaching)

    return {
        "success": True,
        "timestamp": timezone.now().isoformat(),
        "approaching_deadline_count": len(approaching),
        "invoice_numbers": [doc.invoice.number for doc in approaching],
    }


def download_efactura_response_task(document_id: str) -> dict[str, Any]:
    """
    Download ANAF response for accepted document.

    Args:
        document_id: UUID of the accepted EFacturaDocument

    Returns:
        Dict with download result
    """
    from .models import EFacturaStatus  # Deferred: django-q task  # noqa: PLC0415  # Deferred: avoids circular import

    logger.info(f"[e-Factura Task] Downloading response for document {document_id}")

    try:
        if EFacturaDocument is None:
            raise RuntimeError("EFacturaDocument model unavailable")
        document = EFacturaDocument.objects.get(id=document_id)
    except EFacturaDocumentDoesNotExist:
        return {"success": False, "error": "Document not found"}

    if document.status != EFacturaStatus.ACCEPTED.value:
        return {"success": False, "error": "Document not accepted yet"}

    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")
    service = EFacturaService()
    content = service.download_response(document)

    if content:
        return {
            "success": True,
            "document_id": document_id,
            "file_path": document.response_archive.name if document.response_archive else None,
        }
    else:
        return {"success": False, "error": "Download failed"}


def archive_missing_efactura_responses_task() -> dict[str, Any]:
    """Daily recovery for accepted documents whose ANAF ZIP evidence is missing."""
    logger.info("[e-Factura Task] Recovering missing ANAF response archives")
    if EFacturaService is None:
        raise RuntimeError("EFacturaService unavailable")

    results = EFacturaService().process_missing_response_archives()
    logger.info(f"[e-Factura Task] Response archive recovery complete: {results}")
    return {
        "success": True,
        "timestamp": timezone.now().isoformat(),
        **results,
    }


def _create_deadline_alerts(approaching_documents: list[Any]) -> None:
    """Create audit alerts for approaching deadlines."""
    try:
        for document in approaching_documents:
            deadline = document.submission_deadline
            hours_remaining = (deadline - timezone.now()).total_seconds() / 3600 if deadline else 0

            AuditAlert.objects.get_or_create(
                alert_type="compliance_violation",
                title=f"e-Factura Deadline: {document.invoice.number}",
                defaults={
                    "severity": "critical" if hours_remaining < CRITICAL_DEADLINE_HOURS else "high",
                    "description": (
                        f"Invoice {document.invoice.number} must be submitted to e-Factura "
                        f"within {hours_remaining:.1f} hours (deadline: {deadline})"
                    ),
                    "status": "open",
                },
            )
    except Exception as e:
        logger.warning(f"Failed to create deadline alerts: {e}")


def reconcile_efactura_documents() -> dict[str, int]:
    """Daily recovery of durable invoice intent, without performing an ANAF upload."""
    from .intents import reconcile_efactura_documents as reconcile  # noqa: PLC0415

    return reconcile()


# --- Task Scheduling Helpers ---


class _ScheduleDefinition(NamedTuple):
    """One Django-Q schedule: its unique name, the task function's name in this module, and its cadence."""

    name: str
    function: str
    schedule_type: str
    minutes: int | None


@transaction.atomic
def schedule_efactura_tasks() -> dict[str, str]:
    """Install schedules even while disabled, so runtime enablement needs no restart."""
    if Schedule is None:
        raise ImportError(_("Django-Q not installed"))
    definitions = (
        _ScheduleDefinition("efactura_poll_status", "poll_all_pending_status_task", Schedule.MINUTES, 15),
        _ScheduleDefinition("efactura_process_retries", "process_efactura_retries_task", Schedule.HOURLY, None),
        _ScheduleDefinition("efactura_process_pending", "process_pending_submissions_task", Schedule.MINUTES, 5),
        _ScheduleDefinition("efactura_check_deadlines", "check_efactura_deadlines_task", Schedule.DAILY, None),
        _ScheduleDefinition(
            "efactura_archive_missing_responses", "archive_missing_efactura_responses_task", Schedule.DAILY, None
        ),
        _ScheduleDefinition("efactura_reconcile_documents", "reconcile_efactura_documents", Schedule.DAILY, None),
    )
    results: dict[str, str] = {}
    for name, function, schedule_type, minutes in definitions:
        _schedule, created = Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": f"apps.billing.efactura.tasks.{function}",
                "schedule_type": schedule_type,
                "minutes": minutes,
            },
        )
        results[name.removeprefix("efactura_")] = "created" if created else "already_exists"
    logger.info("✅ [e-Factura] Scheduled tasks configured")
    return results


# --- Async Task Helpers ---


def queue_efactura_submission(invoice_id: str) -> str | None:
    """
    Queue an invoice for e-Factura submission.

    Args:
        invoice_id: UUID of the invoice

    Returns:
        Task ID if queued, None if failed
    """
    if not EFacturaSettings().auto_submit_enabled:
        logger.info("✅ [e-Factura] Automatic submission is disabled for invoice %s", invoice_id)
        return None
    try:
        if async_task is None:
            raise ImportError("Django-Q not installed")
        task_id = async_task(
            "apps.billing.efactura.tasks.submit_efactura_task",
            str(invoice_id),
            timeout=TASK_TIMEOUT,
        )
        logger.info(f"Queued e-Factura submission for invoice {invoice_id}: task {task_id}")
        return str(task_id)

    except ImportError:
        logger.warning("Django-Q not installed, running synchronously")
        result = submit_efactura_task(str(invoice_id))
        return "sync" if result.get("success") else None
    except Exception as e:
        logger.error(f"Failed to queue e-Factura submission: {e}")
        return None


def queue_status_poll(document_id: str) -> str | None:
    """
    Queue a status poll for a document.

    Args:
        document_id: UUID of the EFacturaDocument

    Returns:
        Task ID if queued, None if failed
    """
    try:
        if async_task is None:
            raise ImportError("Django-Q not installed")
        task_id = async_task(
            "apps.billing.efactura.tasks.poll_efactura_status_task",
            str(document_id),
            timeout=TASK_TIMEOUT,
        )
        return str(task_id)

    except ImportError:
        result = poll_efactura_status_task(str(document_id))
        return "sync" if result.get("success") else None
    except Exception as e:
        logger.error(f"Failed to queue status poll: {e}")
        return None
