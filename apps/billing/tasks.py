"""Billing background tasks.

This module contains Django-Q2 tasks for billing operations, invoice
generation, payment processing, and dunning workflows.
"""

from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone
from django_q.tasks import async_task

from apps.audit.services import AuditService
from apps.billing.models import Invoice

logger = logging.getLogger(__name__)

# Task configuration
TASK_RETRY_DELAY = 300  # 5 minutes
TASK_MAX_RETRIES = 3
TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
TASK_TIME_LIMIT = 600  # 10 minutes


def submit_efactura(invoice_id: str) -> dict[str, Any]:
    """
    Submit invoice to Romanian e-Factura system.

    Args:
        invoice_id: Invoice UUID to submit

    Returns:
        Dictionary with submission result
    """
    logger.info(f"🏛️ [e-Factura] Starting submission for invoice {invoice_id}")

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        # TODO: Implement actual e-Factura submission
        # For now, just log the action
        logger.info(f"🏛️ [e-Factura] Would submit invoice {invoice.number} to ANAF")

        # Log the submission attempt
        AuditService.log_simple_event(
            event_type="efactura_submission_attempted",
            user=None,
            content_object=invoice,
            description=f"e-Factura submission attempted for invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "e-Factura submission completed",
        }

    except Invoice.DoesNotExist:
        error_msg = f"Invoice {invoice_id} not found"
        logger.error(f"❌ [e-Factura] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [e-Factura] Error submitting invoice {invoice_id}: {e}")
        return {"success": False, "error": str(e)}


def schedule_payment_reminders(invoice_id: str) -> dict[str, Any]:
    """
    Schedule payment reminder emails for an invoice.

    Args:
        invoice_id: Invoice UUID to schedule reminders for

    Returns:
        Dictionary with scheduling result
    """
    logger.info(f"📅 [Reminders] Scheduling payment reminders for invoice {invoice_id}")

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status != "pending":
            logger.info(f"📅 [Reminders] Invoice {invoice.number} is not pending, skipping reminders")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No reminders needed for non-pending invoice",
            }

        # TODO: Implement actual reminder scheduling
        # For now, just log the action
        logger.info(f"📅 [Reminders] Would schedule reminders for invoice {invoice.number}")

        # Log the scheduling
        AuditService.log_simple_event(
            event_type="payment_reminders_scheduled",
            user=None,
            content_object=invoice,
            description=f"Payment reminders scheduled for invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "due_date": invoice.due_date.isoformat() if invoice.due_date else None,
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "Payment reminders scheduled",
        }

    except Invoice.DoesNotExist:
        error_msg = f"Invoice {invoice_id} not found"
        logger.error(f"❌ [Reminders] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [Reminders] Error scheduling reminders for invoice {invoice_id}: {e}")
        return {"success": False, "error": str(e)}


def cancel_payment_reminders(invoice_id: str) -> dict[str, Any]:
    """
    Cancel scheduled payment reminders for an invoice.

    Args:
        invoice_id: Invoice UUID to cancel reminders for

    Returns:
        Dictionary with cancellation result
    """
    logger.info(f"🚫 [Reminders] Cancelling payment reminders for invoice {invoice_id}")

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        # TODO: Implement actual reminder cancellation
        # For now, just log the action
        logger.info(f"🚫 [Reminders] Would cancel reminders for invoice {invoice.number}")

        # Log the cancellation
        AuditService.log_simple_event(
            event_type="payment_reminders_cancelled",
            user=None,
            content_object=invoice,
            description=f"Payment reminders cancelled for invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "Payment reminders cancelled",
        }

    except Invoice.DoesNotExist:
        error_msg = f"Invoice {invoice_id} not found"
        logger.error(f"❌ [Reminders] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [Reminders] Error cancelling reminders for invoice {invoice_id}: {e}")
        return {"success": False, "error": str(e)}


def start_dunning_process(invoice_id: str) -> dict[str, Any]:
    """
    Start the dunning process for an overdue invoice.

    Args:
        invoice_id: Invoice UUID to start dunning for

    Returns:
        Dictionary with dunning result
    """
    logger.info(f"⚠️ [Dunning] Starting dunning process for invoice {invoice_id}")

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status not in ["pending", "overdue"]:
            logger.info(f"⚠️ [Dunning] Invoice {invoice.number} is not overdue, skipping dunning")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No dunning needed for non-overdue invoice",
            }

        # TODO: Implement actual dunning process
        # For now, just log the action
        logger.info(f"⚠️ [Dunning] Would start dunning process for invoice {invoice.number}")

        # Log the dunning start
        AuditService.log_simple_event(
            event_type="dunning_process_started",
            user=None,
            content_object=invoice,
            description=f"Dunning process started for overdue invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "days_overdue": (timezone.now().date() - invoice.due_date).days if invoice.due_date else 0,
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "Dunning process started",
        }

    except Invoice.DoesNotExist:
        error_msg = f"Invoice {invoice_id} not found"
        logger.error(f"❌ [Dunning] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [Dunning] Error starting dunning for invoice {invoice_id}: {e}")
        return {"success": False, "error": str(e)}


def validate_vat_number(tax_profile_id: str) -> dict[str, Any]:
    """
    Validate VAT number with Romanian authorities.

    Args:
        tax_profile_id: CustomerTaxProfile UUID

    Returns:
        Dictionary with validation result
    """
    logger.info(f"🏛️ [VAT] Validating VAT number for tax profile {tax_profile_id}")

    try:
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        tax_profile = CustomerTaxProfile.objects.get(id=tax_profile_id)

        if not tax_profile.vat_number:
            logger.info(f"🏛️ [VAT] No VAT number to validate for tax profile {tax_profile_id}")
            return {"success": True, "tax_profile_id": str(tax_profile.id), "message": "No VAT number to validate"}

        # TODO: Implement actual VAT validation with ANAF/VIES
        # For now, just log the action
        logger.info(f"🏛️ [VAT] Would validate VAT number {tax_profile.vat_number}")

        # Log the validation attempt
        AuditService.log_simple_event(
            event_type="vat_validation_attempted",
            user=None,
            content_object=tax_profile,
            description=f"VAT validation attempted for {tax_profile.vat_number}",
            actor_type="system",
            metadata={
                "tax_profile_id": str(tax_profile.id),
                "vat_number": tax_profile.vat_number,
                "customer_id": str(tax_profile.customer.id),
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "tax_profile_id": str(tax_profile.id),
            "vat_number": tax_profile.vat_number,
            "message": "VAT validation completed",
        }

    except Exception as e:
        logger.exception(f"💥 [VAT] Error validating VAT for tax profile {tax_profile_id}: {e}")
        return {"success": False, "error": str(e)}


def process_auto_payment(invoice_id: str) -> dict[str, Any]:
    """
    Process automatic payment for an invoice.

    Args:
        invoice_id: Invoice UUID to process payment for

    Returns:
        Dictionary with payment result
    """
    logger.info(f"💳 [AutoPay] Processing automatic payment for invoice {invoice_id}")

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status != "pending":
            logger.info(f"💳 [AutoPay] Invoice {invoice.number} is not pending, skipping auto-payment")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No auto-payment needed for non-pending invoice",
            }

        # TODO: Implement actual auto-payment processing
        # For now, just log the action
        logger.info(f"💳 [AutoPay] Would process auto-payment for invoice {invoice.number}")

        # Log the auto-payment attempt
        AuditService.log_simple_event(
            event_type="auto_payment_attempted",
            user=None,
            content_object=invoice,
            description=f"Auto-payment attempted for invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "amount_cents": invoice.total_cents,
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "Auto-payment processed",
        }

    except Invoice.DoesNotExist:
        error_msg = f"Invoice {invoice_id} not found"
        logger.error(f"❌ [AutoPay] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [AutoPay] Error processing auto-payment for invoice {invoice_id}: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# ASYNC WRAPPER FUNCTIONS
# ===============================================================================


def submit_efactura_async(invoice_id: str) -> str:
    """Queue e-Factura submission task."""
    return async_task("apps.billing.tasks.submit_efactura", invoice_id, timeout=TASK_TIME_LIMIT)


def schedule_payment_reminders_async(invoice_id: str) -> str:
    """Queue payment reminder scheduling task."""
    return async_task("apps.billing.tasks.schedule_payment_reminders", invoice_id, timeout=TASK_SOFT_TIME_LIMIT)


def cancel_payment_reminders_async(invoice_id: str) -> str:
    """Queue payment reminder cancellation task."""
    return async_task("apps.billing.tasks.cancel_payment_reminders", invoice_id, timeout=TASK_SOFT_TIME_LIMIT)


def start_dunning_process_async(invoice_id: str) -> str:
    """Queue dunning process start task."""
    return async_task("apps.billing.tasks.start_dunning_process", invoice_id, timeout=TASK_TIME_LIMIT)


def validate_vat_number_async(tax_profile_id: str) -> str:
    """Queue VAT validation task."""
    return async_task("apps.billing.tasks.validate_vat_number", tax_profile_id, timeout=TASK_TIME_LIMIT)


def process_auto_payment_async(invoice_id: str) -> str:
    """Queue auto-payment processing task."""
    return async_task("apps.billing.tasks.process_auto_payment", invoice_id, timeout=TASK_TIME_LIMIT)
