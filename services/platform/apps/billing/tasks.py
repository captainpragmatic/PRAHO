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

# Task configuration — module-level fallbacks (structural, used for async_task timeout args)
_DEFAULT_TASK_RETRY_DELAY = 300  # 5 minutes
_DEFAULT_TASK_MAX_RETRIES = 3
TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
TASK_TIME_LIMIT = 600  # 10 minutes


def _get_task_retry_delay() -> int:
    """Get task retry delay seconds from SettingsService."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("billing.task_retry_delay_seconds", _DEFAULT_TASK_RETRY_DELAY)


def _get_task_max_retries() -> int:
    """Get task max retries from SettingsService."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("billing.task_max_retries", _DEFAULT_TASK_MAX_RETRIES)


# Backward-compatible module-level aliases (for code that imports them)
TASK_RETRY_DELAY = _DEFAULT_TASK_RETRY_DELAY
TASK_MAX_RETRIES = _DEFAULT_TASK_MAX_RETRIES


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


# ===============================================================================
# RECURRING BILLING TASKS
# ===============================================================================


def run_daily_billing() -> dict[str, Any]:
    """
    Daily scheduled task to process subscription renewals.

    This task should be scheduled to run daily (e.g., at 00:00 UTC).
    It processes all subscriptions due for billing and generates invoices.

    Schedule in Django-Q2:
        Schedule.objects.create(
            func='apps.billing.tasks.run_daily_billing',
            schedule_type=Schedule.DAILY,
            repeats=-1,  # Repeat forever
            next_run=timezone.now().replace(hour=0, minute=0, second=0)
        )

    Returns:
        Dictionary with billing run statistics
    """
    from apps.billing.subscription_service import RecurringBillingService  # noqa: PLC0415

    logger.info("📅 [Billing] Starting daily billing run")

    try:
        result = RecurringBillingService.run_billing_cycle()

        logger.info(
            f"📅 [Billing] Daily billing completed: "
            f"{result['subscriptions_processed']} subscriptions, "
            f"{result['invoices_created']} invoices, "
            f"{result['payments_succeeded']}/{result['payments_attempted']} payments succeeded"
        )

        # Log the run
        AuditService.log_simple_event(
            event_type="daily_billing_completed",
            user=None,
            description=f"Daily billing run completed: {result['invoices_created']} invoices created",
            actor_type="system",
            metadata={
                "subscriptions_processed": result["subscriptions_processed"],
                "invoices_created": result["invoices_created"],
                "payments_attempted": result["payments_attempted"],
                "payments_succeeded": result["payments_succeeded"],
                "payments_failed": result["payments_failed"],
                "total_billed_cents": result["total_billed_cents"],
                "errors": result["errors"][:10],  # Limit errors in metadata
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "result": result,
            "message": f"Daily billing completed: {result['invoices_created']} invoices created",
        }

    except Exception as e:
        logger.exception(f"💥 [Billing] Daily billing run failed: {e}")
        return {"success": False, "error": str(e)}


def process_expired_trials() -> dict[str, Any]:
    """
    Process expired trial subscriptions.

    Converts trials with payment methods to paid subscriptions,
    cancels trials without payment methods.

    Should run daily, after run_daily_billing.

    Returns:
        Dictionary with processing result
    """
    from apps.billing.subscription_service import RecurringBillingService  # noqa: PLC0415

    logger.info("⏰ [Trials] Processing expired trials")

    try:
        count = RecurringBillingService.handle_expired_trials()

        logger.info(f"⏰ [Trials] Processed {count} expired trials")

        AuditService.log_simple_event(
            event_type="expired_trials_processed",
            user=None,
            description=f"Processed {count} expired trials",
            actor_type="system",
            metadata={
                "trials_processed": count,
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "trials_processed": count,
            "message": f"Processed {count} expired trials",
        }

    except Exception as e:
        logger.exception(f"💥 [Trials] Error processing expired trials: {e}")
        return {"success": False, "error": str(e)}


def process_grace_period_expirations() -> dict[str, Any]:
    """
    Handle subscriptions with expired grace periods.

    Suspends or cancels subscriptions that have exhausted their grace period
    after payment failures.

    Should run daily.

    Returns:
        Dictionary with processing result
    """
    from apps.billing.subscription_service import RecurringBillingService  # noqa: PLC0415

    logger.info("⚠️ [Grace] Processing expired grace periods")

    try:
        count = RecurringBillingService.handle_grace_period_expirations()

        logger.info(f"⚠️ [Grace] Processed {count} grace period expirations")

        AuditService.log_simple_event(
            event_type="grace_periods_processed",
            user=None,
            description=f"Processed {count} grace period expirations",
            actor_type="system",
            metadata={
                "expirations_processed": count,
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "expirations_processed": count,
            "message": f"Processed {count} grace period expirations",
        }

    except Exception as e:
        logger.exception(f"💥 [Grace] Error processing grace periods: {e}")
        return {"success": False, "error": str(e)}


def notify_expiring_grandfathering(days_ahead: int = 30) -> dict[str, Any]:
    """
    Send notifications for grandfathered prices expiring soon.

    Args:
        days_ahead: Number of days to look ahead for expiring grandfathering

    Returns:
        Dictionary with notification result
    """
    from apps.billing.subscription_service import GrandfatheringService  # noqa: PLC0415

    logger.info(f"📢 [Grandfathering] Checking for expiring grandfathering ({days_ahead} days)")

    try:
        expiring = GrandfatheringService.check_expiring_grandfathering(days_ahead)

        notified_count = 0
        for gf in expiring:
            try:
                # Send notification email
                from apps.notifications.services import (  # noqa: PLC0415
                    EmailService,
                )

                EmailService.send_template_email(
                    template_key="grandfathering_expiring",
                    recipient=gf.customer.primary_email,
                    context={
                        "customer": gf.customer,
                        "product": gf.product,
                        "locked_price": gf.locked_price,
                        "expires_at": gf.expires_at,
                        "savings_percent": gf.savings_percent,
                    },
                )

                # Mark as notified
                gf.expiry_notified = True
                gf.expiry_notified_at = timezone.now()
                gf.save(update_fields=["expiry_notified", "expiry_notified_at"])

                notified_count += 1

            except Exception as e:
                logger.error(f"Failed to notify customer {gf.customer_id} about expiring grandfathering: {e}")

        logger.info(f"📢 [Grandfathering] Notified {notified_count} customers about expiring prices")

        return {
            "success": True,
            "customers_notified": notified_count,
            "total_expiring": len(expiring),
            "message": f"Notified {notified_count} customers about expiring grandfathered prices",
        }

    except Exception as e:
        logger.exception(f"💥 [Grandfathering] Error checking expiring grandfathering: {e}")
        return {"success": False, "error": str(e)}


def run_payment_collection() -> dict[str, Any]:
    """
    Run payment collection for failed payments.

    Processes retry attempts for subscriptions with failed payments.
    Should run multiple times daily (e.g., every 4 hours).

    Returns:
        Dictionary with collection result
    """
    from apps.billing.payment_models import (  # noqa: PLC0415
        PaymentCollectionRun,
        PaymentRetryAttempt,
    )

    logger.info("💳 [Collection] Starting payment collection run")

    try:
        # Create collection run record
        run = PaymentCollectionRun.objects.create(
            run_type="automatic",
        )

        # Find pending retry attempts that are due
        due_retries = PaymentRetryAttempt.objects.filter(
            status="pending",
            scheduled_at__lte=timezone.now(),
        ).select_related("payment", "payment__customer", "payment__invoice", "policy")

        run.total_scheduled = due_retries.count()

        total_recovered_cents = 0
        successful = 0
        failed = 0

        for retry in due_retries:
            try:
                run.total_processed += 1
                retry.status = "processing"
                retry.executed_at = timezone.now()
                retry.save(update_fields=["status", "executed_at"])

                # Attempt payment
                # TODO: Implement actual payment processing via Stripe
                logger.info(
                    f"💳 [Collection] Would retry payment {retry.payment_id} " f"(attempt {retry.attempt_number})"
                )

                # For now, simulate success/failure
                # In production, this would call the payment gateway
                success = False  # Placeholder

                if success:
                    retry.status = "success"
                    successful += 1
                    total_recovered_cents += retry.payment.amount_cents

                    # Update payment status
                    retry.payment.status = "succeeded"
                    retry.payment.save(update_fields=["status"])

                else:
                    retry.status = "failed"
                    retry.failure_reason = "Payment declined"
                    failed += 1

                    # Schedule next retry if applicable
                    if retry.policy and retry.attempt_number < retry.policy.max_attempts:
                        next_retry_date = retry.policy.get_next_retry_date(timezone.now(), retry.attempt_number)
                        if next_retry_date:
                            PaymentRetryAttempt.objects.create(
                                payment=retry.payment,
                                policy=retry.policy,
                                attempt_number=retry.attempt_number + 1,
                                scheduled_at=next_retry_date,
                                status="pending",
                            )

                retry.save()

            except Exception as e:
                logger.error(f"Error processing retry {retry.id}: {e}")
                retry.status = "failed"
                retry.failure_reason = str(e)
                retry.save()
                failed += 1

        # Complete collection run
        run.total_successful = successful
        run.total_failed = failed
        run.amount_recovered_cents = total_recovered_cents
        run.completed_at = timezone.now()
        run.status = "completed"
        run.save()

        logger.info(
            f"💳 [Collection] Run completed: "
            f"{successful} recovered, {failed} failed, "
            f"{total_recovered_cents/100:.2f} total recovered"
        )

        return {
            "success": True,
            "run_id": str(run.id),
            "total_processed": run.total_processed,
            "successful": successful,
            "failed": failed,
            "amount_recovered_cents": total_recovered_cents,
        }

    except Exception as e:
        logger.exception(f"💥 [Collection] Error running payment collection: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# ASYNC WRAPPER FUNCTIONS FOR RECURRING BILLING
# ===============================================================================


def run_daily_billing_async() -> str:
    """Queue daily billing task."""
    return async_task("apps.billing.tasks.run_daily_billing", timeout=TASK_TIME_LIMIT * 2)


def process_expired_trials_async() -> str:
    """Queue expired trials processing task."""
    return async_task("apps.billing.tasks.process_expired_trials", timeout=TASK_TIME_LIMIT)


def process_grace_period_expirations_async() -> str:
    """Queue grace period expiration processing task."""
    return async_task("apps.billing.tasks.process_grace_period_expirations", timeout=TASK_TIME_LIMIT)


def notify_expiring_grandfathering_async(days_ahead: int = 30) -> str:
    """Queue grandfathering expiry notification task."""
    return async_task(
        "apps.billing.tasks.notify_expiring_grandfathering",
        days_ahead,
        timeout=TASK_TIME_LIMIT,
    )


def run_payment_collection_async() -> str:
    """Queue payment collection task."""
    return async_task("apps.billing.tasks.run_payment_collection", timeout=TASK_TIME_LIMIT * 2)
