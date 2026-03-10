"""Billing background tasks.

This module contains Django-Q2 tasks for billing operations, invoice
generation, payment processing, and dunning workflows.
"""

from __future__ import annotations

import logging
from datetime import timedelta
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
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("billing.task_retry_delay_seconds", _DEFAULT_TASK_RETRY_DELAY)


def _get_task_max_retries() -> int:
    """Get task max retries from SettingsService."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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

    from apps.billing.efactura_service import (  # noqa: PLC0415
        EFacturaSubmissionService,
    )

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        # Submit via real EFacturaSubmissionService
        service = EFacturaSubmissionService()
        submission_result = service.submit_invoice(invoice)
        if not submission_result.success:
            logger.error(f"🔥 [e-Factura] Submission failed for {invoice.number}: {submission_result.message}")
        else:
            logger.info(f"✅ [e-Factura] Submitted invoice {invoice.number} to ANAF")
            invoice.meta = {**(invoice.meta or {}), "efactura_submitted": True}
            invoice.save(update_fields=["meta"])

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

        # Schedule 3 reminders: 7 days before, 1 day before, on due date
        if not invoice.due_date:
            logger.info(f"📅 [Reminders] No due date for invoice {invoice.number}, skipping reminders")
            return {"success": True, "invoice_id": str(invoice.id), "message": "No due date set"}

        reminder_offsets = [
            ("7_days_before", timedelta(days=-7)),
            ("1_day_before", timedelta(days=-1)),
            ("on_due_date", timedelta(days=0)),
        ]
        scheduled_count = 0
        for label, offset in reminder_offsets:
            reminder_date = (
                timezone.make_aware(timezone.datetime.combine(invoice.due_date + offset, timezone.datetime.min.time()))
                if not isinstance(invoice.due_date + offset, timezone.datetime)
                else invoice.due_date + offset
            )
            if reminder_date > timezone.now():
                task_name = f"payment_reminder_{invoice.id}_{label}"
                async_task(
                    "apps.billing.tasks._send_payment_reminder",
                    str(invoice.id),
                    task_name=task_name,
                    schedule=reminder_date,
                    timeout=TASK_SOFT_TIME_LIMIT,
                )
                scheduled_count += 1
        logger.info(f"📅 [Reminders] Scheduled {scheduled_count} reminders for invoice {invoice.number}")

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

        # Cancel scheduled django-q tasks for this invoice
        from django_q.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Schedule,  # Deferred: optional dependency  # Deferred: avoids circular import
        )

        cancelled = Schedule.objects.filter(name__startswith=f"payment_reminder_{invoice.id}_").delete()
        cancelled_count = cancelled[0] if cancelled else 0
        logger.info(f"🚫 [Reminders] Cancelled {cancelled_count} reminders for invoice {invoice.number}")

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

    from apps.billing.payment_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        PaymentRetryAttempt,
        PaymentRetryPolicy,
    )
    from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status not in ["pending", "overdue"]:
            logger.info(f"⚠️ [Dunning] Invoice {invoice.number} is not overdue, skipping dunning")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No dunning needed for non-overdue invoice",
            }

        # Find customer's retry policy and create first retry attempt
        # Send dunning email
        EmailService.send_payment_reminder(invoice)

        # Schedule payment retry if there's a payment method on file
        payments = invoice.payments.filter(status="failed").order_by("-created_at")
        if payments.exists():
            payment = payments.first()
            policy = PaymentRetryPolicy.objects.filter(is_active=True, is_default=True).first()
            if policy:
                next_date = policy.get_next_retry_date(timezone.now(), 0)
                if next_date:
                    PaymentRetryAttempt.objects.create(
                        payment=payment,
                        policy=policy,
                        attempt_number=1,
                        scheduled_at=next_date,
                        status="pending",
                    )
                    logger.info(f"⚠️ [Dunning] Scheduled retry for invoice {invoice.number} at {next_date}")
        else:
            logger.info(f"⚠️ [Dunning] No failed payments for invoice {invoice.number}, email-only dunning")

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
    """Validate a customer's VAT number with format check and VIES verification.

    Routing logic:
    - Detects country from VAT prefix (defaults to RO if no prefix).
    - RO numbers: CUIValidator strict check digit + VIES.
    - Other EU numbers: stdnum format check + VIES REST API.
    - Non-EU: rejected immediately.
    - VIES down: falls back to format-only validation.

    Updates CustomerTaxProfile VIES fields and stores result in VATValidation.

    Args:
        tax_profile_id: CustomerTaxProfile UUID.

    Returns:
        Dictionary with validation result.
    """
    logger.info("[VAT] Validating VAT number for tax profile %s", tax_profile_id)

    from apps.billing.gateways.vies_gateway import VIESGateway  # noqa: PLC0415
    from apps.common.eu_vat_validator import (  # noqa: PLC0415
        is_eu_country,
        parse_vat_number,
        validate_vat_format,
    )
    from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

    try:
        tax_profile = CustomerTaxProfile.objects.select_related("customer").get(id=tax_profile_id)

        if not tax_profile.vat_number:
            logger.info("[VAT] No VAT number for tax profile %s", tax_profile_id)
            return {"success": True, "tax_profile_id": str(tax_profile.id), "message": "No VAT number to validate"}

        # Step 1: Parse country + digits
        country_code, vat_digits = parse_vat_number(tax_profile.vat_number)

        if not is_eu_country(country_code):
            _update_tax_profile_vies(tax_profile, status="not_applicable")
            return {
                "success": True,
                "tax_profile_id": str(tax_profile.id),
                "message": f"Non-EU country ({country_code}), VIES not applicable",
            }

        # Step 2: Offline format validation
        fmt = validate_vat_format(country_code, vat_digits)
        if not fmt.is_valid:
            _store_validation(
                fmt.country_code,
                vat_digits,
                fmt.full_vat_number,
                is_valid=False,
                source="format_check",
                response_data={"error": fmt.error_message},
            )
            _update_tax_profile_vies(tax_profile, status="invalid")
            logger.info("[VAT] Format invalid: %s — %s", fmt.full_vat_number, fmt.error_message)
            return {
                "success": True,
                "tax_profile_id": str(tax_profile.id),
                "is_valid": False,
                "message": f"Format invalid: {fmt.error_message}",
            }

        # Step 3: VIES API verification
        vies = VIESGateway.check_vat(country_code, vat_digits)

        if vies.api_available:
            source = "vies"
            is_valid = vies.is_valid
            status = "valid" if vies.is_valid else "invalid"
        else:
            # VIES down — accept format-only
            source = "format_check"
            is_valid = True
            status = "format_only"
            logger.warning("[VAT] VIES unavailable for %s, accepting format-only", fmt.full_vat_number)

        # Step 4: Store results
        _store_validation(
            country_code,
            vat_digits,
            fmt.full_vat_number,
            is_valid=is_valid,
            source=source,
            company_name=vies.company_name,
            company_address=vies.company_address,
            response_data=vies.raw_response,
        )
        _update_tax_profile_vies(
            tax_profile,
            status=status,
            company_name=vies.company_name if vies.api_available else "",
        )

        logger.info("[VAT] Validated %s: %s (source=%s)", fmt.full_vat_number, status, source)

        AuditService.log_simple_event(
            event_type="vat_validation_completed",
            user=None,
            content_object=tax_profile,
            description=f"VAT validation: {fmt.full_vat_number} -> {status}",
            actor_type="system",
            metadata={
                "tax_profile_id": str(tax_profile.id),
                "vat_number": fmt.full_vat_number,
                "country_code": country_code,
                "is_valid": is_valid,
                "source": source,
                "customer_id": str(tax_profile.customer_id),
                "source_app": "billing",
            },
        )

        return {
            "success": True,
            "tax_profile_id": str(tax_profile.id),
            "vat_number": fmt.full_vat_number,
            "is_valid": is_valid,
            "vies_status": status,
            "message": "VAT validation completed",
        }

    except Exception as e:
        logger.exception("[VAT] Error validating VAT for tax profile %s: %s", tax_profile_id, e)
        return {"success": False, "error": str(e)}


def _store_validation(  # noqa: PLR0913
    country_code: str,
    vat_number: str,
    full_vat_number: str,
    *,
    is_valid: bool,
    source: str,
    company_name: str = "",
    company_address: str = "",
    response_data: dict[str, Any] | None = None,
) -> None:
    """Upsert a VATValidation record."""
    from apps.billing.tax_models import VATValidation  # noqa: PLC0415

    expires_at = timezone.now() + timedelta(hours=24 if is_valid else 1)
    VATValidation.objects.update_or_create(
        country_code=country_code,
        vat_number=vat_number,
        defaults={
            "full_vat_number": full_vat_number,
            "is_valid": is_valid,
            "is_active": is_valid,
            "company_name": company_name,
            "company_address": company_address,
            "validation_source": "vies" if source == "vies" else "manual",
            "response_data": response_data or {},
            "expires_at": expires_at,
        },
    )


def _update_tax_profile_vies(
    tax_profile: Any,
    *,
    status: str,
    company_name: str = "",
) -> None:
    """Update CustomerTaxProfile VIES verification fields."""
    tax_profile.vies_verification_status = status
    tax_profile.vies_verified_name = company_name
    update_fields = ["vies_verification_status", "vies_verified_name", "updated_at"]
    if status == "valid":
        tax_profile.vies_verified_at = timezone.now()
        tax_profile.reverse_charge_eligible = True
        update_fields.extend(["vies_verified_at", "reverse_charge_eligible"])
    elif status == "invalid":
        tax_profile.reverse_charge_eligible = False
        update_fields.append("reverse_charge_eligible")
    tax_profile.save(update_fields=update_fields)


def process_auto_payment(invoice_id: str) -> dict[str, Any]:
    """
    Process automatic payment for an invoice.

    Args:
        invoice_id: Invoice UUID to process payment for

    Returns:
        Dictionary with payment result
    """
    logger.info(f"💳 [AutoPay] Processing automatic payment for invoice {invoice_id}")

    from apps.billing.payment_service import PaymentService  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status != "pending":
            logger.info(f"💳 [AutoPay] Invoice {invoice.number} is not pending, skipping auto-payment")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No auto-payment needed for non-pending invoice",
            }

        # Process payment using customer's stored payment method
        result = (
            PaymentService.create_payment_intent(
                order_id=str(invoice.meta.get("order_id", "")),
                gateway="stripe",
                metadata={"invoice_id": str(invoice.id), "auto_payment": True},
            )
            if invoice.meta and invoice.meta.get("order_id")
            else None
        )

        # Determine outcome
        outcome = "skipped"
        if result and result.get("success"):
            payment_intent_id = result.get("payment_intent_id", "")
            confirm = PaymentService.confirm_payment(payment_intent_id, gateway="stripe")
            if confirm.get("success") and confirm.get("status") == "succeeded":
                logger.info(f"💳 [AutoPay] Payment succeeded for invoice {invoice.number}")
                invoice.update_status_from_payments()
                outcome = "success"
            else:
                logger.warning(f"⚠️ [AutoPay] Payment confirmation pending for invoice {invoice.number}")
                outcome = "pending"
        else:
            logger.info(f"💳 [AutoPay] No order linked or payment failed for invoice {invoice.number}")
            outcome = "failed"

        # Log with outcome
        AuditService.log_simple_event(
            event_type=f"auto_payment_{outcome}",
            user=None,
            content_object=invoice,
            description=f"Auto-payment {outcome} for invoice {invoice.number}",
            actor_type="system",
            metadata={
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "amount_cents": invoice.total_cents,
                "outcome": outcome,
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


def _send_payment_reminder(invoice_id: str) -> dict[str, Any]:
    """Send a single payment reminder email for an invoice."""
    from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        invoice = Invoice.objects.get(id=invoice_id)
        result = EmailService.send_payment_reminder(invoice)
        if result.success:
            logger.info(f"📧 [Reminder] Sent payment reminder for invoice {invoice.number}")
        else:
            logger.warning(f"⚠️ [Reminder] Failed to send reminder for {invoice.number}: {result.error}")
        return {"success": result.success, "invoice_id": str(invoice.id)}
    except Invoice.DoesNotExist:
        return {"success": False, "error": f"Invoice {invoice_id} not found"}
    except Exception as e:
        logger.exception(f"💥 [Reminder] Error sending reminder for {invoice_id}: {e}")
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
    from apps.billing.subscription_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        RecurringBillingService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
    from apps.billing.subscription_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        RecurringBillingService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
    from apps.billing.subscription_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        RecurringBillingService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
    from apps.billing.subscription_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        GrandfatheringService,
    )
    from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

    logger.info(f"📢 [Grandfathering] Checking for expiring grandfathering ({days_ahead} days)")

    try:
        expiring = GrandfatheringService.check_expiring_grandfathering(days_ahead)

        notified_count = 0
        for gf in expiring:
            try:
                # Send notification email
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


def _schedule_next_retry(retry: Any, retry_model: Any) -> None:
    """Schedule the next retry attempt if the policy allows more attempts."""
    if retry.policy and retry.attempt_number < retry.policy.max_attempts:
        next_retry_date = retry.policy.get_next_retry_date(timezone.now(), retry.attempt_number)
        if next_retry_date:
            retry_model.objects.create(
                payment=retry.payment,
                policy=retry.policy,
                attempt_number=retry.attempt_number + 1,
                scheduled_at=next_retry_date,
                status="pending",
            )


def run_payment_collection() -> dict[str, Any]:
    """
    Run payment collection for failed payments.

    Processes retry attempts for subscriptions with failed payments.
    Should run multiple times daily (e.g., every 4 hours).

    Returns:
        Dictionary with collection result
    """
    from apps.billing.payment_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        PaymentCollectionRun,
        PaymentRetryAttempt,
    )
    from apps.billing.payment_service import PaymentService  # noqa: PLC0415  # Deferred: avoids circular import

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

                # Attempt payment via Stripe gateway
                logger.info(f"💳 [Collection] Retrying payment {retry.payment_id} (attempt {retry.attempt_number})")

                # Re-attempt payment using stored gateway transaction ID
                success = False
                if retry.payment.gateway_txn_id:
                    confirm_result = PaymentService.confirm_payment(
                        retry.payment.gateway_txn_id,
                        gateway=retry.payment.payment_method or "stripe",
                    )
                    success = confirm_result.get("success", False) and confirm_result.get("status") == "succeeded"

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
                    _schedule_next_retry(retry, PaymentRetryAttempt)

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
            f"{total_recovered_cents / 100:.2f} total recovered"
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


def reverify_expired_vat_validations() -> dict[str, Any]:
    """Re-verify VAT numbers whose VIES validation has expired.

    Runs as a periodic task (e.g., daily). Picks up VATValidation records
    past their expires_at and re-queues validate_vat_number for each.
    """
    from apps.billing.tax_models import VATValidation  # noqa: PLC0415

    logger.info("[VAT] Starting periodic VIES re-verification")

    expired = (
        VATValidation.objects.filter(
            expires_at__lt=timezone.now(),
            is_valid=True,
        )
        .select_related()
        .values_list("vat_number", "country_code")[:100]
    )

    queued = 0
    for vat_number, _country_code in expired:
        # Find the tax profile that owns this VAT number
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        profile = CustomerTaxProfile.objects.filter(vat_number__icontains=vat_number).first()
        if profile:
            async_task("apps.billing.tasks.validate_vat_number", str(profile.id))
            queued += 1

    logger.info("[VAT] Re-verification: queued %d of %d expired validations", queued, len(expired))
    return {"success": True, "queued": queued, "expired_found": len(expired)}


def reverify_expired_vat_validations_async() -> str:
    """Queue periodic VIES re-verification task."""
    return async_task("apps.billing.tasks.reverify_expired_vat_validations", timeout=TASK_TIME_LIMIT)
