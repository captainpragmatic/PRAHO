"""Billing background tasks.

This module contains Django-Q2 tasks for billing operations, invoice
generation, payment processing, and dunning workflows.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from apps.billing.gateways.base import PaymentConfirmResult
    from apps.billing.refund_service import RefundGatewayFacts
    from apps.customers.profile_models import CustomerTaxProfile

from django.db import transaction
from django.db.models import Q
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
PAYMENT_RETRY_LEASE_TIMEOUT = timedelta(seconds=TASK_TIME_LIMIT * 2)


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

    from apps.billing.efactura.service import EFacturaService  # noqa: PLC0415

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        # Submit through the canonical document lifecycle and endpoint router.
        service = EFacturaService()
        submission_result = service.submit_invoice(invoice)
        document_status = submission_result.document.status if submission_result.document else ""
        is_registered_with_anaf = document_status in {"submitted", "processing", "accepted"}
        if not submission_result.success:
            logger.error(f"🔥 [e-Factura] Submission failed for {invoice.number}: {submission_result.error_message}")
        elif is_registered_with_anaf:
            logger.info(f"✅ [e-Factura] Submitted invoice {invoice.number} to ANAF")
            invoice.meta = {**(invoice.meta or {}), "efactura_submitted": True}
            invoice.save(update_fields=["meta"])
        else:
            logger.info(f"🏛️ [e-Factura] Submission for {invoice.number} is already {document_status}")

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

        if not submission_result.success:
            return {
                "success": False,
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "error": submission_result.error_message,
            }

        return {
            "success": True,
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "status": document_status,
            "message": (
                "e-Factura submission completed"
                if is_registered_with_anaf
                else "e-Factura submission is already in progress"
            ),
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

        if invoice.status != "issued":
            logger.info(f"📅 [Reminders] Invoice {invoice.number} is not issued/pending, skipping reminders")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No reminders needed for non-pending invoice",
            }

        # Schedule 3 reminders: 7 days before, 1 day before, on due date
        if not invoice.due_at:
            logger.info(f"📅 [Reminders] No due date for invoice {invoice.number}, skipping reminders")
            return {"success": True, "invoice_id": str(invoice.id), "message": "No due date set"}

        reminder_offsets = [
            ("7_days_before", timedelta(days=-7)),
            ("1_day_before", timedelta(days=-1)),
            ("on_due_date", timedelta(days=0)),
        ]
        scheduled_count = 0
        for label, offset in reminder_offsets:
            reminder_at = invoice.due_at + offset
            if reminder_at > timezone.now():
                task_name = f"payment_reminder_{invoice.id}_{label}"
                async_task(
                    "apps.billing.tasks._send_payment_reminder",
                    str(invoice.id),
                    task_name=task_name,
                    schedule=reminder_at,
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
                "due_at": invoice.due_at.isoformat(),
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

        if invoice.status not in ["issued", "overdue"]:
            logger.info(f"⚠️ [Dunning] Invoice {invoice.number} is not issued/overdue, skipping dunning")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No dunning needed for non-overdue invoice",
            }
        if invoice.due_at is None or invoice.due_at > timezone.now():
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No dunning needed before the invoice due date",
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
                    PaymentRetryAttempt.objects.get_or_create(
                        payment=payment,
                        attempt_number=1,
                        defaults={
                            "policy": policy,
                            "scheduled_at": next_date,
                            "status": "pending",
                        },
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
                "days_overdue": max(0, (timezone.now().date() - invoice.due_at.date()).days),
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
            with transaction.atomic():
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

        source: Literal["vies", "format_check", "manual", "cached"]
        if vies.api_available:
            source = "vies"
            is_valid = vies.is_valid
            status = "valid" if vies.is_valid else "invalid"
        else:
            # VIES down — record format-only result but do NOT grant reverse charge.
            # Naming note: "format_check" is VATValidation.validation_source (HOW it was validated);
            # "format_only" is CustomerTaxProfile.vies_verification_status (WHAT the result means).
            source = "format_check"
            is_valid = False  # Format passed but VIES not confirmed — not valid for reverse charge
            status = "format_only"
            logger.warning(
                "[VAT] VIES unavailable for %s, format-only recorded (not eligible for reverse charge)",
                fmt.full_vat_number,
            )

        # Step 4: Store results — atomic to keep VATValidation + TaxProfile in sync
        with transaction.atomic():
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

        try:
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
        except Exception:  # Audit logging is best-effort; validation already persisted in DB above
            logger.exception("[VAT] Audit log failed for %s — validation result already persisted", fmt.full_vat_number)

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
    source: Literal["vies", "format_check", "manual", "cached"],
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
            "validation_source": source,
            "response_data": response_data or {},
            "expires_at": expires_at,
        },
    )


def _update_tax_profile_vies(
    tax_profile: CustomerTaxProfile,
    *,
    status: str,
    company_name: str = "",
) -> None:
    """Update CustomerTaxProfile VIES verification fields.

    Status values and their effect on reverse_charge_eligible:
      - "valid": VIES confirmed → eligible = True, vies_verified_at set to now
      - "invalid": VIES rejected → eligible = False, vies_verified_at cleared
      - "format_only": VIES unavailable, format passed → eligible = False (no VIES proof), vies_verified_at cleared
      - "not_applicable": non-EU VAT → eligible = False, vies_verified_at cleared
      - any other: unknown → eligible = False (fail-closed), vies_verified_at cleared
    """
    tax_profile.vies_verification_status = status
    tax_profile.vies_verified_name = company_name
    update_fields = ["vies_verification_status", "vies_verified_name", "updated_at"]
    if status == "valid":
        tax_profile.vies_verified_at = timezone.now()
        tax_profile.reverse_charge_eligible = True
        update_fields.extend(["vies_verified_at", "reverse_charge_eligible"])
    else:
        # All non-"valid" statuses revoke reverse charge eligibility (fail-closed)
        # Clear vies_verified_at so stale timestamps don't imply current validity
        tax_profile.reverse_charge_eligible = False
        tax_profile.vies_verified_at = None
        update_fields.extend(["reverse_charge_eligible", "vies_verified_at"])
    tax_profile.save(update_fields=update_fields)


def process_auto_payment(invoice_id: str) -> dict[str, Any]:
    """Create one authorized off-session attempt for an issued recurring invoice."""
    logger.info(f"💳 [AutoPay] Processing automatic payment for invoice {invoice_id}")

    from apps.billing.payment_service import PaymentService  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        from django.db.models import Q  # noqa: PLC0415

        from apps.billing.metering_models import BillingCycle  # noqa: PLC0415

        invoice = Invoice.objects.get(id=invoice_id)

        if invoice.status not in {"issued", "overdue"}:
            logger.info(f"💳 [AutoPay] Invoice {invoice.number} is not payable, skipping auto-payment")
            return {
                "success": True,
                "invoice_id": str(invoice.id),
                "message": "No auto-payment needed for non-pending invoice",
            }

        cycles = list(
            BillingCycle.objects.filter(Q(invoice=invoice) | Q(usage_invoice=invoice))
            .select_related("subscription__saved_payment_method")
            .defer("subscription__saved_payment_method__bank_details")
            .order_by("subscription_id", "id")
        )
        payment_method_ids = {
            cycle.subscription.saved_payment_method.stripe_payment_method_id
            for cycle in cycles
            if cycle.subscription.saved_payment_method is not None
        }
        if not cycles or len(payment_method_ids) != 1:
            return {"success": False, "error": "Invoice has no single authorized recurring payment method"}

        payment_method_id = payment_method_ids.pop()
        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=invoice.id,
            payment_method_id=payment_method_id,
        )
        outcome = "created" if result.get("success") else "failed"

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
            "success": bool(result.get("success")),
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "message": "Auto-payment attempt created" if result.get("success") else "Auto-payment attempt failed",
            "error": result.get("error"),
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
    """Prepare due PRAHO proformas, then collect the automatic-payment groups."""
    from apps.billing.recurring_billing import RecurringBillingOrchestrator  # noqa: PLC0415
    from apps.billing.subscription_service import SubscriptionLifecycleService  # noqa: PLC0415

    logger.info("📅 [Billing] Starting daily billing run")

    try:
        cancellations_finalized = SubscriptionLifecycleService.finalize_period_end_cancellations()
        preparation = RecurringBillingOrchestrator.prepare_due_proformas()
        collection = RecurringBillingOrchestrator.collect_due_proformas()
        renewals_marked_overdue = RecurringBillingOrchestrator.mark_overdue_renewals()
        errors = [*preparation["errors"], *collection["errors"]]
        result = {
            "cancellations_finalized": cancellations_finalized,
            "preparation": preparation,
            "collection": collection,
            "renewals_marked_overdue": renewals_marked_overdue,
            "errors": errors,
        }

        logger.info(
            "📅 [Billing] Daily billing completed: %s subscriptions checked, %s proformas created, %s payments created",
            preparation["subscriptions_checked"],
            preparation["proformas_created"],
            collection["payments_created"],
        )

        AuditService.log_simple_event(
            event_type="daily_billing_completed",
            user=None,
            description=(
                f"Daily billing run completed: {preparation['proformas_created']} proformas prepared, "
                f"{collection['payments_created']} payments created"
            ),
            actor_type="system",
            metadata={
                "preparation": preparation,
                "collection": collection,
                "renewals_marked_overdue": renewals_marked_overdue,
                "errors": errors[:10],
                "source_app": "billing",
            },
        )

        return {
            "success": not errors,
            "result": result,
            "message": (
                f"Daily billing completed: {preparation['proformas_created']} proformas prepared, "
                f"{collection['payments_created']} payments created"
            ),
        }

    except Exception as e:
        logger.exception(f"💥 [Billing] Daily billing run failed: {e}")
        return {"success": False, "error": str(e)}


def process_expired_trials() -> dict[str, Any]:
    """
    Cancel expired trials whose first paid renewal did not settle.

    A trial converts only through successful payment convergence; merely having
    a saved card is never enough to activate paid service.

    Should run daily, after run_daily_billing.

    Returns:
        Dictionary with processing result
    """
    from apps.billing.subscription_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        SubscriptionLifecycleService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info("⏰ [Trials] Processing expired trials")

    try:
        count = SubscriptionLifecycleService.handle_expired_trials()

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
        SubscriptionLifecycleService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info("⚠️ [Grace] Processing expired grace periods")

    try:
        count = SubscriptionLifecycleService.handle_grace_period_expirations()

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
            retry_model.objects.get_or_create(
                payment=retry.payment,
                attempt_number=retry.attempt_number + 1,
                defaults={
                    "policy": retry.policy,
                    "scheduled_at": next_retry_date,
                    "status": "pending",
                },
            )


def _retry_collection_target(original_payment: Any) -> tuple[Any, int | None, Any]:
    """Resolve the mandate-bound method and PRAHO document for a retry."""
    from django.db.models import Q  # noqa: PLC0415

    from apps.billing.metering_models import BillingCycle  # noqa: PLC0415
    from apps.billing.payment_service import PaymentService  # noqa: PLC0415

    if original_payment.invoice_id is not None:
        cycle = (
            BillingCycle.objects.filter(
                Q(invoice_id=original_payment.invoice_id) | Q(usage_invoice_id=original_payment.invoice_id)
            )
            .select_related("subscription__saved_payment_method")
            .defer("subscription__saved_payment_method__bank_details")
            .order_by("subscription_id")
            .first()
        )
        saved_method = cycle.subscription.saved_payment_method if cycle is not None else None
        return saved_method, original_payment.invoice_id, PaymentService.create_payment_intent_for_invoice

    if original_payment.proforma_id is not None:
        cycle = (
            original_payment.proforma.billing_cycles.select_related("subscription__saved_payment_method")
            .defer("subscription__saved_payment_method__bank_details")
            .order_by("subscription_id")
            .first()
        )
        saved_method = cycle.subscription.saved_payment_method if cycle is not None else None
        return saved_method, original_payment.proforma_id, PaymentService.create_payment_intent_for_proforma

    return None, None, None


def _find_retry_result_payment(original_payment: Any, intent_result: Any) -> Any:
    """Find only the newly created PRAHO Payment attempt."""
    gateway_txn_id = intent_result.get("payment_intent_id", "")
    if not gateway_txn_id:
        return None
    return (
        original_payment.__class__.objects.filter(gateway_txn_id=gateway_txn_id).exclude(id=original_payment.id).first()
    )


def _claim_payment_retry(retry_id: Any, retry_model: Any) -> bool:
    """Atomically claim one due retry so overlapping workers cannot double-charge it."""
    return (
        retry_model.objects.filter(id=retry_id, status="pending").update(
            status="processing",
            executed_at=timezone.now(),
        )
        == 1
    )


def _reclaim_stale_payment_retries(retry_model: Any, *, now: datetime) -> int:
    """Release claims older than two task timeouts for idempotent resumption."""
    reclaimed = retry_model.objects.filter(
        status="processing",
        executed_at__lt=now - PAYMENT_RETRY_LEASE_TIMEOUT,
    ).update(
        status="pending",
        executed_at=None,
        updated_at=now,
    )
    if reclaimed:
        logger.warning("Reclaimed %s stale payment retry claim(s)", reclaimed)
    return int(reclaimed)


def _execute_payment_retry(retry: Any, retry_model: Any) -> int | None:
    """Execute one retry and return recovered cents, or None on failure."""
    from apps.billing.payment_service import PaymentService  # noqa: PLC0415

    original_payment = retry.payment
    logger.info(f"💳 [Collection] Retrying payment {retry.payment_id} (attempt {retry.attempt_number})")

    if retry.result_payment_id is not None:
        result_payment = retry.result_payment
        if result_payment.status == "succeeded":
            retry.status = "success"
            retry.failure_reason = ""
            retry.save(update_fields=["status", "failure_reason", "updated_at"])
            return int(result_payment.amount_cents)
        if result_payment.status == "failed":
            retry.status = "failed"
            retry.failure_reason = str(result_payment.meta.get("gateway_error") or "Payment declined")
            _schedule_next_retry(retry, retry_model)
            retry.save(update_fields=["status", "failure_reason", "updated_at"])
            return None

    if original_payment.status != "failed":
        intent_result: Any = {
            "success": False,
            "error": "Only failed payments are eligible for a new retry attempt",
        }
    else:
        saved_method, document_id, create_intent = _retry_collection_target(original_payment)
        payment_method_id = getattr(saved_method, "stripe_payment_method_id", "")
        if create_intent is None or document_id is None or not payment_method_id:
            intent_result = {"success": False, "error": "No authorized recurring payment method"}
        else:
            intent_result = create_intent(
                document_id,
                payment_method_id,
                gateway=original_payment.payment_method or "stripe",
                retry_attempt_id=retry.id,
            )

    gateway_txn_id = intent_result.get("payment_intent_id", "")
    retry.refresh_from_db(fields=["result_payment"])
    result_payment = retry.result_payment or _find_retry_result_payment(original_payment, intent_result)
    if result_payment is not None and retry.result_payment_id is None:
        retry.result_payment = result_payment
        # Persist ownership before confirmation. A definitive failure converges
        # synchronously and must see that the collection worker owns this retry
        # chain, otherwise it could seed a competing attempt for result_payment.
        retry.save(update_fields=["result_payment", "updated_at"])

    confirm_result: PaymentConfirmResult = {"success": False, "status": "failed", "error": None}
    if intent_result.get("success", False) and gateway_txn_id and result_payment is not None:
        confirm_result = PaymentService.confirm_payment(
            gateway_txn_id,
            gateway=original_payment.payment_method or "stripe",
            customer_id=original_payment.customer_id,
        )

    if (
        confirm_result.get("success", False)
        and confirm_result.get("status") == "succeeded"
        and result_payment is not None
    ):
        result_payment.refresh_from_db()
        retry.status = "success"
        retry.failure_reason = ""
        retry.save()
        return int(result_payment.amount_cents)

    retry.status = "failed"
    retry.failure_reason = str(
        confirm_result.get("error") or intent_result.get("error") or confirm_result.get("status") or "Payment declined"
    )
    _schedule_next_retry(retry, retry_model)
    retry.save()
    return None


def run_payment_collection() -> dict[str, Any]:
    """
    Run payment collection for failed payments.

    Processes retry attempts for subscriptions with failed payments.
    Runs every 15 minutes through the canonical billing scheduler.

    Returns:
        Dictionary with collection result
    """
    from apps.billing.payment_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        PaymentCollectionRun,
        PaymentRetryAttempt,
    )

    logger.info("💳 [Collection] Starting payment collection run")

    try:
        # Create collection run record
        run = PaymentCollectionRun.objects.create(
            run_type="automatic",
        )

        now = timezone.now()
        _reclaim_stale_payment_retries(PaymentRetryAttempt, now=now)

        # Find pending retry attempts that are due
        due_retries = PaymentRetryAttempt.objects.filter(
            status="pending",
            scheduled_at__lte=now,
        ).select_related("payment", "payment__customer", "payment__invoice", "policy")

        run.total_scheduled = due_retries.count()

        total_recovered_cents = 0
        successful = 0
        failed = 0

        for retry in due_retries:
            if not _claim_payment_retry(retry.id, PaymentRetryAttempt):
                continue
            retry.refresh_from_db()
            run.total_processed += 1
            try:
                recovered_cents = _execute_payment_retry(retry, PaymentRetryAttempt)
            except Exception as exc:
                logger.error(f"Error processing retry {retry.id}: {exc}")
                retry.status = "failed"
                retry.failure_reason = str(exc)
                retry.save()
                _schedule_next_retry(retry, PaymentRetryAttempt)
                failed += 1
                continue

            if recovered_cents is None:
                failed += 1
            else:
                successful += 1
                total_recovered_cents += recovered_cents

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


def _stripe_refund_facts(source: dict[str, Any], refund_id: str) -> RefundGatewayFacts:
    """Build a convergence fact-dict from a gateway result, omitting empty optionals."""
    facts: RefundGatewayFacts = {
        "refund_id": refund_id,
        "payment_intent_id": source["payment_intent_id"],
        "amount_cents": source["amount_cents"],
        "currency": source["currency"],
        "status": source["status"],
    }
    if source.get("reason"):
        facts["reason"] = source["reason"]
    if source.get("failure_reason"):
        facts["failure_reason"] = source["failure_reason"]
    return facts


def _collect_stripe_refund_facts(
    gateway: Any, *, lookback_days: int, discovery_page_size: int, errors: list[str]
) -> dict[str, RefundGatewayFacts]:
    """Gather refund facts to converge: non-terminal local refunds + recent gateway refunds."""
    from apps.billing.models import Refund  # noqa: PLC0415

    refund_facts: dict[str, RefundGatewayFacts] = {}
    pending_ids = (
        Refund.objects.filter(status__in=("pending", "processing", "approved"))
        .exclude(gateway_refund_id="")
        .values_list("gateway_refund_id", flat=True)
    )
    for refund_id in pending_ids.iterator():
        retrieved = gateway.retrieve_refund(refund_id)
        if retrieved["success"]:
            refund_facts[refund_id] = _stripe_refund_facts(retrieved, retrieved["refund_id"])
        else:
            errors.append(f"{refund_id}: {retrieved['error'] or 'gateway retrieval failed'}")

    created_gte = int((timezone.now() - timedelta(days=max(lookback_days, 1))).timestamp())
    listed = gateway.list_refunds(created_gte=created_gte, limit=discovery_page_size)
    if not listed["success"]:
        errors.append(f"Stripe refund discovery failed: {listed['error'] or 'unknown error'}")
        return refund_facts
    for discovered in listed["refunds"]:
        refund_id = discovered["refund_id"]
        if refund_id and refund_id not in refund_facts:
            refund_facts[refund_id] = _stripe_refund_facts(discovered, refund_id)
    return refund_facts


def reconcile_stripe_refunds(*, lookback_days: int = 30, discovery_page_size: int = 100) -> dict[str, Any]:
    """Converge non-terminal and recently created Stripe refunds into PRAHO."""
    from apps.billing.gateways import PaymentGatewayFactory  # noqa: PLC0415
    from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

    errors: list[str] = []
    try:
        gateway = PaymentGatewayFactory.create_gateway("stripe")
    except Exception as exc:
        logger.exception("[Refund reconciliation] Stripe gateway initialization failed")
        return {"success": False, "refunds_checked": 0, "refunds_converged": 0, "errors": [str(exc)]}

    refund_facts = _collect_stripe_refund_facts(
        gateway, lookback_days=lookback_days, discovery_page_size=discovery_page_size, errors=errors
    )

    converged = 0
    external_skipped = 0
    for refund_id, facts in refund_facts.items():
        result = RefundConvergenceService.converge_gateway_refund(facts)
        if result.is_err():
            errors.append(f"{refund_id}: {result.unwrap_err()}")
            continue
        # Ok(None) means the PaymentIntent is not in this DB (a refund for another system
        # sharing the Stripe account) — a skip, not a convergence. Counting it would inflate
        # the report by every unrelated account refund in the lookback window.
        if result.unwrap() is None:
            external_skipped += 1
        else:
            converged += 1

    if errors:
        # django-q marks a task that returns normally as successful even when the returned
        # payload says success=False; log at error level so a failing nightly reconciliation
        # is visible to monitoring instead of silently green.
        logger.error(
            "🔥 [Refund reconciliation] completed with %d error(s); converged=%d external_skipped=%d",
            len(errors),
            converged,
            external_skipped,
        )

    return {
        "success": not errors,
        "refunds_checked": len(refund_facts),
        "refunds_converged": converged,
        "refunds_external_skipped": external_skipped,
        "errors": errors,
    }


def setup_billing_scheduled_tasks() -> dict[str, str]:
    """Register the single PRAHO renewal path plus local usage processing."""
    from django_q.models import Schedule  # noqa: PLC0415

    from apps.billing.metering_tasks import register_scheduled_tasks  # noqa: PLC0415
    from apps.billing.recurring_billing import unmanaged_auto_renew_service_count  # noqa: PLC0415

    unmanaged_services = unmanaged_auto_renew_service_count()
    if unmanaged_services:
        raise RuntimeError(
            f"{unmanaged_services} active auto-renew services have no PRAHO subscription; "
            "link or migrate them before replacing the renewal scheduler"
        )

    # Remove the retired order-based renewal engine from installations that ran
    # an older setup command. No code path remains behind this schedule.
    Schedule.objects.filter(name__in=["order-process-recurring", "Sync Pending to Stripe"]).delete()

    schedule_definitions = (
        (
            "billing-recurring-orchestrator",
            "apps.billing.tasks.run_daily_billing",
            "15 * * * *",
        ),
        (
            "billing-expired-trials",
            "apps.billing.tasks.process_expired_trials",
            "30 0 * * *",
        ),
        (
            "billing-grace-expirations",
            "apps.billing.tasks.process_grace_period_expirations",
            "0 1 * * *",
        ),
        (
            "billing-payment-retries",
            "apps.billing.tasks.run_payment_collection",
            "*/15 * * * *",
        ),
        (
            "billing-refund-reconciliation",
            "apps.billing.tasks.reconcile_stripe_refunds",
            "45 2 * * *",
        ),
    )
    results: dict[str, str] = {}
    for name, func, cron in schedule_definitions:
        _schedule, created = Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func": func,
                "schedule_type": Schedule.CRON,
                "cron": cron,
                "repeats": -1,
            },
        )
        results[name] = "created" if created else "already_exists"

    register_scheduled_tasks()
    results["local-usage-workflow"] = "configured"
    return results


def reverify_expired_vat_validations() -> dict[str, Any]:
    """Re-verify VAT numbers whose VIES validation has expired.

    Runs as a periodic task (e.g., daily). Picks up VATValidation records
    past their expires_at and re-queues validate_vat_number for each.
    """
    from apps.billing.tax_models import VATValidation  # noqa: PLC0415

    logger.info("[VAT] Starting periodic VIES re-verification")

    expired = list(
        VATValidation.objects.filter(
            expires_at__lt=timezone.now(),
        )
        .filter(
            # Re-verify currently-valid records AND format_only records (VIES was down at initial check)
            # but NOT records that failed format validation (status="invalid") — those won't improve.
            Q(is_valid=True) | Q(validation_source="format_check")
        )
        .values_list("vat_number", "country_code")[:100]
    )

    from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

    queued = 0
    for vat_number, country_code in expired:
        full_vat = f"{country_code}{vat_number}"
        # Only re-queue profiles that are valid or format_only (not hard-invalid format failures)
        profile = CustomerTaxProfile.objects.filter(
            vat_number=full_vat,
            vies_verification_status__in=["valid", "format_only"],
        ).first()
        if profile:
            async_task("apps.billing.tasks.validate_vat_number", str(profile.id))
            queued += 1

    logger.info("[VAT] Re-verification: queued %d of %d expired validations", queued, len(expired))
    return {"success": True, "queued": queued, "expired_found": len(expired)}


def reverify_expired_vat_validations_async() -> str:
    """Queue periodic VIES re-verification task."""
    return async_task("apps.billing.tasks.reverify_expired_vat_validations", timeout=TASK_TIME_LIMIT)
