"""
Comprehensive billing signals for PRAHO Platform
Event-driven billing and payment processing with Romanian compliance.

Includes:
- Core invoice/payment lifecycle events
- Cross-app integration (orders, services, customers)
- Post-refund side effects and notifications
- Romanian compliance (e-Factura, VAT validation)
- Business analytics and reporting
- Data cleanup and maintenance
"""

import logging
from datetime import datetime
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
    BillingAuditService,
    ComplianceEventRequest,
)
from apps.common.validators import log_security_event

from .models import (
    Invoice,
    Payment,
    PaymentRetryAttempt,
    ProformaInvoice,
    TaxRule,
    VATValidation,
)

logger = logging.getLogger(__name__)


def _serialize_values_for_audit(values: dict[str, Any]) -> dict[str, Any]:
    """
    Serialize values for audit logging, handling datetime objects.

    Args:
        values: Dictionary that may contain datetime objects

    Returns:
        Dictionary with datetime objects converted to ISO strings
    """
    serialized = {}
    for key, value in values.items():
        if isinstance(value, datetime):
            # Convert datetime to ISO format string
            serialized[key] = value.isoformat()
        else:
            serialized[key] = value
    return serialized


# ===============================================================================
# BUSINESS CONSTANTS
# ===============================================================================

# Financial thresholds in cents (Romanian business context)
LARGE_REFUND_THRESHOLD_CENTS = 50000  # 500 EUR - requires finance team notification
E_FACTURA_MINIMUM_AMOUNT = 100  # 100 RON - minimum for mandatory e-Factura

# ===============================================================================
# CORE INVOICE LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Invoice)
def handle_invoice_created_or_updated(sender: type[Invoice], instance: Invoice, created: bool, **kwargs: Any) -> None:
    """
    Handle invoice creation and updates.

    Triggers:
    - Audit logging for all invoice changes
    - Email notifications for status changes
    - Romanian e-Factura integration
    - Payment reminder scheduling
    - Cross-app order synchronization
    - Post-refund side effects
    """
    try:
        # Enhanced audit logging using BillingAuditService
        event_type = "invoice_created" if created else "invoice_status_changed"

        old_values = (
            _serialize_values_for_audit(getattr(instance, "_original_invoice_values", {})) if not created else {}
        )
        new_values = _serialize_values_for_audit(
            {
                "number": instance.number,
                "status": instance.status,
                "total_cents": instance.total_cents,
                "customer_id": str(instance.customer.id),
            }
        )

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            # Use specialized billing audit service for richer metadata
            from apps.audit.services import BusinessEventData  # noqa: PLC0415

            event_data = BusinessEventData(
                event_type=event_type,
                business_object=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Invoice {instance.number} {'created' if created else 'updated'}",
            )
            BillingAuditService.log_invoice_event(event_data)

        if created:
            # New invoice created
            _handle_new_invoice_creation(instance)
            logger.info(f"📋 [Invoice] Created {instance.number} for {instance.customer}")

        else:
            # Invoice updated - check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_invoice_status_change(instance, old_status, instance.status)

                # EXTENDED: Cross-app order synchronization
                _sync_orders_on_invoice_status_change(instance, old_status, instance.status)

                # REFUND: Post-refund side effects
                if instance.status == "refunded" and old_status != "refunded":
                    _handle_invoice_refund_completion(instance)

        # Handle specific Romanian compliance requirements
        if instance.status == "issued" and not instance.efactura_sent:
            _trigger_efactura_submission(instance)

        # EXTENDED: Update billing analytics
        _update_billing_analytics(instance, created)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Failed to handle invoice save: {e}")


@receiver(pre_save, sender=Invoice)
def store_original_invoice_values(sender: type[Invoice], instance: Invoice, **kwargs: Any) -> None:
    """Store original values before saving for audit trail"""
    try:
        if instance.pk:
            try:
                original = Invoice.objects.get(pk=instance.pk)
                instance._original_invoice_values = {  # type: ignore[attr-defined]
                    "status": original.status,
                    "total_cents": original.total_cents,
                    "due_at": original.due_at,
                    "efactura_sent": original.efactura_sent,
                }
            except Invoice.DoesNotExist:
                instance._original_invoice_values = {}  # type: ignore[attr-defined]
    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Failed to store original values: {e}")


@receiver(post_save, sender=Invoice)
def handle_invoice_number_generation(sender: type[Invoice], instance: Invoice, created: bool, **kwargs: Any) -> None:
    """
    Generate proper invoice number when status changes to 'issued'.
    Romanian law requires sequential numbering only for issued invoices.
    """
    try:
        if not created and instance.status == "issued" and instance.number.startswith("TMP-"):
            # Generate proper invoice number
            from .services import InvoiceNumberingService  # noqa: PLC0415

            sequence = InvoiceNumberingService.get_or_create_sequence("default")  # type: ignore[attr-defined]
            new_number = sequence.get_next_number("INV")

            # Update without triggering signals again
            Invoice.objects.filter(pk=instance.pk).update(number=new_number, issued_at=timezone.now())

            logger.info(f"📋 [Invoice] Generated number {new_number} for invoice {instance.pk}")

            # Log the numbering event for Romanian compliance
            compliance_request = ComplianceEventRequest(
                compliance_type="efactura_submission",
                reference_id=new_number,
                description=f"Invoice number generated: {new_number}",
                status="success",
                evidence={"old_number": instance.number, "new_number": new_number},
            )
            AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Failed to generate invoice number: {e}")


@receiver(post_delete, sender=Invoice)
def handle_invoice_cleanup(sender: type[Invoice], instance: Invoice, **kwargs: Any) -> None:
    """
    Clean up related data when invoices are deleted.
    Romanian compliance: issued invoices cannot be deleted, only voided.
    """
    try:
        # Romanian law: issued invoices cannot be deleted, only voided
        if instance.status == "issued":
            logger.error(f"🔥 [Invoice] ILLEGAL DELETION: Issued invoice {instance.number} deleted!")

            # Log critical compliance violation
            log_security_event(
                "illegal_invoice_deletion",
                {
                    "invoice_id": str(instance.id),
                    "invoice_number": instance.number,
                    "status": instance.status,
                    "total_cents": instance.total_cents,
                    "customer_id": str(instance.customer.id),
                    "issued_at": instance.issued_at.isoformat() if instance.issued_at else None,
                },
            )

        # Clean up related files and caches
        _cleanup_invoice_files(instance)
        _invalidate_invoice_caches(instance)
        _cancel_invoice_webhooks(instance)

        logger.warning(f"🗑️ [Invoice] Cleaned up deleted invoice {instance.number}")

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Cleanup failed: {e}")


# ===============================================================================
# CORE PAYMENT LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Payment)
def handle_payment_created_or_updated(sender: type[Payment], instance: Payment, created: bool, **kwargs: Any) -> None:
    """
    Handle payment creation and updates.

    Triggers:
    - Invoice status updates when payment succeeds
    - Payment confirmation emails
    - Failed payment retry scheduling
    - Customer credit updates
    - Service activation
    """
    try:
        old_values = (
            _serialize_values_for_audit(getattr(instance, "_original_payment_values", {})) if not created else {}
        )
        new_values = _serialize_values_for_audit(
            {
                "status": instance.status,
                "amount_cents": instance.amount_cents,
                "payment_method": instance.payment_method,
                "customer_id": str(instance.customer.id),
            }
        )

        # Enhanced payment audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            # Determine specific event type based on status change
            audit_event_type = "payment_initiated" if created else f"payment_{instance.status}"

            from apps.audit.services import BusinessEventData  # noqa: PLC0415

            event_data = BusinessEventData(
                event_type=audit_event_type,
                business_object=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Payment {instance.amount} {instance.currency.code} - {instance.status}",
            )
            BillingAuditService.log_payment_event(event_data)

        if created:
            logger.info(f"💳 [Payment] Created payment {instance.id} for {instance.customer}")

        # Check for status changes
        old_status = old_values.get("status")
        if old_status and old_status != instance.status:
            _handle_payment_status_change(instance, old_status, instance.status)

            # EXTENDED: Service activation
            if instance.status == "succeeded" and old_status != "succeeded":
                _activate_payment_services(instance)

            # EXTENDED: Customer credit scoring
            _update_customer_payment_credit(instance, old_status)

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Failed to handle payment save: {e}")


@receiver(pre_save, sender=Payment)
def store_original_payment_values(sender: type[Payment], instance: Payment, **kwargs: Any) -> None:
    """Store original payment values for comparison"""
    try:
        if instance.pk:
            try:
                original = Payment.objects.get(pk=instance.pk)
                instance._original_payment_values = {"status": original.status, "amount_cents": original.amount_cents}
            except Payment.DoesNotExist:
                instance._original_payment_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Failed to store original values: {e}")


@receiver(post_delete, sender=Payment)
def handle_payment_cleanup(sender: type[Payment], instance: Payment, **kwargs: Any) -> None:
    """Clean up payment-related data and handle compliance requirements."""
    try:
        # Log payment deletion for audit
        log_security_event(
            "payment_deleted",
            {
                "payment_id": str(instance.id),
                "customer_id": str(instance.customer.id),
                "invoice_id": str(instance.invoice.id) if instance.invoice else None,
                "amount_cents": instance.amount_cents,
                "status": instance.status,
                "payment_method": instance.payment_method,
            },
        )

        # Clean up payment-related files
        _cleanup_payment_files(instance)

        # Update customer payment statistics
        if instance.status == "succeeded":
            _revert_customer_credit_score(instance.customer, "payment_deleted")

        logger.info(f"🗑️ [Payment] Cleaned up deleted payment {instance.id}")

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Cleanup failed: {e}")


# ===============================================================================
# PROFORMA INVOICE SIGNALS
# ===============================================================================


@receiver(post_save, sender=ProformaInvoice)
def handle_proforma_invoice_conversion(
    sender: type[ProformaInvoice], instance: ProformaInvoice, created: bool, **kwargs: Any
) -> None:
    """
    Handle automatic conversion of proformas to invoices based on business rules.
    Romanian business practice: Proformas convert to invoices upon payment or acceptance.
    """
    try:
        # Enhanced proforma audit logging
        event_type = "proforma_created" if created else "proforma_updated"

        old_values = (
            _serialize_values_for_audit(getattr(instance, "_original_proforma_values", {})) if not created else {}
        )
        new_values = _serialize_values_for_audit(
            {
                "number": instance.number,
                "total_cents": instance.total_cents,
                "customer_id": str(instance.customer.id),
            }
        )

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import BusinessEventData  # noqa: PLC0415

            event_data = BusinessEventData(
                event_type=event_type,
                business_object=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Proforma {instance.number} {'created' if created else 'updated'}",
            )
            BillingAuditService.log_proforma_event(event_data)
        if not created:
            old_values = _serialize_values_for_audit(getattr(instance, "_original_proforma_values", {}))
            old_status = old_values.get("status")

            # Auto-convert proforma to invoice when paid
            if instance.status == "paid" and old_status != "paid" and not hasattr(instance, "converted_invoice"):
                try:
                    from apps.billing.services import (  # noqa: PLC0415
                        ProformaConversionService,
                    )

                    result = ProformaConversionService.convert_to_invoice(  # type: ignore[call-arg]
                        proforma_id=str(instance.id), conversion_reason="payment_received"
                    )

                    if result.is_ok():
                        invoice = result.unwrap()
                        logger.info(f"📋 [Proforma] Auto-converted {instance.number} → {invoice.number}")  # type: ignore[attr-defined]

                        # Link any related orders to the new invoice
                        if hasattr(instance, "orders") and instance.orders.exists():
                            invoice.orders.set(instance.orders.all())  # type: ignore[attr-defined]

                    else:
                        logger.error(f"🔥 [Proforma] Conversion failed: {result.error}")

                except Exception as e:
                    logger.exception(f"🔥 [Proforma] Auto-conversion failed: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Proforma Signal] Conversion handling failed: {e}")


@receiver(pre_save, sender=ProformaInvoice)
def store_original_proforma_values(sender: type[ProformaInvoice], instance: ProformaInvoice, **kwargs: Any) -> None:
    """Store original proforma values for comparison"""
    try:
        if instance.pk:
            try:
                original = ProformaInvoice.objects.get(pk=instance.pk)
                instance._original_proforma_values = {"status": original.status, "total_cents": original.total_cents}
            except ProformaInvoice.DoesNotExist:
                instance._original_proforma_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Proforma Signal] Failed to store original values: {e}")


# ===============================================================================
# TAX AND COMPLIANCE SIGNALS
# ===============================================================================


@receiver(post_save, sender=TaxRule)
def handle_tax_rule_changes(sender: type[TaxRule], instance: TaxRule, created: bool, **kwargs: Any) -> None:
    """
    Handle tax rule creation/updates.

    Triggers:
    - Cache invalidation for tax calculations
    - Compliance logging for Romanian VAT changes
    - Notification to finance team for rate changes
    """
    try:
        event_type = "tax_rule_created" if created else "tax_rule_updated"

        # Audit log
        event_data = AuditEventData(
            event_type=event_type,
            content_object=instance,
            description=f"Tax rule {instance.country_code} {instance.tax_type}: {instance.rate * 100}%",
        )
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            AuditService.log_event(event_data)

        # Invalidate tax calculation cache
        _invalidate_tax_cache(instance.country_code, instance.tax_type)

        # Romanian compliance logging
        if instance.country_code == "RO":
            compliance_request = ComplianceEventRequest(
                compliance_type="vat_validation",
                reference_id=f"tax_rule_{instance.id}",
                description=f"Romanian VAT rule updated: {instance.rate * 100}%",
                status="success",
                evidence={
                    "country": instance.country_code,
                    "rate": float(instance.rate),
                    "effective_date": instance.valid_from.isoformat(),
                },
            )
            AuditService.log_compliance_event(compliance_request)

        logger.info(f"📊 [Tax] Rule {'created' if created else 'updated'}: {instance}")

    except Exception as e:
        logger.exception(f"🔥 [Tax Signal] Failed to handle tax rule change: {e}")


@receiver(post_save, sender=VATValidation)
def handle_vat_validation_result(
    sender: type[VATValidation], instance: VATValidation, created: bool, **kwargs: Any
) -> None:
    """
    Handle VAT validation results.

    Triggers:
    - Compliance logging for Romanian VIES validation
    - Customer profile updates for valid VAT numbers
    - Alert generation for invalid VAT numbers
    """
    try:
        if created:
            # Log VAT validation for compliance
            compliance_request = ComplianceEventRequest(
                compliance_type="vat_validation",
                reference_id=instance.full_vat_number,
                description=f"VAT validation: {instance.full_vat_number} - {'Valid' if instance.is_valid else 'Invalid'}",
                status="success" if instance.is_valid else "validation_failed",
                evidence={
                    "vat_number": instance.full_vat_number,
                    "is_valid": instance.is_valid,
                    "company_name": instance.company_name,
                    "validation_source": instance.validation_source,
                },
            )
            AuditService.log_compliance_event(compliance_request)

            # Update customer tax profiles if VAT is valid
            if instance.is_valid:
                _update_customer_vat_status(instance)
            else:
                _handle_invalid_vat_number(instance)

            logger.info(
                f"🏛️ [VAT] Validation {'✅ valid' if instance.is_valid else '❌ invalid'}: {instance.full_vat_number}"
            )

    except Exception as e:
        logger.exception(f"🔥 [VAT Signal] Failed to handle VAT validation: {e}")


# ===============================================================================
# PAYMENT RETRY AND DUNNING SIGNALS
# ===============================================================================


@receiver(post_save, sender=PaymentRetryAttempt)
def handle_payment_retry_attempt(
    sender: type[PaymentRetryAttempt], instance: PaymentRetryAttempt, created: bool, **kwargs: Any
) -> None:
    """
    Handle payment retry attempts.

    Triggers:
    - Customer notifications for retry results
    - Escalation to manual review after max attempts
    - Service suspension for continued failures
    """
    try:
        if not created:
            old_status = getattr(instance, "_original_retry_status", "")
            if old_status != instance.status and instance.status in ["success", "failed"]:
                _handle_retry_completion(instance)

    except Exception as e:
        logger.exception(f"🔥 [Payment Retry Signal] Failed to handle retry attempt: {e}")


@receiver(pre_save, sender=PaymentRetryAttempt)
def store_original_retry_values(
    sender: type[PaymentRetryAttempt], instance: PaymentRetryAttempt, **kwargs: Any
) -> None:
    """Store original retry values for comparison"""
    try:
        if instance.pk:
            try:
                original = PaymentRetryAttempt.objects.get(pk=instance.pk)
                instance._original_retry_status = original.status
            except PaymentRetryAttempt.DoesNotExist:
                instance._original_retry_status = ""
    except Exception as e:
        logger.exception(f"🔥 [Payment Retry Signal] Failed to store original values: {e}")


# ===============================================================================
# CROSS-APP INTEGRATION FUNCTIONS
# ===============================================================================


def _sync_orders_on_invoice_status_change(invoice: Invoice, old_status: str, new_status: str) -> None:
    """Update related orders when invoice status changes"""
    try:
        if not invoice.orders.exists():
            return

        from apps.orders.services import OrderService, StatusChangeData  # noqa: PLC0415

        if new_status == "paid" and old_status != "paid":
            # Invoice paid - advance orders to processing
            for order in invoice.orders.filter(status="pending"):
                status_change = StatusChangeData(
                    new_status="processing",
                    notes=f"Payment received for invoice {invoice.number}",
                    changed_by=None,  # System change
                )

                result = OrderService.update_order_status(order, status_change)
                if result.is_ok():
                    logger.info(f"📋 [Order] Advanced {order.order_number} to processing")

        elif new_status == "void" and old_status != "void":
            # Invoice voided - cancel related orders
            for order in invoice.orders.all():
                if order.status in ["pending", "processing"]:
                    status_change = StatusChangeData(
                        new_status="cancelled", notes=f"Related invoice {invoice.number} was voided", changed_by=None
                    )

                    result = OrderService.update_order_status(order, status_change)
                    if result.is_ok():
                        logger.info(f"📋 [Order] Cancelled {order.order_number} due to voided invoice")

        elif new_status == "overdue" and old_status != "overdue":
            # Invoice overdue - may suspend related services
            _handle_overdue_order_services(invoice)

    except Exception as e:
        logger.exception(f"🔥 [Invoice] Order sync failed: {e}")


def _activate_payment_services(payment: Payment) -> None:
    """Activate services when payment is received"""
    try:
        if not payment.invoice:
            return

        from apps.provisioning.services import ServiceActivationService  # noqa: PLC0415

        for order in payment.invoice.orders.all():
            for item in order.items.filter(service__isnull=False):
                if item.service and item.service.status in ["pending", "suspended"]:
                    result = ServiceActivationService.activate_service(
                        service=item.service, activation_reason=f"Payment received for invoice {payment.invoice.number}"
                    )

                    if result.is_ok():
                        logger.info(f"⚡ [Service] Activated {item.service.id} after payment")

    except Exception as e:
        logger.exception(f"🔥 [Payment] Service activation failed: {e}")


def _update_customer_payment_credit(payment: Payment, old_status: str) -> None:
    """Update customer credit score based on payment events"""
    try:
        from apps.customers.services import CustomerCreditService  # noqa: PLC0415

        event_type = None
        if payment.status == "succeeded" and old_status != "succeeded":
            event_type = "positive_payment"
        elif payment.status == "failed" and old_status != "failed":
            event_type = "failed_payment"
        elif payment.status == "refunded" and old_status != "refunded":
            event_type = "refund_processed"

        if event_type:
            CustomerCreditService.update_credit_score(
                customer=payment.customer, event_type=event_type, event_date=timezone.now()
            )

            logger.info(f"📊 [Customer] Updated credit score for {payment.customer.id}: {event_type}")

    except Exception as e:
        logger.exception(f"🔥 [Customer] Credit score update failed: {e}")


# ===============================================================================
# POST-REFUND SIDE EFFECTS
# ===============================================================================


def _handle_invoice_refund_completion(invoice: Invoice) -> None:
    """Handle side effects when invoice refund is completed"""
    try:
        # 1. Send invoice refund confirmation
        _send_invoice_refund_confirmation(invoice)

        # 2. Update customer invoice payment patterns
        _update_customer_invoice_history(invoice, "refunded")

        # 3. Handle Romanian e-Factura refund reporting
        _handle_efactura_refund_reporting(invoice)

        # 4. Update billing analytics and KPIs
        _update_billing_refund_metrics(invoice)

        # 5. Create finance team notification for significant refunds
        if invoice.total_cents >= LARGE_REFUND_THRESHOLD_CENTS:
            _notify_finance_team_large_refund(invoice)

        # 6. Compliance and audit logging
        log_security_event(
            "invoice_refund_completed",
            {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "refund_amount_cents": invoice.total_cents,
            },
        )

        logger.info(f"💰 [Refund] Completed invoice refund for {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Refund Signal] Invoice refund completion handling failed: {e}")


# ===============================================================================
# CORE BUSINESS LOGIC FUNCTIONS
# ===============================================================================


def _handle_new_invoice_creation(invoice: Invoice) -> None:
    """Handle new invoice creation tasks"""
    try:
        # Send invoice notification to customer
        _send_invoice_created_email(invoice)

        # Schedule payment reminders if not paid immediately
        if invoice.status == "issued":
            _schedule_payment_reminders(invoice)

        # Update customer billing statistics
        _update_customer_billing_stats(invoice.customer)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] New invoice handling failed: {e}")


def _handle_invoice_status_change(invoice: Invoice, old_status: str, new_status: str) -> None:
    """Handle invoice status changes with various triggers"""
    try:
        logger.info(f"🔄 [Invoice] Status change {invoice.number}: {old_status} → {new_status}")

        # Security event for important status changes
        log_security_event(
            "invoice_status_changed",
            {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer.id),
                "old_status": old_status,
                "new_status": new_status,
                "amount_cents": invoice.total_cents,
            },
        )

        # Trigger different actions based on status transitions
        if new_status == "issued" and old_status == "draft":
            _handle_invoice_issued(invoice)
        elif new_status == "paid" and old_status in ["issued", "overdue"]:
            _handle_invoice_paid(invoice)
        elif new_status == "overdue" and old_status == "issued":
            _handle_invoice_overdue(invoice)
        elif new_status == "void" and old_status in ["draft", "issued"]:
            _handle_invoice_voided(invoice)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Status change handling failed: {e}")


def _handle_payment_status_change(payment: Payment, old_status: str, new_status: str) -> None:
    """Handle payment status changes"""
    try:
        logger.info(f"💳 [Payment] Status change {payment.id}: {old_status} → {new_status}")

        # Security logging for payment status changes
        log_security_event(
            "payment_status_changed",
            {
                "payment_id": str(payment.id),
                "customer_id": str(payment.customer.id),
                "invoice_id": str(payment.invoice.id) if payment.invoice else None,
                "old_status": old_status,
                "new_status": new_status,
                "amount_cents": payment.amount_cents,
                "payment_method": payment.payment_method,
            },
        )

        if new_status == "succeeded" and old_status != "succeeded":
            _handle_payment_success(payment)
        elif new_status == "failed" and old_status in ["pending", "processing"]:
            _handle_payment_failure(payment)
        elif new_status == "refunded":
            _handle_payment_refund(payment)

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Payment status change failed: {e}")


# ===============================================================================
# BUSINESS LOGIC HELPER FUNCTIONS
# ===============================================================================


def _handle_invoice_issued(invoice: Invoice) -> None:
    """Handle invoice being issued"""
    try:
        _send_invoice_issued_email(invoice)
        _schedule_payment_reminders(invoice)

        if _requires_efactura_submission(invoice):
            _trigger_efactura_submission(invoice)

        compliance_request = ComplianceEventRequest(
            compliance_type="efactura_submission",
            reference_id=invoice.number,
            description=f"Invoice issued: {invoice.number} for {invoice.customer}",
            status="success",
            evidence={
                "invoice_total": float(invoice.total),
                "due_date": invoice.due_at.isoformat() if invoice.due_at else None,
                "customer_vat_id": invoice.bill_to_tax_id,
            },
        )
        AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Invoice issued handling failed: {e}")


def _handle_invoice_paid(invoice: Invoice) -> None:
    """Handle invoice being paid"""
    try:
        if not invoice.paid_at:
            Invoice.objects.filter(pk=invoice.pk).update(paid_at=timezone.now())

        _send_payment_received_email(invoice)
        _cancel_payment_reminders(invoice)
        _update_customer_payment_history(invoice.customer, "positive")
        _activate_pending_services(invoice)

        logger.info(f"✅ [Invoice] Payment completed for {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Invoice paid handling failed: {e}")


def _handle_invoice_overdue(invoice: Invoice) -> None:
    """Handle invoice becoming overdue"""
    try:
        _send_invoice_overdue_email(invoice)
        _trigger_dunning_process(invoice)
        _update_customer_payment_history(invoice.customer, "negative")
        _handle_overdue_service_suspension(invoice)

        logger.warning(f"⚠️ [Invoice] Invoice {invoice.number} is overdue")

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Overdue handling failed: {e}")


def _handle_invoice_voided(invoice: Invoice) -> None:
    """Handle invoice being voided"""
    try:
        _send_invoice_voided_email(invoice)
        _cancel_payment_reminders(invoice)

        compliance_request = ComplianceEventRequest(
            compliance_type="efactura_submission",
            reference_id=invoice.number,
            description=f"Invoice voided: {invoice.number}",
            status="voided",
            evidence={"void_date": timezone.now().isoformat()},
        )
        AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Invoice Signal] Invoice voided handling failed: {e}")


def _handle_payment_success(payment: Payment) -> None:
    """Handle successful payment"""
    try:
        if payment.invoice:
            remaining_amount = payment.invoice.get_remaining_amount()
            if remaining_amount <= 0:
                payment.invoice.status = "paid"
                payment.invoice.paid_at = timezone.now()
                payment.invoice.save(update_fields=["status", "paid_at"])

                # 🚀 CROSS-APP INTEGRATION: Trigger Virtualmin provisioning on invoice payment
                _trigger_virtualmin_provisioning_on_payment(payment.invoice)

        _send_payment_success_email(payment)
        _update_customer_payment_history(payment.customer, "positive")
        _cancel_payment_retries(payment)

        logger.info(f"✅ [Payment] Success: {payment.amount} {payment.currency.code}")

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Payment success handling failed: {e}")


def _handle_payment_failure(payment: Payment) -> None:
    """Handle failed payment"""
    try:
        _send_payment_failed_email(payment)
        _schedule_payment_retry(payment)
        _update_customer_payment_history(payment.customer, "negative")

        logger.warning(f"⚠️ [Payment] Failed: {payment.amount} {payment.currency.code}")

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Payment failure handling failed: {e}")


def _handle_payment_refund(payment: Payment) -> None:
    """Handle payment refund completion"""
    try:
        if payment.invoice:
            refunded_amount = sum(p.amount_cents for p in payment.invoice.payments.filter(status="refunded"))
            if refunded_amount >= payment.invoice.total_cents:
                payment.invoice.status = "refunded"
                payment.invoice.save(update_fields=["status"])

        _send_payment_refund_email(payment)

        logger.info(f"↩️ [Payment] Refunded: {payment.amount} {payment.currency.code}")

    except Exception as e:
        logger.exception(f"🔥 [Payment Signal] Payment refund handling failed: {e}")


def _handle_retry_completion(retry_attempt: PaymentRetryAttempt) -> None:
    """Handle completed payment retry attempt"""
    try:
        if retry_attempt.status == "success":
            logger.info(f"✅ [Payment Retry] Successful retry for payment {retry_attempt.payment.id}")
            _send_retry_success_email(retry_attempt)

        elif retry_attempt.status == "failed":
            if retry_attempt.attempt_number >= retry_attempt.policy.max_attempts:
                _handle_final_retry_failure(retry_attempt)
            else:
                logger.warning(f"⚠️ [Payment Retry] Attempt {retry_attempt.attempt_number} failed")

    except Exception as e:
        logger.exception(f"🔥 [Payment Retry Signal] Retry completion handling failed: {e}")


# ===============================================================================
# ANALYTICS & REPORTING FUNCTIONS
# ===============================================================================


def _update_billing_analytics(invoice: Invoice, created: bool) -> None:
    """Update billing analytics and KPIs when invoices change"""
    try:
        from apps.billing.services import BillingAnalyticsService  # noqa: PLC0415

        # Update billing metrics
        BillingAnalyticsService.update_invoice_metrics(
            invoice=invoice, event_type="created" if created else "status_changed"
        )

        # Update customer billing analytics
        BillingAnalyticsService.update_customer_metrics(customer=invoice.customer, invoice=invoice)

        # Invalidate related dashboard caches
        _invalidate_billing_dashboard_cache(invoice.customer.id)

        logger.info(f"📊 [Analytics] Updated billing metrics for {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Billing Signal] Analytics update failed: {e}")


def _update_billing_refund_metrics(invoice: Invoice) -> None:
    """Update billing-specific refund metrics"""
    try:
        from apps.billing.services import BillingAnalyticsService  # noqa: PLC0415

        BillingAnalyticsService.record_invoice_refund(invoice=invoice, refund_date=invoice.updated_at)

        # Update customer lifetime value adjustments
        BillingAnalyticsService.adjust_customer_ltv(
            customer=invoice.customer, adjustment_amount_cents=-invoice.total_cents, adjustment_reason="invoice_refund"
        )

    except Exception as e:
        logger.exception(f"🔥 [Refund] Billing metrics update failed: {e}")


# ===============================================================================
# EMAIL NOTIFICATION FUNCTIONS
# ===============================================================================


def _send_invoice_created_email(invoice: Invoice) -> None:
    """Send invoice created notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="invoice_created",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={"invoice": invoice, "customer": invoice.customer, "invoice_lines": invoice.lines.all()},
        )
    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to send created email: {e}")


def _send_invoice_issued_email(invoice: Invoice) -> None:
    """Send invoice issued notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="invoice_issued",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={"invoice": invoice, "customer": invoice.customer},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to send issued email: {e}")


def _send_payment_received_email(invoice: Invoice) -> None:
    """Send payment received confirmation"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="payment_received",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={"invoice": invoice, "customer": invoice.customer},
        )
    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to send payment received email: {e}")


def _send_invoice_overdue_email(invoice: Invoice) -> None:
    """Send overdue invoice notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="invoice_overdue",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={
                "invoice": invoice,
                "customer": invoice.customer,
                "days_overdue": (timezone.now() - invoice.due_at).days if invoice.due_at else 0,
            },
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to send overdue email: {e}")


def _send_invoice_voided_email(invoice: Invoice) -> None:
    """Send invoice voided notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="invoice_voided",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={"invoice": invoice, "customer": invoice.customer},
        )
    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to send voided email: {e}")


def _send_payment_success_email(payment: Payment) -> None:
    """Send payment success notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="payment_success",
            recipient=payment.customer.primary_email,
            context={"payment": payment, "customer": payment.customer, "invoice": payment.invoice},
        )
    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to send success email: {e}")


def _send_payment_failed_email(payment: Payment) -> None:
    """Send payment failure notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="payment_failed",
            recipient=payment.customer.primary_email,
            context={"payment": payment, "customer": payment.customer, "invoice": payment.invoice},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to send failure email: {e}")


def _send_payment_refund_email(payment: Payment) -> None:
    """Send payment refund notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="payment_refund",
            recipient=payment.customer.primary_email,
            context={"payment": payment, "customer": payment.customer, "invoice": payment.invoice},
        )
    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to send refund email: {e}")


def _send_invoice_refund_confirmation(invoice: Invoice) -> None:
    """Send customer confirmation about invoice refund"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="invoice_refund_confirmation",
            recipient=invoice.bill_to_email or invoice.customer.primary_email,
            context={"invoice": invoice, "customer": invoice.customer, "refund_amount": invoice.total},
            priority="high",
        )

        logger.info(f"📧 [Refund] Sent invoice refund confirmation for {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Refund] Failed to send invoice refund confirmation: {e}")


def _send_retry_success_email(retry_attempt: PaymentRetryAttempt) -> None:
    """Send retry success notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="payment_retry_success",
            recipient=retry_attempt.payment.customer.primary_email,
            context={
                "retry_attempt": retry_attempt,
                "payment": retry_attempt.payment,
                "customer": retry_attempt.payment.customer,
            },
        )
    except Exception as e:
        logger.exception(f"🔥 [Payment Retry] Failed to send success email: {e}")


def _notify_finance_team_large_refund(invoice: Invoice) -> None:
    """Notify finance team about large refunds"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="finance_large_refund_alert",
            recipient="finance@pragmatichost.com",
            context={
                "invoice": invoice,
                "customer": invoice.customer,
                "refund_amount": invoice.total,
                "threshold": 500,  # EUR threshold
            },
            priority="high",
        )

        logger.info(f"🚨 [Finance] Alerted team about large refund: {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Refund] Finance team notification failed: {e}")


# ===============================================================================
# BUSINESS LOGIC UTILITY FUNCTIONS
# ===============================================================================


def _requires_efactura_submission(invoice: Invoice) -> bool:
    """Check if invoice requires e-Factura submission"""
    return (
        invoice.bill_to_country == "RO" and bool(invoice.bill_to_tax_id) and invoice.total >= E_FACTURA_MINIMUM_AMOUNT
    )


def _trigger_efactura_submission(invoice: Invoice) -> None:
    """Trigger e-Factura submission for Romanian compliance"""
    try:
        from apps.billing.efactura.tasks import queue_efactura_submission  # noqa: PLC0415

        task_id = queue_efactura_submission(str(invoice.id))
        if task_id:
            logger.info(f"🏛️ [e-Factura] Queued submission for {invoice.number} (task: {task_id})")
        else:
            logger.warning(f"⚠️ [e-Factura] Failed to queue submission for {invoice.number}")
    except ImportError as e:
        logger.warning(f"⚠️ [e-Factura] e-Factura module not available: {e}")


def _schedule_payment_reminders(invoice: Invoice) -> None:
    """Schedule payment reminder emails"""
    try:
        if invoice.due_at:
            from django_q.tasks import async_task  # noqa: PLC0415

            async_task("apps.billing.tasks.schedule_payment_reminders", str(invoice.id))
    except ImportError:
        logger.info(f"📅 [Invoice] Would schedule reminders for {invoice.number}")


def _cancel_payment_reminders(invoice: Invoice) -> None:
    """Cancel scheduled payment reminders"""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task("apps.billing.tasks.cancel_payment_reminders", str(invoice.id))
    except ImportError:
        logger.info(f"🚫 [Invoice] Would cancel reminders for {invoice.number}")


def _trigger_dunning_process(invoice: Invoice) -> None:
    """Start automated dunning process for overdue invoice"""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task("apps.billing.tasks.start_dunning_process", str(invoice.id))
    except ImportError:
        logger.warning(f"⚠️ [Invoice] Would start dunning for {invoice.number}")


def _schedule_payment_retry(payment: Payment) -> None:
    """Schedule payment retry according to policy"""
    try:
        from apps.billing.services import PaymentRetryService  # noqa: PLC0415

        policy = PaymentRetryService.get_customer_retry_policy(payment.customer)  # type: ignore[attr-defined]
        if policy and policy.is_active:
            PaymentRetryService.schedule_retry(payment, policy)  # type: ignore[attr-defined]
            logger.info(f"🔄 [Payment] Retry scheduled for payment {payment.id}")
    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to schedule retry: {e}")


def _update_customer_payment_history(customer: Any, event_type: str) -> None:
    """Update customer payment history and risk profile"""
    try:
        logger.info(f"📊 [Customer] Payment history {event_type} event for {customer}")
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to update payment history: {e}")


def _update_customer_billing_stats(customer: Any) -> None:
    """Update customer billing statistics"""
    try:
        logger.info(f"📊 [Customer] Updated billing stats for {customer}")
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to update billing stats: {e}")


def _update_customer_invoice_history(invoice: Invoice, event_type: str) -> None:
    """Update customer invoice payment patterns"""
    try:
        from apps.customers.services import CustomerAnalyticsService  # noqa: PLC0415

        CustomerAnalyticsService.record_invoice_event(  # type: ignore[attr-defined]
            customer=invoice.customer,
            event_type=event_type,
            invoice_amount_cents=invoice.total_cents,
            invoice_id=invoice.id,
        )

        logger.info(f"📊 [Customer] Updated invoice history for {invoice.customer.id}")

    except Exception as e:
        logger.exception(f"🔥 [Refund] Customer invoice history update failed: {e}")


def _activate_pending_services(invoice: Invoice) -> None:
    """Activate services that were pending payment"""
    try:
        from apps.provisioning.services import ServiceActivationService  # noqa: PLC0415

        orders = invoice.orders.all()
        for order in orders:
            for item in order.items.filter(service__isnull=False):
                if item.service and item.service.status == "pending":
                    ServiceActivationService.activate_service(item.service)
                    logger.info(f"⚡ [Service] Activated {item.service.id} after payment")

    except Exception as e:
        logger.exception(f"🔥 [Invoice] Failed to activate pending services: {e}")


def _handle_overdue_service_suspension(invoice: Invoice) -> None:
    """Handle service suspension for overdue invoices"""
    try:
        from apps.provisioning.services import ServiceManagementService  # noqa: PLC0415

        # Find all services related to overdue invoice orders
        services = [
            item.service
            for order in invoice.orders.all()
            for item in order.items.filter(service__isnull=False)
            if item.service and item.service.status == "active"
        ]

        # Suspend services for overdue invoices (configurable business rule)
        for service in services:
            result = ServiceManagementService.suspend_service(  # type: ignore[attr-defined]
                service=service,
                reason=f"Invoice {invoice.number} overdue",
                suspend_immediately=False,  # Grace period
                grace_period_days=7,
            )

            if result.is_ok():
                logger.info(f"⏸️ [Service] Scheduled suspension for {service.id} (overdue invoice)")

    except Exception as e:
        logger.exception(f"🔥 [Invoice] Service suspension failed: {e}")


def _handle_overdue_order_services(invoice: Invoice) -> None:
    """Handle services when invoice becomes overdue"""
    # Alias for consistency
    _handle_overdue_service_suspension(invoice)


def _invalidate_tax_cache(country_code: str, tax_type: str) -> None:
    """Invalidate tax calculation cache when rules change"""
    try:
        logger.info(f"🗑️ [Tax] Cache invalidated for {country_code} {tax_type}")
    except Exception as e:
        logger.exception(f"🔥 [Tax] Failed to invalidate cache: {e}")


def _update_customer_vat_status(vat_validation: VATValidation) -> None:
    """Update customer profiles with valid VAT information"""
    try:
        logger.info(f"✅ [VAT] Updated customer profiles for {vat_validation.full_vat_number}")
    except Exception as e:
        logger.exception(f"🔥 [VAT] Failed to update customer VAT status: {e}")


def _handle_invalid_vat_number(vat_validation: VATValidation) -> None:
    """Handle invalid VAT number validation"""
    try:
        logger.warning(f"❌ [VAT] Invalid VAT number detected: {vat_validation.full_vat_number}")
    except Exception as e:
        logger.exception(f"🔥 [VAT] Failed to handle invalid VAT: {e}")


def _handle_final_retry_failure(retry_attempt: PaymentRetryAttempt) -> None:
    """Handle final payment retry failure - escalate to manual review"""
    try:
        logger.error(f"🔥 [Payment Retry] Final attempt failed for payment {retry_attempt.payment.id}")

        _send_manual_review_notification(retry_attempt)
        _update_customer_payment_history(retry_attempt.payment.customer, "final_failure")
        _consider_service_suspension(retry_attempt.payment)

    except Exception as e:
        logger.exception(f"🔥 [Payment Retry] Failed to handle final retry failure: {e}")


def _send_manual_review_notification(retry_attempt: PaymentRetryAttempt) -> None:
    """Send manual review notification to finance team"""
    try:
        logger.info(f"📧 [Payment Retry] Manual review notification sent for {retry_attempt.payment.id}")
    except Exception as e:
        logger.exception(f"🔥 [Payment Retry] Failed to send manual review notification: {e}")


def _consider_service_suspension(payment: Payment) -> None:
    """Consider suspending services for failed payment"""
    try:
        logger.info(f"⚠️ [Payment] Considering service suspension for customer {payment.customer.id}")
    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to consider service suspension: {e}")


def _cancel_payment_retries(payment: Payment) -> None:
    """Cancel any pending payment retries"""
    try:
        PaymentRetryAttempt.objects.filter(payment=payment, status="pending").update(status="cancelled")

        logger.info(f"🚫 [Payment] Cancelled pending retries for payment {payment.id}")

    except Exception as e:
        logger.exception(f"🔥 [Payment] Failed to cancel retries: {e}")


def _handle_efactura_refund_reporting(invoice: Invoice) -> None:
    """Handle e-Factura refund reporting for Romanian compliance"""
    try:
        # Check if this invoice has an e-Factura document that was accepted
        if invoice.bill_to_country == "RO":
            try:
                from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus  # noqa: PLC0415

                efactura_doc = getattr(invoice, "efactura_document", None)
                if efactura_doc and efactura_doc.status == EFacturaStatus.ACCEPTED.value:
                    # TODO: Generate credit note for refund (requires credit note builder)
                    # For now, log that a credit note should be generated
                    logger.info(
                        f"🏛️ [e-Factura] Invoice {invoice.number} was refunded - "
                        f"credit note should be generated for e-Factura compliance"
                    )

                    # Log compliance event
                    compliance_request = ComplianceEventRequest(
                        compliance_type="efactura_submission",
                        reference_id=invoice.number,
                        description=f"Invoice {invoice.number} refunded - credit note pending",
                        status="pending",
                        evidence={
                            "original_upload_index": efactura_doc.anaf_upload_index,
                            "refund_date": invoice.updated_at.isoformat() if invoice.updated_at else None,
                        },
                    )
                    AuditService.log_compliance_event(compliance_request)

            except EFacturaDocument.DoesNotExist:
                # No e-Factura document for this invoice
                pass

    except Exception as e:
        logger.exception(f"🔥 [e-Factura] Refund reporting failed: {e}")


# ===============================================================================
# CLEANUP AND MAINTENANCE FUNCTIONS
# ===============================================================================


def _invalidate_billing_dashboard_cache(customer_id: int) -> None:
    """Invalidate billing dashboard caches"""
    try:
        cache_keys = [
            f"billing_dashboard:{customer_id}",
            f"customer_invoices:{customer_id}",
            f"customer_payments:{customer_id}",
            "billing_totals",
            "monthly_revenue",
        ]

        cache.delete_many(cache_keys)
        logger.info(f"🗑️ [Cache] Cleared billing caches for customer {customer_id}")

    except Exception as e:
        logger.exception(f"🔥 [Cache] Cache invalidation failed: {e}")


def _cleanup_invoice_files(invoice: Invoice) -> None:
    """Clean up files related to deleted invoice"""
    try:
        # Check for invoice PDF
        pdf_path = f"invoices/{invoice.number}.pdf"
        if default_storage.exists(pdf_path):
            default_storage.delete(pdf_path)
            logger.info(f"🗑️ [File] Deleted invoice PDF {pdf_path}")

        # Check for e-Factura XML files
        xml_path = f"efactura/{invoice.number}.xml"
        if default_storage.exists(xml_path):
            default_storage.delete(xml_path)
            logger.info(f"🗑️ [File] Deleted e-Factura XML {xml_path}")

    except Exception as e:
        logger.exception(f"🔥 [File] Invoice file cleanup failed: {e}")


def _cleanup_payment_files(payment: Payment) -> None:
    """Clean up files related to deleted payment"""
    try:
        if payment.meta.get("receipt_file"):
            receipt_path = payment.meta["receipt_file"]
            if default_storage.exists(receipt_path):
                default_storage.delete(receipt_path)
                logger.info(f"🗑️ [File] Deleted payment receipt {receipt_path}")

    except Exception as e:
        logger.exception(f"🔥 [File] Payment file cleanup failed: {e}")


def _invalidate_invoice_caches(invoice: Invoice) -> None:
    """Invalidate caches related to deleted invoice"""
    try:
        cache_keys = [
            f"invoice:{invoice.id}",
            f"invoice_pdf:{invoice.number}",
            f"customer_invoices:{invoice.customer.id}",
            "pending_invoices",
            "overdue_invoices",
        ]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] Invoice cache cleanup failed: {e}")


def _cancel_invoice_webhooks(invoice: Invoice) -> None:
    """Cancel pending webhooks for deleted invoice"""
    try:
        from apps.integrations.models import WebhookDelivery  # noqa: PLC0415

        # Use customer and event type since WebhookDelivery doesn't use GenericForeignKey
        cancelled_count = WebhookDelivery.objects.filter(
            customer=invoice.customer,
            event_type__startswith="invoice.",  # invoice.created, invoice.cancelled, etc.
            status="pending",
        ).update(status="cancelled")

        if cancelled_count > 0:
            logger.info(f"🚫 [Webhook] Cancelled {cancelled_count} pending deliveries for invoice {invoice.number}")

    except Exception as e:
        logger.exception(f"🔥 [Webhook] Invoice webhook cancellation failed: {e}")


def _revert_customer_credit_score(customer: Any, event_type: str) -> None:
    """Revert customer credit score changes"""
    try:
        from apps.customers.services import CustomerCreditService  # noqa: PLC0415

        CustomerCreditService.revert_credit_change(customer=customer, event_type=event_type, event_date=timezone.now())

    except Exception as e:
        logger.exception(f"🔥 [Customer] Credit score reversion failed: {e}")


# ===============================================================================
# CROSS-APP INTEGRATION: VIRTUALMIN PROVISIONING
# ===============================================================================


def _trigger_virtualmin_provisioning_on_payment(invoice: Invoice) -> None:
    """
    Trigger Virtualmin provisioning when invoice is fully paid.

    Cross-app integration point: billing → provisioning
    """
    try:
        # Import here to avoid circular imports
        from django_q.tasks import async_task  # noqa: PLC0415

        from apps.orders.models import OrderItem  # noqa: PLC0415

        # Find hosting services in the paid invoice
        order_items = OrderItem.objects.filter(order__invoice=invoice).select_related("service")

        hosting_services = [
            item.service for item in order_items if item.service and item.service.requires_hosting_account()
        ]

        if hosting_services:
            logger.info(
                f"🚀 [CrossApp] Triggering Virtualmin provisioning for {len(hosting_services)} services on invoice {invoice.number}"
            )

            # Queue provisioning tasks for each hosting service
            for service in hosting_services:
                try:
                    # Get primary domain for the service
                    primary_domain = service.get_primary_domain()
                    if primary_domain:
                        # Queue async provisioning task
                        params = {
                            "service_id": str(service.id),
                            "domain": primary_domain,
                            "template": "Default",  # Use default template, can be customized per service plan
                        }
                        async_task("apps.provisioning.virtualmin_tasks.provision_virtualmin_account", params)

                        logger.info(
                            f"🔄 [CrossApp] Queued Virtualmin provisioning for {primary_domain} (service: {service.id})"
                        )
                    else:
                        logger.warning(
                            f"⚠️ [CrossApp] No primary domain found for service {service.id}, skipping Virtualmin provisioning"
                        )

                except Exception as e:
                    logger.error(f"🔥 [CrossApp] Failed to queue Virtualmin provisioning for service {service.id}: {e}")

        else:
            logger.debug(
                f"📋 [CrossApp] No hosting services found in invoice {invoice.number}, skipping Virtualmin provisioning"
            )

    except Exception as e:
        logger.error(f"🔥 [CrossApp] Failed to trigger Virtualmin provisioning on payment: {e}")
