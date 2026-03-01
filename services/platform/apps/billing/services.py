"""
Billing Services for PRAHO Platform
Handles invoice management, refunds, and Romanian VAT compliance.
Contains critical financial operations including bidirectional refund synchronization.

Includes comprehensive usage-based billing services:
- MeteringService: Event recording and processing
- AggregationService: Usage aggregation management
- RatingEngine: Charge calculation with tiered pricing
- UsageAlertService: Threshold monitoring and alerts
- UsageInvoiceService: Automatic invoice generation from usage
- BillingCycleManager: Subscription billing cycle management
- Stripe metering integration services

This file serves as a re-export hub following ADR-0012 feature-based organization.
"""

from __future__ import annotations

import logging
from decimal import Decimal

# Re-export all services from feature files
# ===============================================================================
# RESULT PATTERN FOR REFUND OPERATIONS
# ===============================================================================
from typing import Any

# Import billing models - moved to top to fix PLC0415
from apps.billing.models import Currency, Invoice, InvoiceLine, InvoiceSequence

# Add imports to fix PLC0415 linting issues
# Ensure refund service uses the same log_security_event function for testing
from .invoice_service import (
    BillingAnalyticsService,
    generate_e_factura_xml,
    generate_invoice_pdf,
    generate_vat_summary,
    send_invoice_email,
)

# Import usage-based billing services
from .metering_service import (
    AggregationService,
    MeteringService,
    RatingEngine,
    UsageAlertService,
    UsageEventData,
)

# Re-export security logging function
from .models import log_security_event
from .proforma_service import (
    ProformaService,
    generate_proforma_pdf,
    send_proforma_email,
)

# Import all refund services from the dedicated refund_service module
from .refund_service import (
    RefundData,
    RefundEligibility,
    RefundQueryService,
    RefundReason,
    RefundResult,
    RefundService,
    RefundStatus,
    RefundType,
    Result,
)
from .stripe_metering import (
    StripeMeterEventService,
    StripeMeterService,
    StripeMeterWebhookHandler,
    StripeSubscriptionMeterService,
    StripeUsageSyncService,
)
from .usage_invoice_service import (
    BillingCycleManager,
    UsageInvoiceService,
)

# Result class is imported from refund_service.py - no need to redefine here

# ===============================================================================
# REFUND SERVICE RE-EXPORTS
# ===============================================================================

# RefundService imports moved to top of file for proper import organization

# RefundService is now imported from refund_service.py
# All refund functionality has been moved to the dedicated module


# RefundQueryService is now imported from refund_service.py
# All refund query functionality has been moved to the dedicated module


# ===============================================================================
# INVOICE SERVICE IMPLEMENTATION
# ===============================================================================


class InvoiceService:
    """Service for creating and managing invoices from orders"""

    def create_from_order(self, order: Any) -> Result[Any, str]:
        """Create an invoice from an order.

        Uses transaction.atomic and select_for_update to prevent race conditions
        in sequence number generation.
        """
        from django.db import IntegrityError, transaction  # noqa: PLC0415

        try:
            with transaction.atomic():
                # Get default currency (RON) - use get_or_create with proper error handling
                try:
                    currency = Currency.objects.get(code="RON")
                except Currency.DoesNotExist:
                    # Use get_or_create inside atomic block to handle concurrent creation
                    currency, _ = Currency.objects.get_or_create(
                        code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
                    )

                # Get invoice sequence with lock to prevent race conditions
                # Using select_for_update ensures only one process generates a number at a time
                try:
                    sequence = InvoiceSequence.objects.select_for_update().get(scope="default")
                except InvoiceSequence.DoesNotExist:
                    # Create with retry in case of concurrent creation
                    try:
                        sequence = InvoiceSequence.objects.create(scope="default")
                    except IntegrityError:
                        # Another process created it - get it with lock
                        sequence = InvoiceSequence.objects.select_for_update().get(scope="default")

                # Calculate totals using current Romanian VAT rate
                from apps.common.tax_service import TaxService  # noqa: PLC0415

                vat_rate = TaxService.get_vat_rate("RO", as_decimal=True)
                subtotal_amount = Decimal(order.total_cents) / 100
                tax_amount = subtotal_amount * vat_rate
                total_amount = subtotal_amount + tax_amount

                # Create invoice - all within the same atomic block to ensure consistency
                invoice = Invoice.objects.create(
                    customer=order.customer,
                    number=sequence.get_next_number("INV"),
                    currency=currency,
                    subtotal_cents=int(subtotal_amount * 100),
                    tax_cents=int(tax_amount * 100),
                    total_cents=int(total_amount * 100),
                    status="draft",
                    # Copy billing address from customer
                    bill_to_name=order.customer.company_name or order.customer.full_name or "",
                    bill_to_tax_id=getattr(order.customer, "cui", "") or "",
                    bill_to_email=order.customer.primary_email or "",
                    bill_to_address1=getattr(order.customer, "address", "") or "",
                    bill_to_city=getattr(order.customer, "city", "") or "",
                    bill_to_country="RO",  # Default to Romania
                    meta={"order_id": str(order.id)},
                )

                # Create invoice lines from order items
                for item in order.items.all():
                    InvoiceLine.objects.create(  # type: ignore[misc]
                        invoice=invoice,
                        description=item.name or f"Order item {item.id}",
                        quantity=item.quantity,
                        unit_price_cents=item.unit_price_cents,
                        total_cents=item.total_cents,
                        tax_rate_percent=19,  # Romanian VAT rate
                        meta={"order_item_id": str(item.id)},
                    )

                # Log invoice creation
                log_security_event(
                    event_type="invoice_created_from_order",
                    details={
                        "invoice_id": str(invoice.id),
                        "invoice_number": invoice.number,
                        "order_id": str(order.id),
                        "order_number": getattr(order, "order_number", ""),
                        "customer_id": str(order.customer.id),
                        "total_cents": invoice.total_cents,
                        "critical_financial_operation": True,
                    },
                )

                return Result.ok(invoice)

        except Exception as e:
            return Result.err(f"Failed to create invoice from order: {e!s}")


_services_logger = logging.getLogger(__name__)


class PaymentRetryService:
    """Schedule payment retries using dunning policies."""

    @staticmethod
    def retry_payment(payment_id: str) -> Result[bool, str]:
        """Find customer's retry policy and schedule a PaymentRetryAttempt."""
        from django.utils import timezone as tz  # noqa: PLC0415

        from apps.billing.models import Payment  # noqa: PLC0415
        from apps.billing.payment_models import PaymentRetryAttempt, PaymentRetryPolicy  # noqa: PLC0415

        try:
            payment = Payment.objects.select_related("customer").get(id=payment_id)
        except Payment.DoesNotExist:
            return Result.err(f"Payment not found: {payment_id}")

        if payment.status == "succeeded":
            return Result.ok(True)  # Already succeeded

        # Find applicable retry policy (customer-specific or default)
        policy = PaymentRetryPolicy.objects.filter(is_active=True, is_default=True).first()
        if not policy:
            _services_logger.warning(f"⚠️ [Retry] No active retry policy for payment {payment_id}")
            return Result.err("No retry policy configured")

        # Check if max attempts reached
        existing_attempts = PaymentRetryAttempt.objects.filter(payment=payment).count()
        if existing_attempts >= policy.max_attempts:
            return Result.err(f"Max retry attempts ({policy.max_attempts}) reached")

        # Schedule next retry
        next_retry_date = policy.get_next_retry_date(tz.now(), existing_attempts)
        if not next_retry_date:
            return Result.err("No more retry dates available")

        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=existing_attempts + 1,
            scheduled_at=next_retry_date,
            status="pending",
        )
        _services_logger.info(
            f"✅ [Retry] Scheduled retry #{existing_attempts + 1} for payment {payment_id} at {next_retry_date}"
        )
        return Result.ok(True)


class EFacturaService:
    """Delegate to real EFacturaSubmissionService."""

    @staticmethod
    def submit_invoice(invoice_id: str) -> Result[bool, str]:
        """Submit invoice to ANAF e-Factura via EFacturaSubmissionService."""
        from apps.billing.efactura_service import EFacturaSubmissionService  # noqa: PLC0415
        from apps.billing.models import Invoice as InvoiceModel  # noqa: PLC0415

        try:
            invoice = InvoiceModel.objects.get(id=invoice_id)
        except InvoiceModel.DoesNotExist:
            return Result.err(f"Invoice not found: {invoice_id}")

        service = EFacturaSubmissionService()
        result = service.submit_invoice(invoice)
        if result.success:
            _services_logger.info(f"✅ [e-Factura] Submitted invoice {invoice.number}")
            return Result.ok(True)
        return Result.err(result.message or "e-Factura submission failed")


class InvoiceNumberingService:
    """Generate sequential invoice numbers using InvoiceSequence."""

    @staticmethod
    def get_next_number(prefix: str = "INV", scope: str = "default") -> str:
        """Get next invoice number from atomic sequence."""
        sequence, _ = InvoiceSequence.objects.get_or_create(scope=scope)
        return sequence.get_next_number(prefix)


class ProformaConversionService:
    """Convert proforma invoices to real invoices."""

    @staticmethod
    def convert_to_invoice(proforma_id: str) -> Result[Any, str]:
        """Convert a proforma to a real invoice with tax recalculation."""
        from django.db import transaction  # noqa: PLC0415
        from django.utils import timezone as tz  # noqa: PLC0415

        from apps.billing.models import ProformaInvoice  # noqa: PLC0415
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        try:
            proforma = ProformaInvoice.objects.select_related("customer", "currency").get(id=proforma_id)
        except ProformaInvoice.DoesNotExist:
            return Result.err(f"Proforma not found: {proforma_id}")

        if proforma.status not in ("draft", "issued"):
            return Result.err(f"Proforma {proforma.number} cannot be converted (status: {proforma.status})")

        try:
            with transaction.atomic():
                # Get invoice sequence
                sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")
                currency = proforma.currency

                if not currency:
                    from apps.billing.currency_models import Currency as CurrencyModel  # noqa: PLC0415

                    currency, _ = CurrencyModel.objects.get_or_create(
                        code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
                    )

                # Recalculate tax
                vat_rate = TaxService.get_vat_rate("RO", as_decimal=True)
                subtotal_cents = proforma.subtotal_cents or 0
                tax_cents = int(Decimal(subtotal_cents) * vat_rate)
                total_cents = subtotal_cents + tax_cents

                invoice = Invoice.objects.create(
                    customer=proforma.customer,
                    number=sequence.get_next_number("INV"),
                    currency=currency,
                    subtotal_cents=subtotal_cents,
                    tax_cents=tax_cents,
                    total_cents=total_cents,
                    status="issued",
                    issued_at=tz.now(),
                    bill_to_name=proforma.bill_to_name or "",
                    bill_to_email=proforma.bill_to_email or "",
                    bill_to_tax_id=getattr(proforma, "bill_to_tax_id", "") or "",
                    bill_to_address1=getattr(proforma, "bill_to_address1", "") or "",
                    bill_to_city=getattr(proforma, "bill_to_city", "") or "",
                    bill_to_country=getattr(proforma, "bill_to_country", "RO") or "RO",
                    meta={"proforma_id": str(proforma.id), "proforma_number": proforma.number},
                )

                # Copy line items
                for line in proforma.lines.all():
                    InvoiceLine.objects.create(
                        invoice=invoice,
                        kind="service",
                        description=line.description,
                        quantity=line.quantity,
                        unit_price_cents=line.unit_price_cents,
                        line_total_cents=line.line_total_cents,
                    )

                # Update proforma status
                proforma.status = "converted"
                proforma.meta = {
                    **(proforma.meta or {}),
                    "invoice_id": str(invoice.id),
                    "invoice_number": invoice.number,
                }
                proforma.save(update_fields=["status", "meta"])

                log_security_event(
                    event_type="proforma_converted_to_invoice",
                    details={
                        "proforma_id": str(proforma.id),
                        "proforma_number": proforma.number,
                        "invoice_id": str(invoice.id),
                        "invoice_number": invoice.number,
                        "total_cents": total_cents,
                        "critical_financial_operation": True,
                    },
                )

                _services_logger.info(f"✅ [Conversion] Proforma {proforma.number} → Invoice {invoice.number}")
                return Result.ok(invoice)

        except Exception as e:
            _services_logger.error(f"🔥 [Conversion] Failed to convert proforma {proforma_id}: {e}")
            return Result.err(f"Conversion failed: {e!s}")


# Expose all services in __all__ for explicit imports
__all__ = [
    # Usage-based billing services
    "AggregationService",
    # Core billing services
    "BillingAnalyticsService",
    "BillingCycleManager",
    "EFacturaService",
    "InvoiceNumberingService",
    "InvoiceService",
    "MeteringService",
    "PaymentRetryService",
    "ProformaConversionService",
    "ProformaService",
    "RatingEngine",
    # Refund services
    "RefundData",
    "RefundEligibility",
    "RefundQueryService",
    "RefundReason",
    "RefundResult",
    "RefundService",
    "RefundStatus",
    "RefundType",
    "Result",
    # Stripe metering services
    "StripeMeterEventService",
    "StripeMeterService",
    "StripeMeterWebhookHandler",
    "StripeSubscriptionMeterService",
    "StripeUsageSyncService",
    "UsageAlertService",
    "UsageEventData",
    "UsageInvoiceService",
    # Helper functions
    "generate_e_factura_xml",
    "generate_invoice_pdf",
    "generate_proforma_pdf",
    "generate_vat_summary",
    "log_security_event",
    "send_invoice_email",
    "send_proforma_email",
]
