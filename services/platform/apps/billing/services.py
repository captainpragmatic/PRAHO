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

from decimal import Decimal

# Re-export all services from feature files
# TODO: RefundService implementation pending - temporarily comment out
# TODO: Add RefundService imports when implemented
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

# Import usage-based billing services
from .metering_service import (
    AggregationService,
    MeteringService,
    RatingEngine,
    UsageAlertService,
    UsageEventData,
)
from .usage_invoice_service import (
    BillingCycleManager,
    UsageInvoiceService,
)
from .stripe_metering import (
    StripeMeterService,
    StripeMeterEventService,
    StripeSubscriptionMeterService,
    StripeUsageSyncService,
    StripeMeterWebhookHandler,
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
        from django.db import IntegrityError, transaction

        try:
            with transaction.atomic():
                # Get default currency (RON) - use get_or_create with proper error handling
                try:
                    currency = Currency.objects.get(code="RON")
                except Currency.DoesNotExist:
                    # Use get_or_create inside atomic block to handle concurrent creation
                    currency, _ = Currency.objects.get_or_create(
                        code="RON",
                        defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
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

<<<<<<< HEAD
            # Calculate totals using current Romanian VAT rate (21%)
            from apps.common.tax_service import TaxService
            vat_rate = TaxService.get_vat_rate('RO', as_decimal=True)
            subtotal_amount = Decimal(order.total_cents) / 100
            tax_amount = subtotal_amount * vat_rate
            total_amount = subtotal_amount + tax_amount
=======
                # Calculate totals (assuming 19% VAT for Romania)
                vat_rate = Decimal("0.19")
                subtotal_amount = Decimal(order.total_cents) / 100
                tax_amount = subtotal_amount * vat_rate
                total_amount = subtotal_amount + tax_amount
>>>>>>> origin/claude/fix-race-conditions-yreZe

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


# Missing services that need to be created/imported
class PaymentRetryService:
    """Placeholder for payment retry functionality"""

    @staticmethod
    def retry_payment(payment_id: str) -> Result[bool, str]:
        # TODO: Implement payment retry logic
        return Result.ok(True)


class EFacturaService:
    """Placeholder for e-Factura integration"""

    @staticmethod
    def submit_invoice(invoice_id: str) -> Result[bool, str]:
        # TODO: Implement e-Factura submission
        return Result.ok(True)


class InvoiceNumberingService:
    """Placeholder for invoice numbering"""

    @staticmethod
    def get_next_number() -> str:
        # TODO: Implement proper numbering
        return "INV-001"


class ProformaConversionService:
    """Placeholder for proforma to invoice conversion"""

    @staticmethod
    def convert_to_invoice(proforma_id: str) -> Result[bool, str]:
        # TODO: Implement conversion logic
        return Result.ok(True)


# Expose all services in __all__ for explicit imports
__all__ = [
    # Core billing services
    "BillingAnalyticsService",
    "EFacturaService",
    "InvoiceNumberingService",
    "InvoiceService",
    "PaymentRetryService",
    "ProformaConversionService",
    "ProformaService",
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
    # Usage-based billing services
    "AggregationService",
    "BillingCycleManager",
    "MeteringService",
    "RatingEngine",
    "UsageAlertService",
    "UsageEventData",
    "UsageInvoiceService",
    # Stripe metering services
    "StripeMeterEventService",
    "StripeMeterService",
    "StripeMeterWebhookHandler",
    "StripeSubscriptionMeterService",
    "StripeUsageSyncService",
    # Helper functions
    "generate_e_factura_xml",
    "generate_invoice_pdf",
    "generate_proforma_pdf",
    "generate_vat_summary",
    "log_security_event",
    "send_invoice_email",
    "send_proforma_email",
]
