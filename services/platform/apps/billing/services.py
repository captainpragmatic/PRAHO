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
- UsageBillingService: Local usage cycle close and invoice management
- PRAHO-owned usage invoice services

This file serves as a re-export hub following ADR-0012 feature-based organization.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal

# Re-export all services from feature files
# ===============================================================================
# RESULT PATTERN FOR REFUND OPERATIONS
# ===============================================================================
from typing import Any

from django.db import transaction
from django.utils import timezone as tz

from apps.billing.currency_models import Currency as CurrencyModel
from apps.billing.fiscal_identity import (
    billing_country_code,
    get_customer_fiscal_identity,
    normalize_business_tax_id,
    validated_cnp_or_empty,
)
from apps.billing.models import Invoice, InvoiceLine
from apps.common.financial_arithmetic import calculate_document_totals
from apps.common.tax_service import CustomerVATInfo, TaxService
from apps.common.types import Err, Ok, Result

# Add imports to fix PLC0415 linting issues
# Ensure refund service uses the same log_security_event function for testing
from .invoice_service import (
    BillingAnalyticsService,
    generate_e_factura_xml,
    generate_invoice_pdf,
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
from .numbering_service import InvoiceNumberingService
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
)
from .usage_invoice_service import (
    UsageBillingService,
    UsageInvoiceService,
)

# Result types imported from apps.common.types (ADR-0003)

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
        try:
            with transaction.atomic():
                order_items = tuple(order.items.all())
                requested_discount_cents = int(getattr(order, "discount_cents", 0) or 0)
                source_totals = calculate_document_totals(order_items, requested_discount_cents)
                taxable_subtotal_cents = source_totals.total_cents - source_totals.tax_cents
                order_discount_cents = source_totals.subtotal_cents - taxable_subtotal_cents

                # VAT is computed on the NET taxable base (gross line subtotal minus the
                # document discount), mirroring the proforma conversion path. order.total_cents
                # is the GROSS tax-INCLUSIVE total — feeding it here re-applied VAT on top of an
                # already-taxed amount and double-taxed the invoice header.
                billing_address = order.billing_address or {}
                bill_to_country = billing_country_code(billing_address.get("country"))
                vat_result = TaxService.calculate_vat_for_document(
                    subtotal_cents=taxable_subtotal_cents,
                    customer_info=_build_customer_vat_info(
                        order.customer,
                        order_id=str(order.id),
                        country=bill_to_country,
                    ),
                )
                fiscal_identity = get_customer_fiscal_identity(order.customer)
                business_tax_id = (
                    normalize_business_tax_id(billing_address.get("vat_number", ""))
                    or normalize_business_tax_id(billing_address.get("vat_id", ""))
                    or fiscal_identity.business_tax_id
                )

                # Create invoice - all within the same atomic block to ensure consistency
                invoice = Invoice.objects.create(
                    customer=order.customer,
                    number=InvoiceNumberingService.get_next_number(),
                    currency=order.currency,
                    subtotal_cents=vat_result.subtotal_cents,
                    tax_cents=vat_result.vat_cents,
                    total_cents=vat_result.total_cents,
                    discount_cents=order_discount_cents,
                    status="draft",
                    bill_to_name=billing_address.get("company_name", "") or order.customer_name,
                    bill_to_tax_id=business_tax_id,
                    bill_to_cnp=fiscal_identity.cnp if not business_tax_id else "",
                    bill_to_email=order.customer_email,
                    bill_to_address1=billing_address.get("address_line1", "") or billing_address.get("line1", ""),
                    bill_to_address2=billing_address.get("address_line2", "") or billing_address.get("line2", ""),
                    bill_to_city=billing_address.get("city", ""),
                    bill_to_region=billing_address.get("county", "") or billing_address.get("region", ""),
                    bill_to_postal=billing_address.get("postal_code", "") or billing_address.get("postal", ""),
                    bill_to_country=bill_to_country,
                    meta={"order_id": str(order.id)},
                )

                # Create invoice lines from order items.
                # InvoiceLine.save() recomputes tax_cents/line_total_cents from the subtotal
                # (qty*unit_price) and tax_rate, so only the inputs are set here.
                vat_rate_decimal = (vat_result.vat_rate / Decimal("100")).quantize(Decimal("0.0001"))
                for item in order_items:
                    InvoiceLine.objects.create(
                        invoice=invoice,
                        kind="service",
                        description=item.product_name or f"Order item {item.id}",
                        quantity=item.quantity,
                        unit_price_cents=item.unit_price_cents,
                        tax_rate=vat_rate_decimal,
                    )
                    # Setup fee as its own line so Σ(line gross) includes it (EN16931 BT-106) and
                    # the invoice lines reconcile with the header subtotal (which counts setup via
                    # OrderItem.subtotal_cents), mirroring the proforma conversion path.
                    setup_cents = int(getattr(item, "setup_cents", 0) or 0)
                    if setup_cents > 0:
                        InvoiceLine.objects.create(
                            invoice=invoice,
                            kind="service",
                            description=f"Setup fee - {item.product_name or item.id}",
                            quantity=Decimal("1"),
                            unit_price_cents=setup_cents,
                            tax_rate=vat_rate_decimal,
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

                return Ok(invoice)

        except Exception as e:
            return Err(f"Failed to create invoice from order: {e!s}")


_services_logger = logging.getLogger(__name__)


def _build_customer_vat_info(
    customer: Any,
    order_id: str | None = None,
    *,
    country: object | None = None,
) -> CustomerVATInfo:
    """Build customer VAT context for TaxService.calculate_vat_for_document()."""
    country_source = country
    if country_source is None:
        billing_address = customer.get_billing_address()
        country_source = getattr(billing_address, "country", "")
    info: CustomerVATInfo = {
        "country": billing_country_code(country_source),
        "is_business": bool(getattr(customer, "company_name", "")),
        "vat_number": None,
        "customer_id": str(getattr(customer, "id", "")),
        "order_id": order_id,
    }
    try:
        tax_profile = customer.tax_profile
    except Exception:
        return info

    info["vat_number"] = getattr(tax_profile, "vat_number", None)
    info["is_vat_payer"] = bool(getattr(tax_profile, "is_vat_payer", False))
    info["reverse_charge_eligible"] = bool(getattr(tax_profile, "reverse_charge_eligible", False))
    vat_rate_override = getattr(tax_profile, "vat_rate", None)
    if vat_rate_override is not None:
        info["custom_vat_rate"] = vat_rate_override
    return info


class PaymentRetryService:
    """Schedule payment retries using dunning policies."""

    @staticmethod
    def retry_payment(payment_id: str) -> Result[bool, str]:
        """Find customer's retry policy and schedule a PaymentRetryAttempt."""
        from apps.billing.models import Payment  # noqa: PLC0415  # Deferred: test mockability
        from apps.billing.payment_models import (  # noqa: PLC0415  # Deferred: test mockability
            PaymentRetryAttempt,
            PaymentRetryPolicy,
        )

        try:
            payment = Payment.objects.select_related("customer").get(id=payment_id)
        except Payment.DoesNotExist:
            return Err(f"Payment not found: {payment_id}")

        if payment.status == "succeeded":
            return Ok(True)  # Already succeeded

        # Find applicable retry policy (customer-specific or default)
        policy = PaymentRetryPolicy.objects.filter(is_active=True, is_default=True).first()
        if not policy:
            _services_logger.warning(f"⚠️ [Retry] No active retry policy for payment {payment_id}")
            return Err("No retry policy configured")

        # Check if max attempts reached
        existing_attempts = PaymentRetryAttempt.objects.filter(payment=payment).count()
        if existing_attempts >= policy.max_attempts:
            return Err(f"Max retry attempts ({policy.max_attempts}) reached")

        # Schedule next retry
        next_retry_date = policy.get_next_retry_date(payment.created_at, existing_attempts)
        if not next_retry_date:
            return Err("No more retry dates available")

        PaymentRetryAttempt.objects.get_or_create(
            payment=payment,
            attempt_number=existing_attempts + 1,
            defaults={
                "policy": policy,
                "scheduled_at": next_retry_date,
                "status": "pending",
            },
        )
        _services_logger.info(
            f"✅ [Retry] Scheduled retry #{existing_attempts + 1} for payment {payment_id} at {next_retry_date}"
        )
        return Ok(True)


class EFacturaService:
    """Compatibility facade over the canonical e-Factura document lifecycle."""

    @staticmethod
    def submit_invoice(invoice_id: str) -> Result[bool, str]:
        """Submit an invoice through the canonical e-Factura service."""
        from apps.billing.efactura.service import EFacturaService as CanonicalEFacturaService  # noqa: PLC0415
        from apps.billing.models import Invoice as InvoiceModel  # noqa: PLC0415  # Deferred: test mockability

        try:
            invoice = InvoiceModel.objects.get(id=invoice_id)
        except InvoiceModel.DoesNotExist:
            return Err(f"Invoice not found: {invoice_id}")

        service = CanonicalEFacturaService()
        result = service.submit_invoice(invoice)
        if result.success:
            _services_logger.info(
                f"✅ [e-Factura] Processed invoice {invoice.number} with status {result.document_status or 'unknown'}"
            )
            return Ok(True)
        return Err(result.error_message or "e-Factura submission failed")


class ProformaConversionService:
    """Convert proforma invoices to real invoices."""

    @staticmethod
    @transaction.atomic
    def convert_to_invoice(proforma_id: str) -> Result[Any, str]:
        """Convert a proforma to a real invoice with tax recalculation."""
        from apps.billing.models import ProformaInvoice  # noqa: PLC0415  # Deferred: test mockability

        try:
            # RC-1: Lock proforma to prevent concurrent conversion creating duplicate invoices
            proforma = (
                ProformaInvoice.objects.select_for_update(of=("self",))
                .select_related("customer", "currency")
                .get(id=proforma_id)
            )
        except ProformaInvoice.DoesNotExist:
            return Err(f"Proforma not found: {proforma_id}")

        if proforma.status not in ("draft", "sent", "accepted"):
            return Err(f"Proforma {proforma.number} cannot be converted (status: {proforma.status})")

        try:
            with transaction.atomic():
                # Get invoice sequence
                currency = proforma.currency

                if not currency:
                    currency, _ = CurrencyModel.objects.get_or_create(
                        code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
                    )

                # C1 fix: Copy proforma totals verbatim — never recalculate.
                # The proforma IS the agreed quote. Recalculating would cause
                # invoice amounts to diverge if VAT rates changed after quoting.
                subtotal_cents = proforma.subtotal_cents or 0
                tax_cents = proforma.tax_cents or 0
                total_cents = proforma.total_cents or 0
                business_tax_id = normalize_business_tax_id(getattr(proforma, "bill_to_tax_id", ""))
                personal_tax_id = (
                    "" if business_tax_id else validated_cnp_or_empty(getattr(proforma, "bill_to_cnp", ""))
                )

                invoice = Invoice.objects.create(
                    customer=proforma.customer,
                    number=InvoiceNumberingService.get_next_number(),
                    currency=currency,
                    subtotal_cents=subtotal_cents,
                    tax_cents=tax_cents,
                    total_cents=total_cents,
                    discount_cents=proforma.discount_cents,
                    due_at=tz.now() + timedelta(days=30),
                    bill_to_name=proforma.bill_to_name or "",
                    bill_to_email=proforma.bill_to_email or "",
                    bill_to_tax_id=business_tax_id,
                    bill_to_cnp=personal_tax_id,
                    bill_to_registration_number=getattr(proforma, "bill_to_registration_number", "") or "",
                    bill_to_address1=getattr(proforma, "bill_to_address1", "") or "",
                    bill_to_address2=getattr(proforma, "bill_to_address2", "") or "",
                    bill_to_city=getattr(proforma, "bill_to_city", "") or "",
                    bill_to_region=getattr(proforma, "bill_to_region", "") or "",
                    bill_to_postal=getattr(proforma, "bill_to_postal", "") or "",
                    bill_to_country=billing_country_code(getattr(proforma, "bill_to_country", "")),
                    meta={"proforma_id": str(proforma.id), "proforma_number": proforma.number},
                )
                # Issue via FSM transition to set locked_at and issued_at
                invoice.issue()
                invoice.save()

                # Copy line items — copy ALL fields including EN16931 and financial fields
                for line in proforma.lines.all():
                    InvoiceLine.objects.create(
                        invoice=invoice,
                        kind=line.kind,
                        service=line.service,
                        billing_cycle=line.billing_cycle,
                        description=line.description,
                        quantity=line.quantity,
                        unit_price_cents=line.unit_price_cents,
                        tax_rate=line.tax_rate,
                        tax_cents=line.tax_cents,
                        line_total_cents=line.line_total_cents,
                        domain_name=line.domain_name,
                        period_start=line.period_start,
                        period_end=line.period_end,
                        unit_code=line.unit_code,
                        tax_category_code=line.tax_category_code,
                        note=line.note,
                        discount_amount_cents=line.discount_amount_cents,
                        seller_item_id=line.seller_item_id,
                        sort_order=line.sort_order,
                    )

                from apps.billing.metering_models import BillingCycle  # noqa: PLC0415

                BillingCycle.objects.filter(proforma=proforma).update(invoice=invoice)

                # Update proforma status via FSM transition
                proforma.convert()
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
                return Ok(invoice)

        except Exception as e:
            _services_logger.error(f"🔥 [Conversion] Failed to convert proforma {proforma_id}: {e}")
            return Err(f"Conversion failed: {e!s}")


# Expose all services in __all__ for explicit imports
__all__ = [
    # Usage-based billing services
    "AggregationService",
    # Core billing services
    "BillingAnalyticsService",
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
    "UsageAlertService",
    "UsageBillingService",
    "UsageEventData",
    "UsageInvoiceService",
    # Helper functions
    "generate_e_factura_xml",
    "generate_invoice_pdf",
    "generate_proforma_pdf",
    "log_security_event",
    "send_invoice_email",
    "send_proforma_email",
]
