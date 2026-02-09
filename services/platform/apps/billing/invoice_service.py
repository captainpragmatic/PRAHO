"""
Invoice Services for PRAHO Platform
Business logic for invoice management and Romanian e-Factura compliance.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db.models import Sum
from django.template.loader import render_to_string
from django.utils import timezone

if TYPE_CHECKING:
    from apps.customers.models import Customer

    from .invoice_models import Invoice

logger = logging.getLogger(__name__)


# ===============================================================================
# BILLING ANALYTICS SERVICE
# ===============================================================================


class BillingAnalyticsService:
    """
    Service for tracking billing analytics and KPIs.
    """

    @staticmethod
    def update_invoice_metrics(invoice: Invoice, event_type: str) -> dict[str, Any]:
        """
        Update invoice-level metrics when invoices change.

        Args:
            invoice: Invoice instance
            event_type: Type of event ('created', 'paid', 'overdue', 'cancelled')

        Returns:
            Dictionary with metrics update details
        """
        from apps.audit.services import AuditService  # noqa: PLC0415

        try:
            metrics = {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "event_type": event_type,
                "amount_cents": invoice.total_cents,
                "updated_at": timezone.now().isoformat(),
            }

            # Update aggregate metrics based on event type
            if event_type == "paid":
                metrics["payment_time_days"] = (
                    (timezone.now() - invoice.created_at).days if invoice.created_at else 0
                )
            elif event_type == "overdue":
                metrics["overdue_amount"] = invoice.total_cents

            AuditService.log_simple_event(
                event_type="invoice_metrics_updated",
                user=None,
                content_object=invoice,
                description=f"Invoice metrics updated for {invoice.number}: {event_type}",
                actor_type="system",
                metadata=metrics,
            )

            logger.info(f"📊 [Analytics] Updated invoice metrics for {invoice.number} - {event_type}")
            return {"success": True, **metrics}

        except Exception as e:
            logger.error(f"🔥 [Analytics] Failed to update invoice metrics: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def update_customer_metrics(customer: Customer, invoice: Invoice) -> dict[str, Any]:
        """
        Update customer billing analytics.

        Args:
            customer: Customer instance
            invoice: Invoice that triggered the update

        Returns:
            Dictionary with customer metrics
        """
        from apps.billing.models import Invoice as InvoiceModel  # noqa: PLC0415
        from apps.billing.models import Payment  # noqa: PLC0415

        try:
            # Calculate customer billing stats
            invoices = InvoiceModel.objects.filter(customer=customer)
            payments = Payment.objects.filter(invoice__customer=customer, status="succeeded")

            total_invoiced = invoices.aggregate(total=Sum("total_cents"))["total"] or 0
            total_paid = payments.aggregate(total=Sum("amount_cents"))["total"] or 0
            outstanding = total_invoiced - total_paid

            metrics = {
                "customer_id": str(customer.id),
                "total_invoiced_cents": total_invoiced,
                "total_paid_cents": total_paid,
                "outstanding_cents": outstanding,
                "invoice_count": invoices.count(),
                "paid_invoice_count": invoices.filter(status="paid").count(),
                "updated_at": timezone.now().isoformat(),
            }

            # Update customer metadata if available
            if hasattr(customer, "meta") and customer.meta is not None:
                customer.meta["billing_metrics"] = metrics
                customer.save(update_fields=["meta", "updated_at"])

            logger.info(f"📊 [Analytics] Updated customer metrics for {customer}")
            return {"success": True, **metrics}

        except Exception as e:
            logger.error(f"🔥 [Analytics] Failed to update customer metrics: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def record_invoice_refund(invoice: Invoice, refund_date: datetime) -> dict[str, Any]:
        """
        Record invoice refund for analytics.

        Args:
            invoice: Invoice being refunded
            refund_date: Date of the refund

        Returns:
            Dictionary with refund record details
        """
        from apps.audit.services import AuditService  # noqa: PLC0415

        try:
            refund_data = {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "refund_amount_cents": invoice.total_cents,
                "refund_date": refund_date.isoformat(),
                "customer_id": str(invoice.customer.id) if invoice.customer else None,
            }

            AuditService.log_simple_event(
                event_type="invoice_refund_recorded",
                user=None,
                content_object=invoice,
                description=f"Refund recorded for invoice {invoice.number}",
                actor_type="system",
                metadata=refund_data,
            )

            logger.info(f"📊 [Analytics] Recorded refund for invoice {invoice.number}")
            return {"success": True, **refund_data}

        except Exception as e:
            logger.error(f"🔥 [Analytics] Failed to record refund: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def adjust_customer_ltv(customer: Customer, adjustment_amount_cents: int, adjustment_reason: str) -> dict[str, Any]:
        """
        Adjust customer lifetime value.

        Args:
            customer: Customer whose LTV to adjust
            adjustment_amount_cents: Amount to adjust (positive or negative)
            adjustment_reason: Reason for the adjustment

        Returns:
            Dictionary with LTV adjustment details
        """
        from apps.audit.services import AuditService  # noqa: PLC0415

        try:
            adjustment_amount = Decimal(adjustment_amount_cents) / 100

            # Get current LTV from customer metadata
            current_ltv = 0
            if hasattr(customer, "meta") and customer.meta:
                current_ltv = customer.meta.get("lifetime_value_cents", 0)

            new_ltv = current_ltv + adjustment_amount_cents

            # Update customer metadata
            if hasattr(customer, "meta") and customer.meta is not None:
                customer.meta["lifetime_value_cents"] = new_ltv
                customer.meta["ltv_last_adjusted"] = timezone.now().isoformat()
                customer.save(update_fields=["meta", "updated_at"])

            adjustment_data = {
                "customer_id": str(customer.id),
                "previous_ltv_cents": current_ltv,
                "adjustment_cents": adjustment_amount_cents,
                "new_ltv_cents": new_ltv,
                "reason": adjustment_reason,
            }

            AuditService.log_simple_event(
                event_type="customer_ltv_adjusted",
                user=None,
                content_object=customer,
                description=f"LTV adjusted for {customer} by €{adjustment_amount:.2f} ({adjustment_reason})",
                actor_type="system",
                metadata=adjustment_data,
            )

            logger.info(f"📊 [Analytics] Adjusted LTV for {customer} by €{adjustment_amount:.2f}")
            return {"success": True, **adjustment_data}

        except Exception as e:
            logger.error(f"🔥 [Analytics] Failed to adjust LTV: {e}")
            return {"success": False, "error": str(e)}


# ===============================================================================
# PDF GENERATION & EMAIL SERVICES
# ===============================================================================


def generate_invoice_pdf(invoice: Invoice) -> bytes:
    """
    Generate PDF for an invoice.

    Args:
        invoice: Invoice instance to generate PDF for

    Returns:
        PDF content as bytes
    """
    try:
        # Try to use weasyprint for PDF generation
        try:
            from weasyprint import HTML  # noqa: PLC0415
        except ImportError:
            logger.warning("⚠️ [PDF] weasyprint not installed, returning placeholder PDF")
            return _generate_placeholder_pdf(invoice)

        # Render HTML template
        context = {
            "invoice": invoice,
            "company": {
                "name": getattr(settings, "COMPANY_NAME", "PRAHO Platform"),
                "address": getattr(settings, "COMPANY_ADDRESS", ""),
                "vat_number": getattr(settings, "COMPANY_VAT_NUMBER", ""),
                "bank_details": getattr(settings, "COMPANY_BANK_DETAILS", ""),
            },
            "customer": invoice.customer,
            "items": invoice.items.all() if hasattr(invoice, "items") else [],
        }

        html_content = render_to_string("billing/invoice_pdf.html", context)

        # Generate PDF
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(pdf_file)
        pdf_content = pdf_file.getvalue()

        logger.info(f"📄 [PDF] Generated PDF for invoice {invoice.number} ({len(pdf_content)} bytes)")
        return pdf_content

    except Exception as e:
        logger.error(f"🔥 [PDF] Failed to generate PDF for invoice {invoice.number}: {e}")
        return _generate_placeholder_pdf(invoice)


def _generate_placeholder_pdf(invoice: Invoice) -> bytes:
    """Generate a simple placeholder PDF when weasyprint is not available."""
    # Return a minimal PDF structure
    content = f"""Invoice: {invoice.number}
Customer: {invoice.customer.get_display_name() if invoice.customer else 'N/A'}
Amount: {Decimal(invoice.total_cents) / 100:.2f}
Date: {invoice.created_at.strftime('%Y-%m-%d') if invoice.created_at else 'N/A'}

This is a placeholder PDF. Install weasyprint for proper PDF generation.
"""
    return content.encode("utf-8")


def generate_e_factura_xml(invoice: Invoice) -> str:
    """
    Generate e-Factura XML for Romanian compliance.

    Args:
        invoice: Invoice to generate e-Factura XML for

    Returns:
        e-Factura compliant XML string
    """
    try:
        # Build e-Factura XML structure according to Romanian ANAF specifications
        customer = invoice.customer
        items = invoice.items.all() if hasattr(invoice, "items") else []

        # Calculate totals
        total_without_vat = Decimal(invoice.subtotal_cents or 0) / 100
        vat_amount = Decimal(invoice.tax_cents or 0) / 100
        total_with_vat = Decimal(invoice.total_cents or 0) / 100

        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
    <cbc:ID>{invoice.number}</cbc:ID>
    <cbc:IssueDate>{invoice.created_at.strftime('%Y-%m-%d') if invoice.created_at else ''}</cbc:IssueDate>
    <cbc:DueDate>{invoice.due_date.strftime('%Y-%m-%d') if hasattr(invoice, 'due_date') and invoice.due_date else ''}</cbc:DueDate>
    <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
    <cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>

    <cac:AccountingSupplierParty>
        <cac:Party>
            <cac:PartyName>
                <cbc:Name>{getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}</cbc:Name>
            </cac:PartyName>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>{getattr(settings, 'COMPANY_VAT_NUMBER', '')}</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
        </cac:Party>
    </cac:AccountingSupplierParty>

    <cac:AccountingCustomerParty>
        <cac:Party>
            <cac:PartyName>
                <cbc:Name>{customer.get_display_name() if customer else ''}</cbc:Name>
            </cac:PartyName>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>{customer.vat_number if customer and hasattr(customer, 'vat_number') else ''}</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
        </cac:Party>
    </cac:AccountingCustomerParty>

    <cac:TaxTotal>
        <cbc:TaxAmount currencyID="RON">{vat_amount:.2f}</cbc:TaxAmount>
    </cac:TaxTotal>

    <cac:LegalMonetaryTotal>
        <cbc:LineExtensionAmount currencyID="RON">{total_without_vat:.2f}</cbc:LineExtensionAmount>
        <cbc:TaxExclusiveAmount currencyID="RON">{total_without_vat:.2f}</cbc:TaxExclusiveAmount>
        <cbc:TaxInclusiveAmount currencyID="RON">{total_with_vat:.2f}</cbc:TaxInclusiveAmount>
        <cbc:PayableAmount currencyID="RON">{total_with_vat:.2f}</cbc:PayableAmount>
    </cac:LegalMonetaryTotal>
</Invoice>"""

        logger.info(f"🇷🇴 [e-Factura] Generated XML for invoice {invoice.number}")
        return xml_content

    except Exception as e:
        logger.error(f"🔥 [e-Factura] Failed to generate XML for invoice {invoice.number}: {e}")
        raise


def send_invoice_email(invoice: Invoice, recipient_email: str | None = None) -> bool:
    """
    Send invoice via email.

    Args:
        invoice: Invoice to send
        recipient_email: Optional override for recipient email

    Returns:
        True if email was sent successfully
    """
    from django.core.mail import EmailMessage  # noqa: PLC0415

    try:
        email = recipient_email or (invoice.customer.primary_email if invoice.customer else None)

        if not email:
            logger.error(f"🔥 [Email] No recipient email for invoice {invoice.number}")
            return False

        # Generate PDF attachment
        pdf_content = generate_invoice_pdf(invoice)

        # Build email
        subject = f"Invoice {invoice.number} from {getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}"

        body = f"""Dear {invoice.customer.get_display_name() if invoice.customer else 'Customer'},

Please find attached invoice {invoice.number}.

Invoice Details:
- Invoice Number: {invoice.number}
- Amount: €{Decimal(invoice.total_cents) / 100:.2f}
- Due Date: {invoice.due_date.strftime('%Y-%m-%d') if hasattr(invoice, 'due_date') and invoice.due_date else 'N/A'}

Thank you for your business.

Best regards,
{getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}
"""

        email_message = EmailMessage(
            subject=subject,
            body=body,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@praho.io"),
            to=[email],
        )

        # Attach PDF
        email_message.attach(
            f"invoice_{invoice.number}.pdf",
            pdf_content,
            "application/pdf",
        )

        email_message.send()

        logger.info(f"📧 [Email] Sent invoice {invoice.number} to {email}")
        return True

    except Exception as e:
        logger.error(f"🔥 [Email] Failed to send invoice {invoice.number}: {e}")
        return False


def generate_vat_summary(period_start: str, period_end: str) -> dict[str, Any]:
    """
    Generate VAT summary report for Romanian compliance.

    Args:
        period_start: Start date of the reporting period (YYYY-MM-DD)
        period_end: End date of the reporting period (YYYY-MM-DD)

    Returns:
        Dictionary with VAT summary data
    """
    from apps.billing.models import Invoice  # noqa: PLC0415

    try:
        start_date = datetime.strptime(period_start, "%Y-%m-%d")
        end_date = datetime.strptime(period_end, "%Y-%m-%d")

        # Get invoices in the period
        invoices = Invoice.objects.filter(
            created_at__gte=start_date,
            created_at__lte=end_date,
            status__in=["paid", "sent"],
        )

        # Calculate totals
        total_sales_cents = invoices.aggregate(total=Sum("subtotal_cents"))["total"] or 0
        total_vat_cents = invoices.aggregate(total=Sum("tax_cents"))["total"] or 0
        total_amount_cents = invoices.aggregate(total=Sum("total_cents"))["total"] or 0

        # Group by VAT rate
        vat_breakdown = {}
        for invoice in invoices:
            vat_rate = getattr(invoice, "vat_rate", 19)  # Default 19% for Romania
            if vat_rate not in vat_breakdown:
                vat_breakdown[vat_rate] = {"sales": 0, "vat": 0, "count": 0}
            vat_breakdown[vat_rate]["sales"] += invoice.subtotal_cents or 0
            vat_breakdown[vat_rate]["vat"] += invoice.tax_cents or 0
            vat_breakdown[vat_rate]["count"] += 1

        summary = {
            "period_start": period_start,
            "period_end": period_end,
            "total_sales": Decimal(total_sales_cents) / 100,
            "total_vat": Decimal(total_vat_cents) / 100,
            "total_amount": Decimal(total_amount_cents) / 100,
            "invoice_count": invoices.count(),
            "vat_breakdown": {
                rate: {
                    "sales": Decimal(data["sales"]) / 100,
                    "vat": Decimal(data["vat"]) / 100,
                    "count": data["count"],
                }
                for rate, data in vat_breakdown.items()
            },
            "generated_at": timezone.now().isoformat(),
        }

        logger.info(f"🇷🇴 [VAT Report] Generated VAT summary for {period_start} to {period_end}")
        return summary

    except Exception as e:
        logger.error(f"🔥 [VAT Report] Failed to generate VAT summary: {e}")
        return {
            "period_start": period_start,
            "period_end": period_end,
            "error": str(e),
        }
