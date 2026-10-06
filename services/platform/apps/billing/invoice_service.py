"""
Invoice Services for PRAHO Platform
Business logic for invoice management and Romanian e-Factura compliance.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, time
from decimal import ROUND_HALF_UP, Decimal, DecimalException
from typing import TYPE_CHECKING, Any, Required, TypedDict

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.utils.translation import gettext as _

from apps.billing.document_adjustments import UnsupportedDocumentAdjustmentError, validate_no_unsupported_adjustments
from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User

    from .invoice_models import Invoice, InvoiceLine

logger = logging.getLogger(__name__)
_MAX_DRAFT_PRICE_CENTS = (1 << 63) - 1


class DraftInvoiceLineData(TypedDict, total=False):
    id: str
    description: str
    quantity: str
    unit_price: str
    tax_rate: str
    tax_category_code: str


class DraftInvoiceData(TypedDict, total=False):
    customer: str
    currency: str
    due_at: str
    public_notes: str
    internal_notes: str
    lines: Required[list[DraftInvoiceLineData]]


def draft_invoice_edit_block_reason(invoice: Invoice) -> str | None:
    """Read eligibility here; the mutation calls it again under the invoice lock."""
    from apps.billing.payment_models import CreditLedger  # noqa: PLC0415

    if invoice.status != "draft" or invoice.locked_at is not None:
        return _("Only an unlocked draft invoice can be edited.")
    if invoice.issuer_provider != "builtin":
        return _("External issuer drafts are read-only. Use issuance reconciliation.")
    if invoice.document_kind == "credit_note":
        return _("Credit notes cannot be edited.")
    if (
        invoice.payments.exists()
        or CreditLedger.objects.filter(invoice=invoice).exists()
        or invoice.gift_card_reservations.exists()
    ):
        return _("Invoices with payment, credit or gift-card allocations cannot be edited.")
    try:
        if invoice.discount_cents:
            raise UnsupportedDocumentAdjustmentError
        validate_no_unsupported_adjustments(
            meta=invoice.meta,
            line_discount_cents=invoice.lines.values_list("discount_amount_cents", flat=True),
        )
    except UnsupportedDocumentAdjustmentError:
        return _("Invoices with discounts or adjustments cannot be edited.")
    return None


def _draft_decimal(value: str) -> Decimal:
    if not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value):
        raise ValidationError(_("Line quantities and prices must be valid finite numbers."))
    try:
        parsed = Decimal(value)
    except DecimalException as exc:
        raise ValidationError(_("Line quantities and prices must be valid finite numbers.")) from exc
    if not parsed.is_finite():
        raise ValidationError(_("Line quantities and prices must be valid finite numbers."))
    return parsed


def _draft_line_id(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValidationError(_("Invalid invoice line ID."))
    return int(value)


def _draft_line_ids(rows: list[DraftInvoiceLineData], existing: dict[int, InvoiceLine]) -> set[int]:
    seen: set[int] = set()
    for row in rows:
        if not row.get("id"):
            continue
        line_id = _draft_line_id(row["id"])
        if line_id not in existing:
            raise ValidationError(_("An invoice line belongs to another invoice or no longer exists."))
        if line_id in seen:
            raise ValidationError(_("Duplicate invoice line ID."))
        seen.add(line_id)
    for line_id, line in existing.items():
        if line_id not in seen and line.billing_cycle_id is not None:
            raise ValidationError(_("Billing-cycle lines cannot be deleted or repriced."))
    return seen


def _recorded_draft_line_tax(invoice: Invoice) -> tuple[Decimal, str]:
    from apps.billing.tax_evidence import derive_tax_category, read_vat_evidence  # noqa: PLC0415
    from apps.common.tax_service import VATCalculationResult  # noqa: PLC0415

    decision = read_vat_evidence(invoice)
    if decision is None:
        raise ValidationError(_("A new line requires a recorded invoice tax decision."))
    result = VATCalculationResult(
        scenario=decision.scenario,
        vat_rate=decision.rate,
        subtotal_cents=decision.subtotal_cents,
        vat_cents=decision.tax_cents,
        total_cents=decision.total_cents,
        country_code=decision.country,
        is_business=decision.is_business,
        vat_number=decision.vat_number,
        reasoning="",
        audit_data={},
    )
    return (decision.rate / Decimal("100")).quantize(Decimal("0.0001")), derive_tax_category(result)


def _save_draft_line(invoice: Invoice, row: DraftInvoiceLineData, existing: dict[int, InvoiceLine]) -> None:
    from apps.billing.invoice_models import InvoiceLine  # noqa: PLC0415

    quantity = _draft_decimal(row.get("quantity", ""))
    price = _draft_decimal(row.get("unit_price", ""))
    if quantity <= 0 or quantity > Decimal("999999999.999") or price < 0:
        raise ValidationError(_("Line quantity must be positive and price must not be negative."))
    if price > Decimal(_MAX_DRAFT_PRICE_CENTS) / 100:
        raise ValidationError(_("Line quantities or prices are out of range."))
    try:
        quantity = quantity.quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
        cents = int((price * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except DecimalException as exc:
        raise ValidationError(_("Line quantities or prices are out of range.")) from exc
    if quantity <= 0 or cents > _MAX_DRAFT_PRICE_CENTS:
        raise ValidationError(_("Line quantities or prices are out of range."))
    if row.get("id"):
        line = existing[_draft_line_id(row["id"])]
        if ("tax_rate" in row and row["tax_rate"] != str(line.tax_rate)) or (
            "tax_category_code" in row and row["tax_category_code"] != line.tax_category_code
        ):
            raise ValidationError(_("The recorded VAT rate and category cannot be edited."))
        if line.billing_cycle_id is not None and (quantity != line.quantity or cents != line.unit_price_cents):
            raise ValidationError(_("Billing-cycle lines cannot be deleted or repriced."))
    else:
        rate, category = _recorded_draft_line_tax(invoice)
        line = InvoiceLine(invoice=invoice, kind="service", tax_rate=rate, tax_category_code=category)
    line.description = row.get("description", "").strip()
    line.quantity = quantity
    line.unit_price_cents = cents
    line.calculate_totals()
    line.full_clean()
    line.save()


def _refresh_draft_vat_evidence(invoice: Invoice) -> None:
    from apps.billing.tax_evidence import capture_vat_evidence, read_vat_evidence  # noqa: PLC0415
    from apps.common.tax_service import VATCalculationResult  # noqa: PLC0415

    decision = read_vat_evidence(invoice)
    if decision is None:
        return
    result = VATCalculationResult(
        scenario=decision.scenario,
        vat_rate=decision.rate,
        subtotal_cents=invoice.subtotal_cents,
        vat_cents=invoice.tax_cents,
        total_cents=invoice.total_cents,
        country_code=decision.country,
        is_business=decision.is_business,
        vat_number=decision.vat_number,
        reasoning="",
        audit_data={},
    )
    invoice.vat_evidence = capture_vat_evidence(result, recorded_evidence=invoice.vat_evidence)


def _draft_field_snapshot(invoice: Invoice) -> dict[str, object]:
    return {
        "due_at": invoice.due_at.isoformat() if invoice.due_at else None,
        "public_notes": invoice.meta.get("public_notes", ""),
        "internal_notes": invoice.meta.get("internal_notes", ""),
        "subtotal_cents": invoice.subtotal_cents,
        "tax_cents": invoice.tax_cents,
        "total_cents": invoice.total_cents,
    }


def _draft_line_snapshot(line: InvoiceLine) -> dict[str, object]:
    return {
        "description": line.description,
        "quantity": str(line.quantity),
        "unit_price_cents": line.unit_price_cents,
        "tax_rate": str(line.tax_rate),
        "tax_category_code": line.tax_category_code,
        "service_id": str(line.service_id) if line.service_id is not None else None,
        "billing_cycle_id": str(line.billing_cycle_id) if line.billing_cycle_id is not None else None,
    }


def _update_draft_fields(invoice: Invoice, data: DraftInvoiceData, user: User) -> None:
    if (
        not user.is_authenticated
        or not user.can_manage_financial_data
        or not user.can_access_customer(invoice.customer)
    ):
        raise ValidationError(_("You do not have permission to edit this invoice."))
    reason = draft_invoice_edit_block_reason(invoice)
    if reason:
        raise ValidationError(reason)
    if data.get("customer", str(invoice.customer_id)) != str(invoice.customer_id):
        raise ValidationError(_("The invoice customer cannot be changed."))
    if data.get("currency", invoice.currency_id) != invoice.currency_id:
        raise ValidationError(_("The invoice currency cannot be changed."))
    if not data["lines"]:
        raise ValidationError(_("An invoice must contain at least one line."))
    if "due_at" in data:
        if not data["due_at"]:
            invoice.due_at = None
        else:
            due_date = parse_date(data["due_at"])
            if due_date is None:
                raise ValidationError(_("Enter a valid due date."))
            invoice.due_at = timezone.make_aware(datetime.combine(due_date, time.min))
    invoice.meta = dict(invoice.meta)
    if "public_notes" in data:
        invoice.meta["public_notes"] = data["public_notes"]
    if "internal_notes" in data:
        invoice.meta["internal_notes"] = data["internal_notes"]


def update_draft_invoice(invoice_id: int, data: DraftInvoiceData, user: User) -> Result[Invoice, str]:
    """Edit a frozen tax decision's draft lines atomically; never issue the document."""
    from apps.audit.services import AuditService  # noqa: PLC0415
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.tax_evidence import TaxEvidenceError  # noqa: PLC0415

    try:
        with transaction.atomic():
            try:
                invoice = Invoice.objects.select_for_update().get(pk=invoice_id)
                old_fields = _draft_field_snapshot(invoice)
                _update_draft_fields(invoice, data, user)
                existing = {line.pk: line for line in invoice.lines.all()}
                old_lines = {str(pk): _draft_line_snapshot(line) for pk, line in existing.items()}
                retained = _draft_line_ids(data["lines"], existing)
                for row in data["lines"]:
                    _save_draft_line(invoice, row, existing)
                for line_id, line in existing.items():
                    if line_id not in retained:
                        line.delete()
                invoice.recalculate_totals()
                _refresh_draft_vat_evidence(invoice)
                invoice.save(
                    update_fields=[
                        "due_at",
                        "meta",
                        "subtotal_cents",
                        "tax_cents",
                        "total_cents",
                        "vat_evidence",
                        "updated_at",
                    ]
                )
                new_fields = _draft_field_snapshot(invoice)
                new_lines = {str(line.pk): _draft_line_snapshot(line) for line in invoice.lines.all()}
                AuditService.log_simple_event(
                    "invoice_edited",
                    user=user,
                    content_object=invoice,
                    description=_("Invoice %(number)s edited.") % {"number": invoice.display_number},
                    old_values={"fields": old_fields, "lines": old_lines},
                    new_values={"fields": new_fields, "lines": new_lines},
                    metadata={
                        "diff": {
                            "fields": {
                                key: {"before": value, "after": new_fields[key]}
                                for key, value in old_fields.items()
                                if value != new_fields[key]
                            },
                            "lines": {
                                "created": [key for key in new_lines if key not in old_lines],
                                "deleted": [key for key in old_lines if key not in new_lines],
                                "updated": {
                                    key: {"before": old_lines[key], "after": value}
                                    for key, value in new_lines.items()
                                    if key in old_lines and old_lines[key] != value
                                },
                            },
                        }
                    },
                )
                logger.info("✅ [Billing] Edited draft invoice %s", invoice.display_number)
                return Ok(invoice)
            except (ValidationError, TaxEvidenceError, DecimalException, ValueError) as exc:
                transaction.set_rollback(True)
                if isinstance(exc, ValidationError):
                    error = "; ".join(exc.messages)
                elif isinstance(exc, DecimalException):
                    error = _("Line quantities or prices are out of range.")
                else:
                    error = _("Invalid draft invoice data.")
                return Err(error)
    except Invoice.DoesNotExist:
        return Err(_("Invoice not found."))
    except DatabaseError:
        logger.exception("🔥 [Billing] Draft invoice edit failed for %s", invoice_id)
        return Err(_("The invoice could not be saved. Please try again."))


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
        from apps.audit.services import AuditService  # noqa: PLC0415  # Deferred: avoids circular import

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
                metrics["payment_time_days"] = (timezone.now() - invoice.created_at).days if invoice.created_at else 0
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
        from apps.billing.models import Invoice as InvoiceModel  # noqa: PLC0415  # Deferred: avoids circular import
        from apps.billing.models import Payment  # noqa: PLC0415  # Deferred: avoids circular import

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

            # Update customer metadata if available (locked to prevent lost updates)
            if hasattr(customer, "meta") and customer.meta is not None:
                from apps.customers.models import Customer  # noqa: PLC0415  # Deferred: avoids circular import

                with transaction.atomic():
                    locked = Customer.objects.select_for_update(of=("self",)).get(id=customer.id)
                    locked.meta = locked.meta or {}
                    locked.meta["billing_metrics"] = metrics
                    locked.save(update_fields=["meta", "updated_at"])

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
        from apps.audit.services import AuditService  # noqa: PLC0415  # Deferred: avoids circular import

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
        from apps.audit.services import AuditService  # noqa: PLC0415  # Deferred: avoids circular import

        try:
            adjustment_amount = Decimal(adjustment_amount_cents) / 100

            # Get current LTV from customer metadata
            current_ltv = 0
            current_ltv_locked = 0  # Initialised here; re-read from DB when meta is not None
            if hasattr(customer, "meta") and customer.meta:
                current_ltv = customer.meta.get("lifetime_value_cents", 0)

            new_ltv = current_ltv + adjustment_amount_cents

            # Update customer metadata (locked to prevent lost updates)
            if hasattr(customer, "meta") and customer.meta is not None:
                from apps.customers.models import Customer  # noqa: PLC0415  # Deferred: avoids circular import

                with transaction.atomic():
                    locked = Customer.objects.select_for_update(of=("self",)).get(id=customer.id)
                    locked.meta = locked.meta or {}
                    # Re-read current LTV from locked row for accurate calculation
                    current_ltv_locked = locked.meta.get("lifetime_value_cents", 0)
                    locked.meta["lifetime_value_cents"] = current_ltv_locked + adjustment_amount_cents
                    locked.meta["ltv_last_adjusted"] = timezone.now().isoformat()
                    locked.save(update_fields=["meta", "updated_at"])
                    new_ltv = locked.meta["lifetime_value_cents"]

            adjustment_data = {
                "customer_id": str(customer.id),
                "previous_ltv_cents": current_ltv_locked,
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
    """Return the authoritative PDF for this invoice.

    Routed through the issuer chokepoint rather than straight to the renderer,
    because an externally-issued invoice already HAS an authoritative rendering —
    the provider's, which is what the customer and the accountant see and what sits
    behind whatever reached ANAF. Rendering our own version of that document would
    produce a second, unofficial copy that can differ in layout or rounding.

    Errors intentionally propagate so callers cannot replace a legally significant
    invoice with an unvalidated placeholder attachment.
    """
    from apps.billing.issuers.documents import get_invoice_pdf_bytes  # noqa: PLC0415
    from apps.common.types import Err  # noqa: PLC0415

    # DocumentDeferred deliberately propagates: a queued email job should be retried
    # by the queue, not turned into a send with no attachment or a hard failure.
    result = get_invoice_pdf_bytes(invoice)
    if isinstance(result, Err):
        raise RuntimeError(f"Could not obtain the PDF for invoice {invoice.display_number}: {result.error}")
    return result.unwrap()


def generate_e_factura_xml(invoice: Invoice) -> str:
    """Generate e-Factura (CIUS-RO UBL 2.1) XML via the canonical builder.

    Shares `builder_for` with the ANAF submission path so the staff download emits the
    identical, fully-conformant document (#188) - including for a credit note, which this
    function used to restate as an `<Invoice>` because it named one builder directly.
    """
    from apps.billing.efactura.xml_builder import builder_for  # noqa: PLC0415

    try:
        xml_content = builder_for(invoice).build()
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
    from django.core.mail import EmailMessage  # noqa: PLC0415  # Deferred: avoids circular import

    try:
        email = recipient_email or (invoice.customer.primary_email if invoice.customer else None)

        if not email:
            logger.error(f"🔥 [Email] No recipient email for invoice {invoice.number}")
            return False

        # Generate PDF attachment
        pdf_content = generate_invoice_pdf(invoice)

        # Build email
        subject = f"Invoice {invoice.number} from {getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}"

        body = f"""Dear {invoice.customer.get_display_name() if invoice.customer else "Customer"},

Please find attached invoice {invoice.number}.

Invoice Details:
- Invoice Number: {invoice.number}
- Amount: €{Decimal(invoice.total_cents) / 100:.2f}
- Due Date: {invoice.due_at.strftime("%Y-%m-%d") if invoice.due_at else "N/A"}

Thank you for your business.

Best regards,
{getattr(settings, "COMPANY_NAME", "PRAHO Platform")}
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

    except UnsupportedDocumentAdjustmentError:
        # Deterministic fail-closed guard, not a transient delivery failure: the
        # caller must see it (and must never mark the invoice as sent).
        raise
    except Exception as e:
        logger.error(f"🔥 [Email] Failed to send invoice {invoice.number}: {e}")
        return False
