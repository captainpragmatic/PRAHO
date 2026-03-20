"""
Proforma Services for PRAHO Platform
Business logic for proforma invoice management, PDF generation,
and the proforma payment convergence point (Phase B).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _t

from apps.common.types import Err, Ok, Result
from apps.common.validators import log_security_event

if TYPE_CHECKING:
    from apps.users.models import User

    from .proforma_models import ProformaInvoice

logger = logging.getLogger(__name__)


# ===============================================================================
# PROFORMA PDF GENERATION & EMAIL SERVICES
# ===============================================================================


def generate_proforma_pdf(proforma: Any) -> bytes:  # ProformaInvoice type would create circular import
    """Generate PDF for a proforma invoice using the ReportLab generator."""
    logger.info(f"📄 [PDF] Generating PDF for proforma {proforma.number}")
    from apps.billing.pdf_generators import generate_proforma_pdf as _generate_pdf  # noqa: PLC0415

    return _generate_pdf(proforma)


def send_proforma_email(
    proforma: Any, recipient_email: str | None = None
) -> bool:  # ProformaInvoice type would create circular import
    """Send proforma invoice via email with PDF attachment."""
    from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

    email = recipient_email or proforma.customer.primary_email
    logger.info(f"📧 [Email] Sending proforma {proforma.number} to {email}")
    try:
        pdf_bytes = generate_proforma_pdf(proforma)
        email_result = EmailService.send_email(
            to=email,
            subject=_t("Proforma Invoice %(number)s") % {"number": proforma.number},
            body_text=_t("Please find attached proforma invoice %(number)s.") % {"number": proforma.number},
            attachments=[(f"proforma_{proforma.number}.pdf", pdf_bytes, "application/pdf")],
        )
        if not email_result.success:
            logger.error(f"🔥 [Email] Proforma {proforma.number} send failed: {email_result.error}")
            return False
        logger.info(f"✅ [Email] Proforma {proforma.number} sent to {email}")
        return True
    except Exception as exc:
        logger.error(f"🔥 [Email] Failed to send proforma {proforma.number}: {exc}")
        return False


# ===============================================================================
# PROFORMA SERVICE CLASS
# ===============================================================================


class ProformaService:
    """Service class for proforma invoice business logic"""

    @staticmethod
    def update_proforma(proforma: ProformaInvoice, update_data: dict[str, Any], user: User) -> Result[bool, str]:
        """Update proforma invoice with new data"""
        try:
            # Update basic fields
            if "bill_to_name" in update_data:
                proforma.bill_to_name = update_data["bill_to_name"]
            if "bill_to_email" in update_data:
                proforma.bill_to_email = update_data["bill_to_email"]
            if "notes" in update_data:
                proforma.notes = update_data["notes"]

            # Save changes
            proforma.save()

            logger.info(f"📝 [Proforma] Updated proforma {proforma.number} by user {user.email}")
            return Ok(True)

        except Exception as e:
            logger.error(f"Failed to update proforma {proforma.number}: {e}")
            return Err(f"Failed to update proforma: {e}")

    @staticmethod
    @transaction.atomic
    def create_from_order(order: Any) -> Result[Any, str]:
        """Create a proforma invoice from an order, synchronously (DB only, ~20ms).

        Why synchronous: proforma creation is a DB-only operation (no PDF, no email).
        PDF generation and email sending happen asynchronously after commit.
        This ensures the proforma exists in the same transaction that sets order to awaiting_payment.
        Per F3: must be inside the same transaction, NOT in on_commit callback.
        """
        from apps.billing.proforma_models import (  # noqa: PLC0415
            ProformaInvoice as ProformaModel,
        )
        from apps.billing.proforma_models import (  # noqa: PLC0415
            ProformaLine,
            ProformaSequence,
        )
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        try:
            # Get proforma sequence with lock to prevent race conditions
            sequence, _ = ProformaSequence.objects.get_or_create(scope="default")
            proforma_number = sequence.get_next_number("PRO")

            # Extract bill_to from order billing_address JSON
            billing_addr = order.billing_address or {}
            bill_to_name = billing_addr.get("company_name", "") or order.customer_name
            bill_to_country = billing_addr.get("country", "RO") or "RO"

            # Set currency explicitly from order (F10: never rely on defaults)
            currency = order.currency

            # Calculate VAT using the same engine as invoices for consistency.
            # H5 fix: Subtract discount_cents from subtotal before VAT calculation so
            # the proforma reflects the actual amount the customer owes.
            from apps.billing.services import _build_customer_vat_info  # noqa: PLC0415

            discount_cents = int(getattr(order, "discount_cents", 0) or 0)
            taxable_subtotal = max(0, int(order.subtotal_cents) - discount_cents)
            vat_result = TaxService.calculate_vat_for_document(
                subtotal_cents=taxable_subtotal,
                customer_info=_build_customer_vat_info(order.customer, order_id=str(order.id)),
            )

            # Create proforma — status stays "draft" (email sending is separate)
            proforma = ProformaModel.objects.create(
                customer=order.customer,
                number=proforma_number,
                currency=currency,
                subtotal_cents=vat_result.subtotal_cents,
                tax_cents=vat_result.vat_cents,
                total_cents=vat_result.total_cents,
                valid_until=timezone.now() + timedelta(days=7),
                bill_to_name=bill_to_name,
                bill_to_email=order.customer_email,
                bill_to_country=bill_to_country,
                bill_to_city=billing_addr.get("city", ""),
                bill_to_address1=billing_addr.get("address_line1", "") or billing_addr.get("line1", ""),
                bill_to_tax_id=billing_addr.get("vat_number", "") or billing_addr.get("vat_id", ""),
                meta={"order_id": str(order.id), "order_number": order.order_number},
            )

            # Create proforma lines from order items
            vat_rate_decimal = (vat_result.vat_rate / Decimal("100")).quantize(Decimal("0.0001"))
            for item in order.items.all():
                line = ProformaLine(
                    proforma=proforma,
                    kind="service",
                    description=item.product_name,
                    quantity=Decimal(str(item.quantity)),
                    unit_price_cents=item.unit_price_cents,
                    tax_rate=vat_rate_decimal,
                )
                line.calculate_totals()
                line.save()

            # Recalculate proforma totals from lines for consistency
            proforma.recalculate_totals()
            proforma.save(update_fields=["subtotal_cents", "tax_cents", "total_cents"])

            # Link proforma to order (inside same transaction per F3)
            order.proforma = proforma
            order.save(update_fields=["proforma", "updated_at"])

            log_security_event(
                "proforma_created_from_order",
                {
                    "proforma_id": str(proforma.id),
                    "proforma_number": proforma.number,
                    "order_id": str(order.id),
                    "order_number": order.order_number,
                    "total_cents": proforma.total_cents,
                    "critical_financial_operation": True,
                },
            )

            logger.info(
                "✅ [Proforma] Created %s from order %s (total: %d cents)",
                proforma.number,
                order.order_number,
                proforma.total_cents,
            )
            return Ok(proforma)

        except Exception as e:
            logger.exception("🔥 [Proforma] Failed to create proforma from order: %s", e)
            return Err(f"Failed to create proforma from order: {e}")


PAYMENT_METHOD_MAP: dict[str, str] = {"bank_transfer": "bank", "card": "stripe"}


def _normalize_payment_method(raw: str) -> str:
    """Canonical mapping to prevent data corruption from inconsistent method names."""
    return PAYMENT_METHOD_MAP.get(raw.lower(), raw.lower())


class ProformaPaymentService:
    """Convergence point for all payment paths (bank transfer, Stripe, admin).

    Why a single convergence point: both Stripe webhook and admin "Record Payment"
    must follow identical logic — lock proforma, validate, create/link payment,
    convert to invoice, emit signal. Duplicating this logic would create divergent
    behavior and race conditions.
    """

    @staticmethod
    @transaction.atomic
    def record_payment_and_convert(  # noqa: PLR0913, PLR0911, PLR0912, C901  # Convergence point: all payment paths share 6 params; guards are intentional
        proforma_id: str,
        amount_cents: int,
        payment_method: str,
        reference: str = "",
        created_by: Any | None = None,
        existing_payment: Any | None = None,
    ) -> Result[Any, str]:
        """Record payment on proforma and convert to invoice.

        Lock ordering: ALWAYS lock Proforma first, then Payment (F4).
        Signal emission via on_commit to prevent rollback issues (F2).
        Idempotent: already-converted proforma returns Ok(existing_invoice) (M9).
        """
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.billing.payment_models import Payment  # noqa: PLC0415
        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
        from apps.billing.services import ProformaConversionService  # noqa: PLC0415

        try:
            # Lock proforma first (F4: consistent lock ordering prevents deadlock)
            proforma = ProformaInvoice.objects.select_for_update(of=("self",)).get(id=proforma_id)
        except ProformaInvoice.DoesNotExist:
            return Err(f"Proforma not found: {proforma_id}")

        # Idempotent: already converted → return existing invoice (M9)
        if proforma.status == "converted":
            invoice_id = (proforma.meta or {}).get("invoice_id")
            if invoice_id:
                try:
                    return Ok(Invoice.objects.get(id=invoice_id))
                except Invoice.DoesNotExist:
                    pass
            return Ok(None)

        # Validate proforma is in a convertible state
        if proforma.status not in ("draft", "sent", "accepted"):
            return Err(f"Proforma {proforma.number} cannot accept payment (status: {proforma.status})")

        # Validate proforma is not expired
        if proforma.is_expired:
            return Err(f"Proforma {proforma.number} has expired")

        # Validate full payment only (partial payments not supported yet)
        if amount_cents != proforma.total_cents:
            return Err(
                f"Payment amount ({amount_cents}) must equal proforma total ({proforma.total_cents}). "
                f"Partial payments not supported."
            )

        # Create or link payment (pending — do NOT mark succeeded until conversion succeeds).
        # H2 fix: Payment is kept in its initial state until proforma→invoice conversion
        # succeeds. If conversion fails, the atomic transaction rolls back the payment too.
        if existing_payment:
            # C5: Guard against cross-customer payment linking
            if existing_payment.customer_id != proforma.customer_id:
                return Err("Payment customer does not match proforma customer")
            # Stripe path: update existing payment with proforma link
            payment = existing_payment
            payment.proforma = proforma
            payment.save(update_fields=["proforma", "updated_at"])
        else:
            # Bank transfer / admin path: create payment record (status stays "pending" for now)
            payment = Payment.objects.create(
                customer=proforma.customer,
                proforma=proforma,
                amount_cents=amount_cents,
                currency=proforma.currency,
                payment_method=payment_method,
                reference_number=reference,
                created_by=created_by,
                meta={"proforma_id": str(proforma.id), "proforma_number": proforma.number},
            )

        log_security_event(
            "payment_recorded_on_proforma",
            {
                "proforma_id": str(proforma.id),
                "payment_id": str(payment.id),
                "amount_cents": amount_cents,
                "payment_method": payment_method,
                "critical_financial_operation": True,
            },
        )

        # Convert proforma to invoice using existing conversion service.
        # H2 fix: Do conversion BEFORE marking payment succeeded. If conversion fails,
        # mark the atomic block for rollback so the payment record is not persisted.
        conversion_result = ProformaConversionService.convert_to_invoice(str(proforma.id))
        if conversion_result.is_err():
            # set_rollback(True) ensures the @transaction.atomic block rolls back on return,
            # preventing the payment record from being committed to the DB.
            transaction.set_rollback(True)
            return Err(f"Proforma conversion failed: {conversion_result.unwrap_err()}")

        invoice = conversion_result.unwrap()

        # H2 fix: Now that conversion succeeded, mark bank/admin payment as succeeded.
        # For existing_payment (Stripe path) the payment was already succeeded by the gateway.
        if not existing_payment:
            payment.succeed()
            payment.save(update_fields=["status", "updated_at"])

        # Re-link payment to the new invoice
        payment.invoice = invoice
        payment.save(update_fields=["invoice", "updated_at"])

        # H7 fix: Mark the invoice as paid now that payment is confirmed.
        # ProformaConversionService creates the invoice in "issued" state.
        # We must transition it to "paid" so the order confirmation path sees a paid invoice.
        try:
            invoice.mark_as_paid()
            invoice.save(update_fields=["status", "paid_at"])
        except Exception:
            # If already paid (idempotent retry), log and continue
            logger.warning(
                "⚠️ [ProformaPayment] Could not mark invoice %s as paid (status: %s)",
                invoice.number,
                invoice.status,
            )

        # Link orders to the new invoice
        for linked_order in proforma.orders.all():
            linked_order.invoice = invoice
            linked_order.save(update_fields=["invoice", "updated_at"])

        log_security_event(
            "proforma_converted_to_invoice",
            {
                "proforma_id": str(proforma.id),
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "payment_id": str(payment.id),
                "critical_financial_operation": True,
            },
        )

        # Emit signal via on_commit — ensures DB is committed before receivers run (F2).
        # Receivers (Orders app) will confirm the order and start provisioning.
        from apps.billing.custom_signals import proforma_payment_received  # noqa: PLC0415

        # H8: Refresh proforma so the closure captures the post-conversion status
        # ("converted"), not the pre-transaction state seen by signal receivers.
        proforma.refresh_from_db()
        _proforma = proforma
        _invoice = invoice
        _payment = payment
        transaction.on_commit(
            lambda: proforma_payment_received.send(
                sender=ProformaPaymentService,
                proforma=_proforma,
                invoice=_invoice,
                payment=_payment,
            )
        )

        logger.info(
            "✅ [ProformaPayment] Recorded payment %s on %s → converted to %s",
            payment.id,
            proforma.number,
            invoice.number,
        )
        return Ok(invoice)
