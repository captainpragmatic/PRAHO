"""
Usage-Based Invoice Generation Service for PRAHO Platform
Automatically generates invoices from usage aggregations.

This service handles:
- Invoice creation from billing cycles
- Line item generation from aggregations
- Credit application and discounts
- Tax calculation with Romanian VAT compliance
- Integration with existing invoice workflow
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import Exists, Max, OuterRef, Sum
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.audit.services import AuditService
from apps.common.tax_service import CustomerVATInfo, TaxService
from apps.common.types import Err, Ok, Result
from apps.customers.models import CustomerAddress, CustomerTaxProfile

from . import config as billing_config
from .fiscal_identity import billing_country_code, get_customer_fiscal_identity
from .invoice_models import Invoice, InvoiceLine, InvoiceSequence
from .metering_models import BillingCycle, UsageAggregation, UsageMeter
from .metering_service import AggregationService, RatingEngine
from .payment_models import CreditLedger, Payment
from .recurring_billing import usage_collection_schedule

logger = logging.getLogger(__name__)


class UsageInvoiceService:
    """
    Service for generating invoices from usage-based billing cycles.

    Responsible for:
    - Creating invoices from closed billing cycles
    - Adding usage line items with proper descriptions
    - Applying customer credits
    - Calculating taxes (Romanian VAT)
    - Integrating with existing invoice workflow
    """

    def __init__(self) -> None:
        # Use centralized config for defaults
        self.default_vat_rate = billing_config.DEFAULT_VAT_RATE

    @transaction.atomic
    def generate_invoice_from_cycle(  # noqa: C901, PLR0911, PLR0915  # Atomic usage rating, document, tax, and credit flow
        self, billing_cycle_id: str
    ) -> Result[dict[str, Any], str]:  # Complexity: multi-step workflow  # Complexity: multi-step business logic
        """
        Generate an invoice from a billing cycle.

        The billing cycle must be closed.
        All usage aggregations must be rated.
        """
        try:
            billing_cycle = (
                BillingCycle.objects.select_for_update(of=("self",))
                .select_related("subscription", "subscription__customer", "subscription__currency")
                .get(id=billing_cycle_id)
            )
        except BillingCycle.DoesNotExist:
            return Err(f"Billing cycle not found: {billing_cycle_id}")

        if billing_cycle.status != "closed":
            return Err(f"Billing cycle not ready for invoicing: status is {billing_cycle.status}")

        subscription = billing_cycle.subscription
        customer = subscription.customer
        currency = subscription.currency

        # Check if invoice already exists
        if billing_cycle.usage_invoice:
            return Err(f"Usage invoice already exists for billing cycle: {billing_cycle.usage_invoice.number}")

        # Get unrated aggregations - they need rating first
        unrated = UsageAggregation.objects.filter(
            billing_cycle=billing_cycle, status__in=("accumulating", "pending_rating")
        ).exists()

        if unrated:
            # Rate them first
            rating_engine = RatingEngine()
            rating_result = rating_engine.rate_billing_cycle(str(billing_cycle_id))
            if rating_result.is_err():
                return Err(f"Failed to rate billing cycle: {rating_result.unwrap_err()}")

        # Refresh billing cycle to get updated totals
        billing_cycle.refresh_from_db()

        if UsageAggregation.objects.filter(billing_cycle=billing_cycle).exclude(status="rated").exists():
            return Err("Billing cycle still contains usage that is not safely rated")

        if billing_cycle.usage_charge_cents <= 0:
            billing_cycle.finalize()
            billing_cycle.save(update_fields=["status", "finalized_at", "updated_at"])
            return Ok(
                {
                    "invoice_id": None,
                    "invoice_number": None,
                    "total_cents": 0,
                    "line_items": 0,
                    "finalized_without_invoice": True,
                }
            )

        # Get all rated aggregations
        aggregations = UsageAggregation.objects.filter(billing_cycle=billing_cycle, status="rated").select_related(
            "meter"
        )

        with transaction.atomic():
            # Get invoice sequence (reuse existing billing pattern)
            sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")

            # The fixed period price was collected on the renewal proforma/invoice.
            # This second document contains post-paid usage only.
            gross_amount_cents = billing_cycle.usage_charge_cents
            discount_cents = billing_cycle.discount_cents
            if discount_cents < 0 or discount_cents > gross_amount_cents:
                return Err("Usage billing discount must be between zero and the usage charge")

            # Calculate net amount before tax (this becomes subtotal)
            # Account credit is payment tender, not a discount, so it never
            # changes the Romanian VAT base or the invoice face value.
            net_amount_cents = gross_amount_cents - discount_cents

            # Resolve the immutable fiscal address before tax so the same country
            # drives both the VAT decision and the issued document snapshot.
            billing_address = self._get_customer_billing_address(customer)

            # Calculate tax (Romanian VAT standard rate)
            vat_result = TaxService.calculate_vat_for_document(
                subtotal_cents=net_amount_cents,
                customer_info=self._get_customer_vat_info(
                    customer,
                    country=billing_address["country"],
                ),
            )
            vat_rate = vat_result.vat_rate / Decimal("100")
            tax_cents = vat_result.vat_cents

            # Total = subtotal + tax (must satisfy Invoice model validation)
            total_cents = net_amount_cents + tax_cents
            customer_credit = self._get_customer_credit_balance(customer)
            credit_applied_cents = min(max(customer_credit, 0), total_cents)
            _notice_at, charge_at = usage_collection_schedule(billing_cycle.period_end)

            # Create invoice - subtotal is the NET taxable amount (matching Invoice.clean() validation)
            invoice = Invoice.objects.create(
                customer=customer,
                number=sequence.get_next_number("INV"),
                status="draft",
                currency=currency,
                subtotal_cents=net_amount_cents,  # NET amount before tax (not gross)
                tax_cents=tax_cents,
                total_cents=total_cents,
                discount_cents=discount_cents,
                issued_at=timezone.now(),
                due_at=charge_at,
                bill_to_name=billing_address.get("name", ""),
                bill_to_tax_id=billing_address.get("tax_id", ""),
                bill_to_cnp=billing_address.get("cnp", ""),
                bill_to_email=billing_address.get("email", ""),
                bill_to_address1=billing_address.get("address1", ""),
                bill_to_address2=billing_address.get("address2", ""),
                bill_to_city=billing_address.get("city", ""),
                bill_to_region=billing_address.get("region", ""),
                bill_to_postal=billing_address.get("postal", ""),
                bill_to_country=billing_address.get("country", billing_config.DEFAULT_COUNTRY_CODE),
                meta={
                    "billing_cycle_id": str(billing_cycle.id),
                    "subscription_id": str(subscription.id),
                    "is_usage_based": True,
                    "period_start": billing_cycle.period_start.isoformat(),
                    "period_end": billing_cycle.period_end.isoformat(),
                    "gross_amount_cents": gross_amount_cents,
                    "discount_cents": discount_cents,
                    "credit_applied_cents": credit_applied_cents,
                },
            )

            # Add usage line items (pre-tax amounts)
            for agg in aggregations:
                if agg.charge_cents > 0:
                    description = self._format_usage_description(agg)

                    line = InvoiceLine.objects.create(
                        invoice=invoice,
                        kind="service",
                        service=None,
                        description=description,
                        quantity=agg.overage_value,
                        unit_price_cents=self._get_unit_price_cents(agg),
                        tax_rate=vat_rate,
                        line_total_cents=agg.charge_cents,  # Pre-tax
                    )

                    # Link aggregation to invoice line
                    agg.invoice_line = line
                # Freeze every rated aggregation into this invoice snapshot,
                # including included/zero-charge usage with no line item.
                agg.mark_invoiced()
                agg.save()

            # Update billing cycle
            invoice.issue()
            invoice.save()

            billing_cycle.usage_invoice = invoice
            billing_cycle.credit_applied_cents = credit_applied_cents
            billing_cycle.total_cents = total_cents
            billing_cycle.tax_cents = tax_cents
            billing_cycle.mark_invoiced()  # FSM transition sets invoiced_at
            billing_cycle.save()

            if credit_applied_cents > 0:
                CreditLedger.objects.create(
                    customer=customer,
                    invoice=invoice,
                    delta_cents=-credit_applied_cents,
                    reason=f"Applied to invoice {invoice.number}",
                )
                credit_payment = Payment.objects.create(
                    customer=customer,
                    invoice=invoice,
                    amount_cents=credit_applied_cents,
                    currency=currency,
                    payment_method="other",
                    reference_number=f"credit:{invoice.number}",
                    meta={"source": "customer_credit"},
                )
                credit_payment.succeed()
                credit_payment.save(update_fields=["status", "updated_at"])

                from .payment_convergence import PaymentSuccessService  # noqa: PLC0415

                convergence = PaymentSuccessService.converge_local_paid_document(credit_payment.id)
                if convergence.is_err():
                    transaction.set_rollback(True)
                    return Err(f"Customer credit allocation failed: {convergence.unwrap_err()}")

            # Log invoice creation
            AuditService.log_simple_event(
                event_type="usage_invoice_created",
                user=None,
                content_object=invoice,
                description=f"Usage invoice generated: {invoice.number}",
                actor_type="system",
                metadata={
                    "invoice_id": str(invoice.id),
                    "invoice_number": invoice.number,
                    "billing_cycle_id": str(billing_cycle.id),
                    "customer_id": str(customer.id),
                    "prepaid_base_charge_cents": billing_cycle.base_charge_cents,
                    "usage_charge_cents": billing_cycle.usage_charge_cents,
                    "discount_cents": discount_cents,
                    "credit_applied_cents": credit_applied_cents,
                    "tax_cents": tax_cents,
                    "total_cents": total_cents,
                    "usage_line_items": len(aggregations),
                },
            )

        logger.info(f"Generated invoice {invoice.number} for billing cycle {billing_cycle_id}: {total_cents} cents")

        return Ok(
            {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "total_cents": total_cents,
                "line_items": invoice.lines.count(),
            }
        )

    def _get_customer_credit_balance(self, customer: Any) -> int:
        """Get customer's available credit balance in cents"""
        result = CreditLedger.objects.filter(customer=customer).aggregate(total=Sum("delta_cents"))

        return result["total"] or 0

    def _get_customer_vat_info(self, customer: Any, *, country: str | None = None) -> CustomerVATInfo:
        """Build the authoritative VAT context for a usage invoice."""
        info: CustomerVATInfo = {
            "country": country or billing_config.DEFAULT_COUNTRY_CODE,
            "is_business": bool(getattr(customer, "company_name", "")),
            "vat_number": None,
            "customer_id": str(getattr(customer, "id", "")),
            "order_id": None,
        }
        try:
            tax_profile = CustomerTaxProfile.objects.get(customer=customer)
            info["vat_number"] = getattr(tax_profile, "vat_number", None)
            info["is_vat_payer"] = bool(getattr(tax_profile, "is_vat_payer", False))
            info["reverse_charge_eligible"] = bool(getattr(tax_profile, "reverse_charge_eligible", False))
            vat_rate_override = getattr(tax_profile, "vat_rate", None)
            if vat_rate_override is not None:
                info["custom_vat_rate"] = vat_rate_override
        except (ObjectDoesNotExist, AttributeError, TypeError, ValueError):
            logger.debug("Could not resolve customer VAT profile for usage billing")
        return info

    def _get_customer_billing_address(self, customer: Any) -> dict[str, str]:
        """Get customer's billing address."""
        address = {
            "name": customer.get_billing_name(),
            "tax_id": "",
            "cnp": "",
            "email": customer.primary_email or "",
            "address1": "",
            "address2": "",
            "city": "",
            "region": "",
            "postal": "",
            "country": billing_config.DEFAULT_COUNTRY_CODE,
        }

        # Try to get from customer addresses
        try:
            billing_addr = CustomerAddress.objects.filter(customer=customer, is_billing=True, is_current=True).first()

            if billing_addr:
                address["address1"] = billing_addr.address_line1 or ""
                address["address2"] = billing_addr.address_line2 or ""
                address["city"] = billing_addr.city or ""
                address["region"] = billing_addr.county or ""
                address["postal"] = billing_addr.postal_code or ""
                address["country"] = billing_country_code(
                    billing_addr.country,
                    default=billing_config.DEFAULT_COUNTRY_CODE,
                )
        except (ImportError, ObjectDoesNotExist, AttributeError, TypeError, ValueError):
            logger.debug("Could not resolve customer billing address")

        fiscal_identity = get_customer_fiscal_identity(customer)
        address["tax_id"] = fiscal_identity.business_tax_id
        address["cnp"] = fiscal_identity.cnp

        return address

    def _format_usage_description(self, aggregation: Any) -> str:
        """Format a human-readable usage line description"""
        meter = aggregation.meter
        unit = meter.unit_display or meter.get_unit_display()

        parts = [f"{meter.display_name}:"]

        if aggregation.included_allowance > 0:
            parts.append(
                f"{aggregation.total_value:.2f} {unit} "
                f"({aggregation.included_allowance:.2f} {unit} included, "
                f"{aggregation.overage_value:.2f} {unit} overage)"
            )
        else:
            parts.append(f"{aggregation.total_value:.2f} {unit}")

        return " ".join(parts)

    def _get_unit_price_cents(self, aggregation: Any) -> int:
        """Calculate effective unit price for display"""
        if aggregation.overage_value > 0:
            return int(aggregation.charge_cents / aggregation.overage_value)
        return 0

    def issue_invoice(self, invoice_id: str) -> Result[Any, str]:
        """
        Issue a draft invoice (change status from draft to issued).
        """
        try:
            invoice = Invoice.objects.get(id=invoice_id)
        except Invoice.DoesNotExist:
            return Err(f"Invoice not found: {invoice_id}")

        if invoice.status != "draft":
            return Err(f"Invoice is not in draft status: {invoice.status}")

        with transaction.atomic():
            try:
                invoice.issue()
            except TransitionNotAllowed:
                logger.warning("⚠️ [Invoice] Cannot issue invoice %s from status '%s'", invoice.number, invoice.status)
                return Err(f"Cannot issue invoice {invoice.number} from status '{invoice.status}'")
            # Note: issue() FSM transition already sets issued_at and locked_at
            invoice.save()

            # Log issuance
            AuditService.log_simple_event(
                event_type="invoice_issued",
                user=None,
                content_object=invoice,
                description=f"Invoice issued: {invoice.number}",
                actor_type="system",
                metadata={
                    "invoice_id": str(invoice.id),
                    "invoice_number": invoice.number,
                    "total_cents": invoice.total_cents,
                },
            )

        return Ok(invoice)


class UsageBillingService:
    """Close, rate, and invoice usage inside PRAHO-owned billing cycles."""

    @staticmethod
    @transaction.atomic
    def _finalize_zero_usage_cycle(billing_cycle_id: str) -> bool | None:
        """Finalize a fully rated zero cycle under lock.

        Returns True when finalized, False when invoicing/rating is required,
        and None when another worker has already handled the cycle.
        """
        try:
            cycle = BillingCycle.objects.select_for_update(of=("self",)).filter(pk=billing_cycle_id).first()
        except BillingCycle.DoesNotExist:
            return None
        if cycle is None or cycle.status != "closed" or cycle.usage_invoice_id is not None:
            return None
        aggregations = UsageAggregation.objects.filter(billing_cycle=cycle)
        if aggregations.exclude(status="rated").exists():
            return False
        rated_total = aggregations.aggregate(total=Sum("charge_cents"))["total"] or 0
        if rated_total > 0:
            if cycle.usage_charge_cents != rated_total:
                cycle.usage_charge_cents = rated_total
                cycle.save(update_fields=["usage_charge_cents", "updated_at"])
            return False
        cycle.finalize()
        cycle.save(update_fields=["status", "finalized_at", "updated_at"])
        return True

    @staticmethod
    def close_expired_cycles() -> tuple[int, int]:
        """
        Close all billing cycles that have passed their end date.

        Returns: (closed_count, error_count)
        """
        now = timezone.now()
        max_grace_hours = (
            UsageMeter.objects.filter(is_active=True).aggregate(max_grace=Max("event_grace_period_hours"))["max_grace"]
            or 0
        )
        close_through = now - timedelta(hours=max_grace_hours)
        expired_cycles = BillingCycle.objects.filter(status="active", period_end__lte=close_through)

        aggregation_service = AggregationService()
        closed = 0
        errors = 0

        for cycle in expired_cycles:
            result = aggregation_service.close_billing_cycle(str(cycle.id))
            if result.is_ok():
                closed += 1
            else:
                errors += 1
                logger.error(f"Error closing cycle {cycle.id}: {result.unwrap_err()}")

        logger.info(f"Closed {closed} expired billing cycles, {errors} errors")

        return closed, errors

    @staticmethod
    def generate_pending_invoices() -> tuple[int, int]:
        """
        Generate invoices for all closed and rated billing cycles.

        Returns: (generated_count, error_count)
        """
        pending_cycle_ids = list(
            BillingCycle.objects.filter(status="closed", usage_invoice__isnull=True).values_list("id", flat=True)
        )

        invoice_service = UsageInvoiceService()
        generated = 0
        errors = 0

        for cycle_id in pending_cycle_ids:
            zero_usage_result = UsageBillingService._finalize_zero_usage_cycle(str(cycle_id))
            if zero_usage_result is not False:
                continue
            result = invoice_service.generate_invoice_from_cycle(str(cycle_id))
            if result.is_ok():
                invoice_id = result.unwrap().get("invoice_id")
                if not invoice_id:
                    continue
                generated += 1
            else:
                errors += 1
                logger.error(f"Error generating invoice for cycle {cycle_id}: {result.unwrap_err()}")

        logger.info(f"Generated {generated} invoices, {errors} errors")

        return generated, errors

    @staticmethod
    def collect_due_usage_invoices(as_of: datetime | None = None) -> tuple[int, int]:
        """Collect authorized post-paid usage only when its notice window has elapsed."""
        from .tasks import process_auto_payment  # noqa: PLC0415

        run_at = as_of or timezone.now()
        # Leave a gateway-less pending reservation eligible so PaymentService can
        # resume its original idempotency key after an interrupted create call.
        blocking_recurring_attempts = Payment.objects.filter(
            invoice_id=OuterRef("usage_invoice_id"),
            payment_method="stripe",
            meta__source="recurring_billing",
        ).exclude(status="pending", gateway_txn_id__isnull=True)
        due_invoice_ids = list(
            BillingCycle.objects.filter(
                status="invoiced",
                usage_invoice__status__in=("issued", "overdue"),
                usage_invoice__due_at__lte=run_at,
                subscription__auto_payment_enabled=True,
            )
            .annotate(has_blocking_attempt=Exists(blocking_recurring_attempts))
            .filter(has_blocking_attempt=False)
            .order_by()
            .values_list("usage_invoice_id", flat=True)
            .distinct()
        )

        collected = 0
        errors = 0
        for invoice_id in due_invoice_ids:
            result = process_auto_payment(str(invoice_id))
            if result.get("success"):
                collected += 1
            else:
                errors += 1
                logger.error(
                    "Usage auto-collection failed for invoice %s: %s",
                    invoice_id,
                    result.get("error") or "unknown error",
                )

        logger.info("Collected %s due usage invoices, %s errors", collected, errors)
        return collected, errors
