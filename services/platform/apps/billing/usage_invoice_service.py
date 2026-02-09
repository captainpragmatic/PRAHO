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
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone

from apps.audit.services import AuditService

from . import config as billing_config

logger = logging.getLogger(__name__)


@dataclass
class Result:
    """Result pattern for operations"""
    _value: Any
    _error: str | None

    @classmethod
    def ok(cls, value: Any) -> Result:
        return cls(_value=value, _error=None)

    @classmethod
    def err(cls, error: str) -> Result:
        return cls(_value=None, _error=error)

    def is_ok(self) -> bool:
        return self._error is None

    def is_err(self) -> bool:
        return self._error is not None

    def unwrap(self) -> Any:
        if self._error:
            raise ValueError(f"Called unwrap on error: {self._error}")
        return self._value

    @property
    def error(self) -> str | None:
        return self._error


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

    def generate_invoice_from_cycle(self, billing_cycle_id: str) -> Result:
        """
        Generate an invoice from a billing cycle.

        The billing cycle must be in 'closed' or 'rated' status.
        All usage aggregations must be rated.
        """
        from .invoice_models import Invoice, InvoiceLine, InvoiceSequence
        from .metering_models import BillingCycle, UsageAggregation
        from .payment_models import CreditLedger

        try:
            billing_cycle = BillingCycle.objects.select_related(
                "subscription", "subscription__customer", "subscription__currency"
            ).get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Result.err(f"Billing cycle not found: {billing_cycle_id}")

        if billing_cycle.status not in ("closed", "accumulating"):
            return Result.err(
                f"Billing cycle not ready for invoicing: status is {billing_cycle.status}"
            )

        subscription = billing_cycle.subscription
        customer = subscription.customer
        currency = subscription.currency

        # Check if invoice already exists
        if billing_cycle.invoice:
            return Result.err(
                f"Invoice already exists for billing cycle: {billing_cycle.invoice.number}"
            )

        # Get unrated aggregations - they need rating first
        unrated = UsageAggregation.objects.filter(
            billing_cycle=billing_cycle,
            status__in=("accumulating", "pending_rating")
        ).exists()

        if unrated:
            # Rate them first
            from .metering_service import RatingEngine
            rating_engine = RatingEngine()
            rating_result = rating_engine.rate_billing_cycle(str(billing_cycle_id))
            if rating_result.is_err():
                return Result.err(f"Failed to rate billing cycle: {rating_result.error}")

        # Refresh billing cycle to get updated totals
        billing_cycle.refresh_from_db()

        # Get all rated aggregations
        aggregations = UsageAggregation.objects.filter(
            billing_cycle=billing_cycle,
            status="rated"
        ).select_related("meter")

        with transaction.atomic():
            # Get invoice sequence (reuse existing billing pattern)
            sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")

            # Calculate gross amount (base + usage charges)
            gross_amount_cents = billing_cycle.base_charge_cents + billing_cycle.usage_charge_cents
            discount_cents = billing_cycle.discount_cents

            # Apply customer credit if available
            credit_applied_cents = 0
            customer_credit = self._get_customer_credit_balance(customer)

            if customer_credit > 0:
                # Apply credit up to invoice total (after discounts)
                max_credit = min(customer_credit, gross_amount_cents - discount_cents)
                if max_credit > 0:
                    credit_applied_cents = max_credit
                    billing_cycle.credit_applied_cents = credit_applied_cents
                    billing_cycle.save(update_fields=["credit_applied_cents"])

            # Calculate net amount before tax (this becomes subtotal)
            # Following existing InvoiceService pattern: subtotal is pre-tax taxable amount
            net_amount_cents = gross_amount_cents - discount_cents - credit_applied_cents

            # Calculate tax (Romanian VAT standard rate)
            vat_rate = self._get_customer_vat_rate(customer)
            tax_cents = int(net_amount_cents * vat_rate)

            # Total = subtotal + tax (must satisfy Invoice model validation)
            total_cents = net_amount_cents + tax_cents

            # Get billing address from customer
            billing_address = self._get_customer_billing_address(customer)

            # Create invoice - subtotal is the NET taxable amount (matching Invoice.clean() validation)
            invoice = Invoice.objects.create(
                customer=customer,
                number=sequence.get_next_number("INV"),
                status="draft",
                currency=currency,
                subtotal_cents=net_amount_cents,  # NET amount before tax (not gross)
                tax_cents=tax_cents,
                total_cents=total_cents,
                issued_at=timezone.now(),
                due_at=billing_config.get_payment_due_date(),
                bill_to_name=billing_address.get("name", ""),
                bill_to_tax_id=billing_address.get("tax_id", ""),
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

            # Add base subscription line item (pre-tax amount)
            if billing_cycle.base_charge_cents > 0:
                InvoiceLine.objects.create(
                    invoice=invoice,
                    kind="service",
                    description=(
                        f"{subscription.product.name} - "
                        f"{billing_cycle.period_start.strftime('%d.%m.%Y')} to "
                        f"{billing_cycle.period_end.strftime('%d.%m.%Y')}"
                    ),
                    quantity=Decimal("1"),
                    unit_price_cents=billing_cycle.base_charge_cents,
                    tax_rate=vat_rate,
                    line_total_cents=billing_cycle.base_charge_cents,  # Pre-tax
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
                    agg.status = "invoiced"
                    agg.save(update_fields=["invoice_line", "status"])

            # Add discount line if applicable
            if discount_cents > 0:
                InvoiceLine.objects.create(
                    invoice=invoice,
                    kind="discount",
                    description="Discount",
                    quantity=Decimal("1"),
                    unit_price_cents=-discount_cents,
                    tax_rate=Decimal("0"),
                    line_total_cents=-discount_cents,
                )

            # Add credit line if applicable
            if credit_applied_cents > 0:
                InvoiceLine.objects.create(
                    invoice=invoice,
                    kind="credit",
                    description="Account Credit Applied",
                    quantity=Decimal("1"),
                    unit_price_cents=-credit_applied_cents,
                    tax_rate=Decimal("0"),
                    line_total_cents=-credit_applied_cents,
                )

                # Deduct credit from customer account
                CreditLedger.objects.create(
                    customer=customer,
                    invoice=invoice,
                    delta_cents=-credit_applied_cents,
                    reason=f"Applied to invoice {invoice.number}",
                )

            # Update billing cycle
            billing_cycle.invoice = invoice
            billing_cycle.invoiced_at = timezone.now()
            billing_cycle.status = "invoiced"
            billing_cycle.total_cents = total_cents
            billing_cycle.tax_cents = tax_cents
            billing_cycle.save()

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
                    "base_charge_cents": billing_cycle.base_charge_cents,
                    "usage_charge_cents": billing_cycle.usage_charge_cents,
                    "discount_cents": discount_cents,
                    "credit_applied_cents": credit_applied_cents,
                    "tax_cents": tax_cents,
                    "total_cents": total_cents,
                    "usage_line_items": len(aggregations),
                },
            )

        logger.info(
            f"Generated invoice {invoice.number} for billing cycle {billing_cycle_id}: "
            f"{total_cents} cents"
        )

        return Result.ok({
            "invoice_id": str(invoice.id),
            "invoice_number": invoice.number,
            "total_cents": total_cents,
            "line_items": invoice.lines.count(),
        })

    def _get_customer_credit_balance(self, customer: Any) -> int:
        """Get customer's available credit balance in cents"""
        from django.db.models import Sum

        from .payment_models import CreditLedger

        result = CreditLedger.objects.filter(
            customer=customer
        ).aggregate(total=Sum("delta_cents"))

        return result["total"] or 0

    def _get_customer_vat_rate(self, customer: Any) -> Decimal:
        """Get the applicable VAT rate for a customer."""
        # Check if customer has tax profile with reverse charge
        try:
            from apps.customers.models import CustomerTaxProfile
            tax_profile = CustomerTaxProfile.objects.get(customer=customer)

            # EU B2B reverse charge - 0% VAT if valid EU VAT number
            if tax_profile.is_reverse_charge_eligible and tax_profile.vat_number:
                country = getattr(customer, "country", billing_config.DEFAULT_COUNTRY_CODE)
                # Reverse charge applies to EU customers outside provider's country
                if (billing_config.is_eu_country(country) and
                        country != billing_config.DEFAULT_COUNTRY_CODE):
                    return Decimal("0")

        except (ImportError, ObjectDoesNotExist, AttributeError, TypeError, ValueError):
            logger.debug("Could not resolve customer reverse-charge VAT profile")

        # Use TaxRule if available, otherwise fall back to default
        customer_country = getattr(customer, "country", billing_config.DEFAULT_COUNTRY_CODE)
        return billing_config.get_vat_rate(customer_country)

    def _get_customer_billing_address(self, customer: Any) -> dict[str, str]:
        """Get customer's billing address."""
        address = {
            "name": customer.company_name or customer.full_name or "",
            "tax_id": "",
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
            from apps.customers.models import CustomerAddress
            billing_addr = CustomerAddress.objects.filter(
                customer=customer,
                address_type="billing",
                is_current=True
            ).first()

            if billing_addr:
                address["address1"] = billing_addr.street_address or ""
                address["address2"] = billing_addr.street_address_2 or ""
                address["city"] = billing_addr.city or ""
                address["region"] = billing_addr.region or ""
                address["postal"] = billing_addr.postal_code or ""
                address["country"] = billing_addr.country_code or billing_config.DEFAULT_COUNTRY_CODE
        except (ImportError, ObjectDoesNotExist, AttributeError, TypeError, ValueError):
            logger.debug("Could not resolve customer billing address")

        # Try to get tax ID from tax profile
        try:
            from apps.customers.models import CustomerTaxProfile
            tax_profile = CustomerTaxProfile.objects.get(customer=customer)
            address["tax_id"] = tax_profile.cui or tax_profile.vat_number or ""
        except (ImportError, ObjectDoesNotExist, AttributeError, TypeError, ValueError):
            logger.debug("Could not resolve customer tax profile for tax ID")

        return address

    def _format_usage_description(self, aggregation: Any) -> str:
        """Format a human-readable usage line description"""
        meter = aggregation.meter
        unit = meter.unit_display or meter.get_unit_display()

        # Format: "Bandwidth Usage: 150 GB (100 GB included, 50 GB overage)"
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

    def issue_invoice(self, invoice_id: str) -> Result:
        """
        Issue a draft invoice (change status from draft to issued).
        """
        from .invoice_models import Invoice

        try:
            invoice = Invoice.objects.get(id=invoice_id)
        except Invoice.DoesNotExist:
            return Result.err(f"Invoice not found: {invoice_id}")

        if invoice.status != "draft":
            return Result.err(f"Invoice is not in draft status: {invoice.status}")

        with transaction.atomic():
            invoice.status = "issued"
            invoice.issued_at = timezone.now()
            invoice.locked_at = timezone.now()  # Make immutable
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

        return Result.ok(invoice)


class BillingCycleManager:
    """
    Manager for creating and advancing billing cycles.

    Handles:
    - Creating new billing cycles for subscriptions
    - Advancing to next billing period
    - Closing expired cycles
    """

    def create_billing_cycle(
        self,
        subscription_id: str,
        period_start: datetime | None = None
    ) -> Result:
        """
        Create a new billing cycle for a subscription.
        """
        from dateutil.relativedelta import relativedelta

        from .metering_models import BillingCycle
        from .subscription_models import Subscription

        try:
            subscription = Subscription.objects.get(id=subscription_id)
        except Subscription.DoesNotExist:
            return Result.err(f"Subscription not found: {subscription_id}")

        if not subscription.is_active:
            return Result.err(f"Subscription is not active: {subscription.status}")

        # Determine period start
        if period_start is None:
            # Use current period end as new start, or now if no current period
            period_start = subscription.current_period_end or timezone.now()

        # Calculate period end based on billing interval
        interval_map = {
            "monthly": relativedelta(months=1),
            "quarterly": relativedelta(months=3),
            "semi_annual": relativedelta(months=6),
            "annual": relativedelta(years=1),
        }
        delta = interval_map.get(subscription.billing_cycle, relativedelta(months=1))
        period_end = period_start + delta

        # Check for existing cycle
        existing = BillingCycle.objects.filter(
            subscription=subscription,
            period_start=period_start
        ).exists()

        if existing:
            return Result.err(f"Billing cycle already exists for period starting {period_start}")

        with transaction.atomic():
            billing_cycle = BillingCycle.objects.create(
                subscription=subscription,
                period_start=period_start,
                period_end=period_end,
                status="active",
                base_charge_cents=subscription.unit_price_cents,
            )

            # Update subscription's current period
            subscription.current_period_start = period_start
            subscription.current_period_end = period_end
            subscription.save(update_fields=["current_period_start", "current_period_end"])

            # Log creation
            AuditService.log_simple_event(
                event_type="billing_cycle_created",
                user=None,
                content_object=billing_cycle,
                description=f"Billing cycle created for {subscription}",
                actor_type="system",
                metadata={
                    "billing_cycle_id": str(billing_cycle.id),
                    "subscription_id": str(subscription.id),
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat(),
                    "base_charge_cents": subscription.unit_price_cents,
                },
            )

        return Result.ok(billing_cycle)

    def advance_all_subscriptions(self) -> tuple[int, int, list[str]]:
        """
        Check all subscriptions and create new billing cycles as needed.

        Returns: (created_count, error_count, errors)
        """
        from .subscription_models import Subscription

        active_subscriptions = Subscription.objects.filter(
            status__in=("active", "trialing")
        )

        created = 0
        errors = 0
        error_messages = []
        now = timezone.now()

        for subscription in active_subscriptions:
            # Check if current period has ended
            if subscription.current_period_end and subscription.current_period_end <= now:
                # Need to create new billing cycle
                result = self.create_billing_cycle(str(subscription.id))
                if result.is_ok():
                    created += 1
                else:
                    errors += 1
                    error_messages.append(
                        f"Subscription {subscription.id}: {result.error}"
                    )

        logger.info(
            f"Billing cycle advancement: {created} created, {errors} errors"
        )

        return created, errors, error_messages

    def close_expired_cycles(self) -> tuple[int, int]:
        """
        Close all billing cycles that have passed their end date.

        Returns: (closed_count, error_count)
        """
        from .metering_models import BillingCycle
        from .metering_service import AggregationService

        now = timezone.now()
        expired_cycles = BillingCycle.objects.filter(
            status="active",
            period_end__lte=now
        )

        aggregation_service = AggregationService()
        closed = 0
        errors = 0

        for cycle in expired_cycles:
            result = aggregation_service.close_billing_cycle(str(cycle.id))
            if result.is_ok():
                closed += 1
            else:
                errors += 1
                logger.error(f"Error closing cycle {cycle.id}: {result.error}")

        logger.info(f"Closed {closed} expired billing cycles, {errors} errors")

        return closed, errors

    def generate_pending_invoices(self) -> tuple[int, int]:
        """
        Generate invoices for all closed and rated billing cycles.

        Returns: (generated_count, error_count)
        """
        from .metering_models import BillingCycle

        pending_cycles = BillingCycle.objects.filter(
            status="closed",
            invoice__isnull=True
        )

        invoice_service = UsageInvoiceService()
        generated = 0
        errors = 0

        for cycle in pending_cycles:
            result = invoice_service.generate_invoice_from_cycle(str(cycle.id))
            if result.is_ok():
                generated += 1
            else:
                errors += 1
                logger.error(f"Error generating invoice for cycle {cycle.id}: {result.error}")

        logger.info(f"Generated {generated} invoices, {errors} errors")

        return generated, errors
