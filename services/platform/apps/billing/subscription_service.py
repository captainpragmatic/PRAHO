"""
Subscription Service for PRAHO Platform
Business logic for subscription management, proration, and recurring billing.

Provides:
- Subscription creation and lifecycle management
- Mid-cycle upgrades/downgrades with proration
- Price grandfathering when product prices change
- Recurring billing invoice generation
- Trial management
"""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.products.models import Product
    from apps.users.models import User

from .invoice_models import Invoice, InvoiceLine, InvoiceSequence
from .subscription_models import (
    PriceGrandfathering,
    Subscription,
    SubscriptionChange,
)
from .validators import log_security_event

logger = logging.getLogger(__name__)


# ===============================================================================
# TYPE DEFINITIONS
# ===============================================================================


class SubscriptionCreateData(TypedDict, total=False):
    """Data for creating a subscription."""

    customer_id: str
    product_id: str
    billing_cycle: str
    quantity: int
    trial_days: int
    payment_method_id: str
    apply_grandfathering: bool
    custom_price_cents: int
    metadata: dict[str, Any]


class SubscriptionChangeData(TypedDict, total=False):
    """Data for changing a subscription."""

    new_product_id: str
    new_quantity: int
    new_billing_cycle: str
    prorate: bool
    apply_immediately: bool
    reason: str


class ProrationResult(TypedDict):
    """Result of proration calculation."""

    unused_credit_cents: int
    new_charge_cents: int
    proration_amount_cents: int
    days_remaining: int
    days_in_period: int
    old_daily_rate_cents: int
    new_daily_rate_cents: int


class BillingRunResult(TypedDict):
    """Result of a billing run."""

    subscriptions_processed: int
    invoices_created: int
    payments_attempted: int
    payments_succeeded: int
    payments_failed: int
    total_billed_cents: int
    errors: list[str]


# ===============================================================================
# PRORATION SERVICE
# ===============================================================================


class ProrationService:
    """
    Service for calculating proration amounts for subscription changes.

    Proration ensures fair billing when customers upgrade or downgrade mid-cycle:
    - Upgrade: Customer gets credit for unused portion and is charged for new plan
    - Downgrade: Customer gets credit for unused portion, new charge is lower
    """

    @staticmethod
    def calculate_proration(
        old_price_cents: int,
        new_price_cents: int,
        old_quantity: int,
        new_quantity: int,
        days_remaining: int,
        days_in_period: int,
    ) -> ProrationResult:
        """
        Calculate proration for a mid-cycle subscription change.

        Args:
            old_price_cents: Current unit price in cents
            new_price_cents: New unit price in cents
            old_quantity: Current quantity
            new_quantity: New quantity
            days_remaining: Days left in current period
            days_in_period: Total days in billing period

        Returns:
            ProrationResult with calculated amounts
        """
        if days_in_period <= 0:
            days_in_period = 30  # Fallback to monthly

        # Calculate daily rates
        old_total = old_price_cents * old_quantity
        new_total = new_price_cents * new_quantity

        old_daily_rate = old_total / days_in_period
        new_daily_rate = new_total / days_in_period

        # Calculate unused credit (what customer already paid but won't use)
        unused_credit_cents = int(old_daily_rate * days_remaining)

        # Calculate new charge (what customer owes for new plan remainder)
        new_charge_cents = int(new_daily_rate * days_remaining)

        # Net proration (positive = customer pays, negative = credit)
        proration_amount_cents = new_charge_cents - unused_credit_cents

        return ProrationResult(
            unused_credit_cents=unused_credit_cents,
            new_charge_cents=new_charge_cents,
            proration_amount_cents=proration_amount_cents,
            days_remaining=days_remaining,
            days_in_period=days_in_period,
            old_daily_rate_cents=int(old_daily_rate),
            new_daily_rate_cents=int(new_daily_rate),
        )

    @staticmethod
    def calculate_subscription_proration(
        subscription: Subscription,
        new_price_cents: int,
        new_quantity: int = 1,
    ) -> ProrationResult:
        """
        Calculate proration for a specific subscription change.

        Args:
            subscription: The subscription being changed
            new_price_cents: New unit price in cents
            new_quantity: New quantity (defaults to 1)

        Returns:
            ProrationResult with calculated amounts
        """
        now = timezone.now()

        # Calculate days remaining
        days_remaining = 0 if subscription.current_period_end <= now else (subscription.current_period_end - now).days

        return ProrationService.calculate_proration(
            old_price_cents=subscription.effective_price_cents,
            new_price_cents=new_price_cents,
            old_quantity=subscription.quantity,
            new_quantity=new_quantity,
            days_remaining=days_remaining,
            days_in_period=subscription.cycle_days,
        )

    @staticmethod
    def calculate_upgrade_credit(
        subscription: Subscription,
    ) -> int:
        """Calculate credit for unused portion of current plan."""
        now = timezone.now()

        if subscription.current_period_end <= now:
            return 0

        days_remaining = (subscription.current_period_end - now).days
        daily_rate = (subscription.effective_price_cents * subscription.quantity) / subscription.cycle_days

        return int(daily_rate * days_remaining)


# ===============================================================================
# SUBSCRIPTION SERVICE
# ===============================================================================


class SubscriptionService:
    """
    Core service for subscription management.

    Handles:
    - Subscription creation and activation
    - Plan changes with proration
    - Cancellation and pausing
    - Trial management
    """

    @staticmethod
    def create_subscription(
        customer: Customer,
        product: Product,
        data: SubscriptionCreateData,
        user: User | None = None,
    ) -> Result[Subscription, str]:
        """
        Create a new subscription for a customer.

        Args:
            customer: Customer to subscribe
            product: Product/plan to subscribe to
            data: Subscription configuration
            user: User creating the subscription (for audit)

        Returns:
            Result with created subscription or error message
        """
        try:
            from .currency_models import Currency

            with transaction.atomic():
                # Get or create default currency
                try:
                    currency = Currency.objects.get(code="RON")
                except Currency.DoesNotExist:
                    currency = Currency.objects.create(code="RON", name="Romanian Leu", symbol="lei")

                # Determine price
                if data.get("custom_price_cents"):
                    unit_price_cents = data["custom_price_cents"]
                else:
                    unit_price_cents = getattr(product, "price_cents", 0) or getattr(product, "unit_price_cents", 0)

                # Check for grandfathering
                locked_price_cents = None
                locked_price_reason = ""
                if data.get("apply_grandfathering"):
                    grandfathering = PriceGrandfathering.objects.filter(
                        customer=customer,
                        product=product,
                        is_active=True,
                    ).first()
                    if grandfathering and not grandfathering.is_expired:
                        locked_price_cents = grandfathering.locked_price_cents
                        locked_price_reason = grandfathering.reason

                now = timezone.now()
                billing_cycle = data.get("billing_cycle", "monthly")
                quantity = data.get("quantity", 1)

                # Calculate cycle days
                from .subscription_models import BILLING_CYCLE_DAYS

                cycle_days = BILLING_CYCLE_DAYS.get(billing_cycle, 30)

                # Create subscription
                subscription = Subscription.objects.create(
                    customer=customer,
                    product=product,
                    currency=currency,
                    billing_cycle=billing_cycle,
                    quantity=quantity,
                    unit_price_cents=unit_price_cents,
                    locked_price_cents=locked_price_cents,
                    locked_price_reason=locked_price_reason,
                    current_period_start=now,
                    current_period_end=now + timedelta(days=cycle_days),
                    next_billing_date=now + timedelta(days=cycle_days),
                    payment_method_id=data.get("payment_method_id", ""),
                    meta=data.get("metadata", {}),
                    status="pending",
                    created_by=user,
                )

                # Handle trial period
                trial_days = data.get("trial_days", 0)
                if trial_days > 0:
                    subscription.start_trial(trial_days, user)
                else:
                    subscription.activate(user)

                log_security_event(
                    event_type="subscription_created",
                    details={
                        "subscription_id": str(subscription.id),
                        "subscription_number": subscription.subscription_number,
                        "customer_id": str(customer.id),
                        "product_id": str(product.id),
                        "billing_cycle": billing_cycle,
                        "effective_price_cents": subscription.effective_price_cents,
                        "is_grandfathered": subscription.is_grandfathered,
                        "trial_days": trial_days,
                        "critical_financial_operation": True,
                    },
                    user_email=user.email if user else None,
                )

                return Ok(subscription)

        except Exception as e:
            logger.exception(f"Failed to create subscription: {e}")
            return Err(f"Failed to create subscription: {e}")

    @staticmethod
    def change_subscription(
        subscription: Subscription,
        data: SubscriptionChangeData,
        user: User | None = None,
    ) -> Result[SubscriptionChange, str]:
        """
        Change a subscription (upgrade, downgrade, quantity change).

        Args:
            subscription: Subscription to change
            data: Change details
            user: User making the change (for audit)

        Returns:
            Result with SubscriptionChange record or error message
        """
        try:
            from apps.products.models import Product

            with transaction.atomic():
                # Determine new values
                new_product = subscription.product
                if data.get("new_product_id"):
                    new_product = Product.objects.get(id=data["new_product_id"])

                new_quantity = data.get("new_quantity", subscription.quantity)
                new_billing_cycle = data.get("new_billing_cycle", subscription.billing_cycle)
                new_price_cents = getattr(new_product, "price_cents", 0) or getattr(new_product, "unit_price_cents", 0)

                # Determine change type
                if data.get("new_product_id") and new_price_cents > subscription.effective_price_cents:
                    change_type = "upgrade"
                elif data.get("new_product_id") and new_price_cents < subscription.effective_price_cents:
                    change_type = "downgrade"
                elif new_quantity > subscription.quantity:
                    change_type = "quantity_increase"
                elif new_quantity < subscription.quantity:
                    change_type = "quantity_decrease"
                elif new_billing_cycle != subscription.billing_cycle:
                    change_type = "billing_cycle_change"
                else:
                    change_type = "price_change"

                # Create change record
                change = SubscriptionChange.objects.create(
                    subscription=subscription,
                    change_type=change_type,
                    old_product=subscription.product,
                    old_price_cents=subscription.effective_price_cents,
                    old_quantity=subscription.quantity,
                    old_billing_cycle=subscription.billing_cycle,
                    new_product=new_product,
                    new_price_cents=new_price_cents,
                    new_quantity=new_quantity,
                    new_billing_cycle=new_billing_cycle,
                    prorate=data.get("prorate", True),
                    apply_immediately=data.get("apply_immediately", True),
                    effective_date=timezone.now() if data.get("apply_immediately", True) else subscription.current_period_end,
                    reason=data.get("reason", ""),
                    created_by=user,
                )

                # Calculate proration
                change.calculate_proration()
                change.save()

                # Apply immediately if requested
                if data.get("apply_immediately", True):
                    change.apply(user)

                    # Create proration invoice if there's a charge
                    if change.proration_amount_cents > 0:
                        SubscriptionService._create_proration_invoice(subscription, change, user)

                log_security_event(
                    event_type="subscription_change_created",
                    details={
                        "subscription_id": str(subscription.id),
                        "change_id": str(change.id),
                        "change_type": change_type,
                        "proration_amount_cents": change.proration_amount_cents,
                        "apply_immediately": data.get("apply_immediately", True),
                        "critical_financial_operation": True,
                    },
                    user_email=user.email if user else None,
                )

                return Ok(change)

        except Exception as e:
            logger.exception(f"Failed to change subscription: {e}")
            return Err(f"Failed to change subscription: {e}")

    @staticmethod
    def _create_proration_invoice(
        subscription: Subscription,
        change: SubscriptionChange,
        user: User | None = None,
    ) -> Invoice:
        """Create an invoice for proration charges."""
        from .currency_models import Currency

        # Get sequence
        sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")

        # Get currency
        try:
            currency = Currency.objects.get(code="RON")
        except Currency.DoesNotExist:
            currency = Currency.objects.create(code="RON", name="Romanian Leu", symbol="lei")

        # Calculate tax using centralized TaxService (ADR-0015)
        from apps.common.tax_service import TaxService

        subtotal_cents = change.proration_amount_cents
        vat_rate = TaxService.get_vat_rate("RO", as_decimal=True)
        tax_cents = int(Decimal(subtotal_cents) * vat_rate)
        total_cents = subtotal_cents + tax_cents

        # Create invoice
        invoice = Invoice.objects.create(
            customer=subscription.customer,
            number=sequence.get_next_number("INV"),
            currency=currency,
            subtotal_cents=subtotal_cents,
            tax_cents=tax_cents,
            total_cents=total_cents,
            status="issued",
            issued_at=timezone.now(),
            due_at=timezone.now() + timedelta(days=7),
            bill_to_name=subscription.customer.company_name or subscription.customer.full_name or "",
            bill_to_email=subscription.customer.primary_email or "",
            bill_to_country="RO",
            meta={
                "subscription_id": str(subscription.id),
                "change_id": str(change.id),
                "type": "proration",
            },
            created_by=user,
        )

        # Create invoice line
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description=f"Proration: {change.change_type.replace('_', ' ').title()} - {subscription.product.name}",
            quantity=Decimal("1"),
            unit_price_cents=subtotal_cents,
            tax_rate=vat_rate,
            line_total_cents=total_cents,
        )

        # Link change to invoice
        change.invoice = invoice
        change.save(update_fields=["invoice"])

        return invoice

    @staticmethod
    def cancel_subscription(
        subscription: Subscription,
        reason: str = "customer_request",
        at_period_end: bool = True,
        feedback: str = "",
        user: User | None = None,
    ) -> Result[Subscription, str]:
        """
        Cancel a subscription.

        Args:
            subscription: Subscription to cancel
            reason: Cancellation reason code
            at_period_end: If True, cancel at end of period; if False, cancel immediately
            feedback: Optional customer feedback
            user: User cancelling (for audit)

        Returns:
            Result with updated subscription or error
        """
        try:
            subscription.cancel(
                reason=reason,
                at_period_end=at_period_end,
                feedback=feedback,
                user=user,
            )
            return Ok(subscription)
        except Exception as e:
            logger.exception(f"Failed to cancel subscription: {e}")
            return Err(f"Failed to cancel subscription: {e}")

    @staticmethod
    def reactivate_subscription(
        subscription: Subscription,
        user: User | None = None,
    ) -> Result[Subscription, str]:
        """
        Reactivate a cancelled subscription.

        Only works if subscription is cancelled but period hasn't ended.
        """
        try:
            if subscription.status != "cancelled" and not subscription.cancel_at_period_end:
                return Err("Subscription is not cancelled")

            with transaction.atomic():
                subscription.status = "active"
                subscription.cancel_at_period_end = False
                subscription.cancelled_at = None
                subscription.cancellation_reason = ""
                subscription.cancellation_feedback = ""
                subscription.save()

                log_security_event(
                    event_type="subscription_reactivated",
                    details={
                        "subscription_id": str(subscription.id),
                        "subscription_number": subscription.subscription_number,
                    },
                    user_email=user.email if user else None,
                )

                return Ok(subscription)

        except Exception as e:
            logger.exception(f"Failed to reactivate subscription: {e}")
            return Err(f"Failed to reactivate subscription: {e}")


# ===============================================================================
# GRANDFATHERING SERVICE
# ===============================================================================


class GrandfatheringService:
    """
    Service for managing price grandfathering when prices change.

    When a product's price increases, existing customers can be "grandfathered"
    to keep their old price for a period of time or indefinitely.
    """

    @staticmethod
    def apply_grandfathering_for_price_increase(
        product: Product,
        old_price_cents: int,
        new_price_cents: int,
        reason: str = "Price increase protection",
        expires_at: Any = None,
        user: User | None = None,
    ) -> Result[int, str]:
        """
        Apply grandfathering to all active subscribers when a price increases.

        Args:
            product: Product with price change
            old_price_cents: Previous price
            new_price_cents: New (higher) price
            reason: Reason for grandfathering
            expires_at: When grandfathering expires (None = never)
            user: User applying grandfathering

        Returns:
            Result with count of affected customers or error
        """
        try:
            if new_price_cents <= old_price_cents:
                return Err("New price must be higher than old price for grandfathering")

            with transaction.atomic():
                # Find all active subscriptions for this product
                active_subs = Subscription.objects.filter(
                    product=product,
                    status__in=["active", "trialing"],
                )

                count = 0
                for sub in active_subs:
                    # Skip if already grandfathered at same or lower price
                    if sub.locked_price_cents and sub.locked_price_cents <= old_price_cents:
                        continue

                    # Create grandfathering record
                    PriceGrandfathering.objects.update_or_create(
                        customer=sub.customer,
                        product=product,
                        defaults={
                            "locked_price_cents": old_price_cents,
                            "original_price_cents": old_price_cents,
                            "current_product_price_cents": new_price_cents,
                            "reason": reason,
                            "expires_at": expires_at,
                            "is_active": True,
                            "created_by": user,
                        },
                    )

                    # Update subscription
                    sub.apply_grandfathered_price(
                        locked_price_cents=old_price_cents,
                        reason=reason,
                        expires_at=expires_at,
                        user=user,
                    )

                    count += 1

                log_security_event(
                    event_type="bulk_grandfathering_applied",
                    details={
                        "product_id": str(product.id),
                        "old_price_cents": old_price_cents,
                        "new_price_cents": new_price_cents,
                        "customers_affected": count,
                        "reason": reason,
                        "critical_financial_operation": True,
                    },
                    user_email=user.email if user else None,
                )

                return Ok(count)

        except Exception as e:
            logger.exception(f"Failed to apply grandfathering: {e}")
            return Err(f"Failed to apply grandfathering: {e}")

    @staticmethod
    def expire_grandfathering(
        customer: Customer,
        product: Product,
        user: User | None = None,
    ) -> Result[bool, str]:
        """Expire a specific customer's grandfathering for a product."""
        try:
            grandfathering = PriceGrandfathering.objects.filter(
                customer=customer,
                product=product,
                is_active=True,
            ).first()

            if not grandfathering:
                return Err("No active grandfathering found")

            grandfathering.expire(user)

            # Update subscription
            sub = Subscription.objects.filter(
                customer=customer,
                product=product,
                status__in=["active", "trialing"],
            ).first()

            if sub:
                sub.locked_price_cents = None
                sub.locked_price_reason = ""
                sub.locked_price_expires_at = None
                sub.save()

            return Ok(True)

        except Exception as e:
            logger.exception(f"Failed to expire grandfathering: {e}")
            return Err(f"Failed to expire grandfathering: {e}")

    @staticmethod
    def get_customer_grandfathering(customer: Customer) -> list[PriceGrandfathering]:
        """Get all active grandfathering for a customer."""
        return list(
            PriceGrandfathering.objects.filter(
                customer=customer,
                is_active=True,
            )
            .select_related("product")
            .order_by("-locked_at")
        )

    @staticmethod
    def check_expiring_grandfathering(days_ahead: int = 30) -> list[PriceGrandfathering]:
        """Find grandfathering records expiring within N days."""
        expiry_threshold = timezone.now() + timedelta(days=days_ahead)

        return list(
            PriceGrandfathering.objects.filter(
                is_active=True,
                expires_at__isnull=False,
                expires_at__lte=expiry_threshold,
                expiry_notified=False,
            ).select_related("customer", "product")
        )


# ===============================================================================
# RECURRING BILLING SERVICE
# ===============================================================================


class RecurringBillingService:
    """
    Service for processing recurring billing.

    Handles:
    - Daily billing runs for subscriptions due for renewal
    - Invoice generation
    - Payment processing
    - Failed payment handling
    """

    @staticmethod
    def run_billing_cycle(
        billing_date: Any = None,
        dry_run: bool = False,
    ) -> BillingRunResult:
        """
        Process all subscriptions due for billing.

        Args:
            billing_date: Date to run billing for (defaults to today)
            dry_run: If True, don't actually create invoices or charge

        Returns:
            BillingRunResult with statistics
        """
        billing_date = billing_date or timezone.now()

        result = BillingRunResult(
            subscriptions_processed=0,
            invoices_created=0,
            payments_attempted=0,
            payments_succeeded=0,
            payments_failed=0,
            total_billed_cents=0,
            errors=[],
        )

        # Find subscriptions due for billing
        due_subscriptions = Subscription.objects.filter(
            status="active",
            next_billing_date__lte=billing_date,
        ).select_related("customer", "product", "currency")

        for subscription in due_subscriptions:
            try:
                result["subscriptions_processed"] += 1

                if dry_run:
                    result["total_billed_cents"] += subscription.total_price_cents
                    continue

                # Generate invoice
                invoice_result = RecurringBillingService._generate_renewal_invoice(subscription)

                if invoice_result.is_ok():
                    invoice = invoice_result.unwrap()
                    result["invoices_created"] += 1
                    result["total_billed_cents"] += invoice.total_cents

                    # Attempt payment
                    if subscription.payment_method_id:
                        result["payments_attempted"] += 1
                        payment_result = RecurringBillingService._process_payment(subscription, invoice)

                        if payment_result.is_ok():
                            result["payments_succeeded"] += 1
                            subscription.record_payment(invoice.total_cents)
                            subscription.renew()
                        else:
                            result["payments_failed"] += 1
                            subscription.mark_payment_failed()
                            result["errors"].append(f"Payment failed for {subscription.subscription_number}: {payment_result.error}")
                    else:
                        # No payment method, just renew (manual payment expected)
                        subscription.renew()

                else:
                    result["errors"].append(f"Invoice generation failed for {subscription.subscription_number}: {invoice_result.error}")

            except Exception as e:
                logger.exception(f"Error processing subscription {subscription.id}: {e}")
                result["errors"].append(f"Error for {subscription.subscription_number}: {e}")

        log_security_event(
            event_type="billing_cycle_completed",
            details={
                "billing_date": billing_date.isoformat() if hasattr(billing_date, "isoformat") else str(billing_date),
                "subscriptions_processed": result["subscriptions_processed"],
                "invoices_created": result["invoices_created"],
                "payments_succeeded": result["payments_succeeded"],
                "payments_failed": result["payments_failed"],
                "total_billed_cents": result["total_billed_cents"],
                "dry_run": dry_run,
                "critical_financial_operation": True,
            },
        )

        return result

    @staticmethod
    def _generate_renewal_invoice(subscription: Subscription) -> Result[Invoice, str]:
        """Generate a renewal invoice for a subscription."""
        try:

            sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")

            # Calculate amounts using centralized TaxService (ADR-0015)
            from apps.common.tax_service import TaxService

            subtotal_cents = subscription.total_price_cents
            tax_rate = TaxService.get_vat_rate("RO", as_decimal=True)
            tax_cents = int(Decimal(subtotal_cents) * tax_rate)
            total_cents = subtotal_cents + tax_cents

            # Create invoice
            invoice = Invoice.objects.create(
                customer=subscription.customer,
                number=sequence.get_next_number("INV"),
                currency=subscription.currency,
                subtotal_cents=subtotal_cents,
                tax_cents=tax_cents,
                total_cents=total_cents,
                status="issued",
                issued_at=timezone.now(),
                due_at=timezone.now() + timedelta(days=14),
                bill_to_name=subscription.customer.company_name or subscription.customer.full_name or "",
                bill_to_email=subscription.customer.primary_email or "",
                bill_to_country="RO",
                meta={
                    "subscription_id": str(subscription.id),
                    "subscription_number": subscription.subscription_number,
                    "billing_period_start": subscription.current_period_start.isoformat(),
                    "billing_period_end": subscription.current_period_end.isoformat(),
                    "type": "recurring",
                },
            )

            # Create invoice line
            period_desc = f"{subscription.current_period_start.strftime('%Y-%m-%d')} to {subscription.current_period_end.strftime('%Y-%m-%d')}"
            InvoiceLine.objects.create(
                invoice=invoice,
                kind="service",
                description=f"{subscription.product.name} - {subscription.billing_cycle.title()} ({period_desc})",
                quantity=Decimal(subscription.quantity),
                unit_price_cents=subscription.effective_price_cents,
                tax_rate=tax_rate,
                line_total_cents=total_cents,
            )

            return Ok(invoice)

        except Exception as e:
            logger.exception(f"Failed to generate renewal invoice: {e}")
            return Err(f"Failed to generate invoice: {e}")

    @staticmethod
    def _process_payment(subscription: Subscription, invoice: Invoice) -> Result[bool, str]:
        """
        Process payment for an invoice.

        TODO: Implement actual Stripe payment processing.
        """
        # Placeholder - actual implementation would use Stripe API
        logger.info(
            f"💳 [Payment] Would process payment for invoice {invoice.number} "
            f"using payment method {subscription.payment_method_id}"
        )

        # For now, return success to allow testing
        # In production, this would call Stripe or other payment gateway
        return Ok(True)

    @staticmethod
    def handle_expired_trials() -> int:
        """
        Process expired trials - convert or cancel.

        Returns count of trials processed.
        """
        now = timezone.now()
        count = 0

        expired_trials = Subscription.objects.filter(
            status="trialing",
            trial_end__lte=now,
        )

        for subscription in expired_trials:
            try:
                if subscription.payment_method_id:
                    # Has payment method - convert to paid
                    subscription.convert_trial()
                else:
                    # No payment method - cancel
                    subscription.cancel(
                        reason="non_payment",
                        at_period_end=False,
                    )
                count += 1
            except Exception as e:
                logger.exception(f"Error processing expired trial {subscription.id}: {e}")

        return count

    @staticmethod
    def handle_grace_period_expirations() -> int:
        """
        Handle subscriptions with expired grace periods.

        Returns count of subscriptions suspended.
        """
        now = timezone.now()
        count = 0

        expired_grace = Subscription.objects.filter(
            status="past_due",
            grace_period_ends_at__lte=now,
        )

        for subscription in expired_grace:
            try:
                if subscription.failed_payment_count >= 5:
                    # Max retries exceeded - cancel
                    subscription.cancel(
                        reason="non_payment",
                        at_period_end=False,
                    )
                else:
                    # Suspend services but keep subscription
                    subscription.status = "paused"
                    subscription.paused_at = now
                    subscription.save()

                count += 1

                log_security_event(
                    event_type="subscription_suspended_nonpayment",
                    details={
                        "subscription_id": str(subscription.id),
                        "subscription_number": subscription.subscription_number,
                        "failed_payment_count": subscription.failed_payment_count,
                    },
                )

            except Exception as e:
                logger.exception(f"Error handling grace expiration for {subscription.id}: {e}")

        return count


# ===============================================================================
# EXPORTS
# ===============================================================================

__all__ = [
    "BillingRunResult",
    "GrandfatheringService",
    "ProrationResult",
    "ProrationService",
    "RecurringBillingService",
    "SubscriptionChangeData",
    "SubscriptionCreateData",
    "SubscriptionService",
]
