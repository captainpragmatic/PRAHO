"""
Subscription Service for PRAHO Platform
Business logic for subscription lifecycle and recurring billing.

Provides:
- Subscription creation and lifecycle management
- Price grandfathering when product prices change
- Recurring billing invoice generation
- Trial management
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any, TypedDict

from django.db import transaction
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.products.models import Product
    from apps.users.models import User

from .recurring_locking import lock_recurring_collection_customer
from .subscription_models import (
    PriceGrandfathering,
    Subscription,
)
from .validators import log_security_event

logger = logging.getLogger(__name__)

_DEFAULT_MAX_PAYMENT_RETRIES = 5
MAX_PAYMENT_RETRIES = _DEFAULT_MAX_PAYMENT_RETRIES

# Subscription.billing_cycle and ProductPrice.get_price_for_period speak different vocabularies.
# quarterly/custom are deliberately absent: ProductPrice only defines monthly, semiannual and
# annual pricing, so there is no list price to resolve for those cycles — they need an explicit
# custom_price_cents rather than an invented one.
_BILLING_CYCLE_TO_PRICE_PERIOD = {
    "monthly": "monthly",
    "semi_annual": "semiannual",
    "yearly": "annual",
}


def _resolve_subscription_unit_price_cents(product: Any, currency: Any, billing_cycle: str) -> Result[int, str]:
    """Resolve a product's list price in cents for a subscription's billing cycle.

    The list price lives on ProductPrice (per currency), not on Product: reading
    `product.price_cents` / `product.unit_price_cents` — neither of which exists — always yielded
    0, so every subscription without an explicit custom price was billed nothing (#209).
    """
    from apps.products.models import ProductPrice  # noqa: PLC0415  # Deferred: avoids circular import

    period = _BILLING_CYCLE_TO_PRICE_PERIOD.get(billing_cycle)
    if period is None:
        return Err(
            f"No list price is defined for billing cycle '{billing_cycle}'; "
            f"pass custom_price_cents for this subscription"
        )

    price = ProductPrice.objects.filter(product=product, currency=currency, is_active=True).first()
    if price is None:
        return Err(f"No active {getattr(currency, 'code', currency)} price for product {product}")

    cents = price.get_price_cents_for_period(period)
    has_active_free_promotion = (
        price.promo_price_cents == 0
        and price.promo_valid_until is not None
        and timezone.now() <= price.promo_valid_until
    )
    if cents <= 0 and not has_active_free_promotion:
        # A bare zero period price means "unset" on ProductPrice, not a real list price —
        # returning it as Ok would recreate the billed-zero defect this fix removes (#209).
        # An explicit, unexpired zero-cent promotion is intentional and remains valid.
        return Err(
            f"Product {product} has no usable {period} list price in "
            f"{getattr(currency, 'code', currency)}; pass custom_price_cents"
        )
    return Ok(cents)


def get_max_payment_retries() -> int:
    """Get max payment retries from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return SettingsService.get_integer_setting("billing.max_payment_retries", _DEFAULT_MAX_PAYMENT_RETRIES)


class _SubscriptionCreationError(ValueError):
    """Expected, customer-safe subscription creation failure."""


def _resolve_creation_currency(currency_code: str) -> Any:
    from .currency_models import Currency  # noqa: PLC0415

    try:
        return Currency.objects.get(code=currency_code)
    except Currency.DoesNotExist:
        if currency_code != "RON":
            raise _SubscriptionCreationError(f"Currency {currency_code} does not exist") from None
        return Currency.objects.create(code="RON", name="Romanian Leu", symbol="lei")


def _resolve_creation_service(customer: Any, product: Any, currency: Any, service_id: str | None) -> tuple[Any, Any]:
    if not service_id:
        return None, None

    from apps.provisioning.models import Service  # noqa: PLC0415

    try:
        service = Service.objects.select_for_update().get(pk=service_id)
    except Service.DoesNotExist:
        raise _SubscriptionCreationError(f"Service {service_id} does not exist") from None
    if service.customer_id != customer.id:
        raise _SubscriptionCreationError("Service and subscription customer do not match")
    if service.currency_id != currency.id:
        raise _SubscriptionCreationError("Service and subscription currency do not match")

    existing = Subscription.objects.filter(service=service).first()
    if existing is not None and (existing.customer_id != customer.id or existing.product_id != product.id):
        raise _SubscriptionCreationError("Service is already linked to a different subscription")
    return service, existing


def _resolve_creation_price(product: Any, currency: Any, data: SubscriptionCreateData) -> int:
    custom_price_cents = data.get("custom_price_cents")
    if custom_price_cents is not None:
        if custom_price_cents < 0:
            raise _SubscriptionCreationError("custom_price_cents cannot be negative")
        return custom_price_cents

    price_result = _resolve_subscription_unit_price_cents(product, currency, data.get("billing_cycle", "monthly"))
    if price_result.is_err():
        raise _SubscriptionCreationError(price_result.unwrap_err())
    return price_result.unwrap()


def _validate_idempotent_creation_terms(
    existing: Subscription,
    *,
    billing_cycle: str,
    quantity: int,
    unit_price_cents: int,
    custom_cycle_days: int | None,
) -> None:
    """Accept a service-enrollment retry only when its financial terms are identical."""
    requested_terms = {
        "billing_cycle": billing_cycle,
        "quantity": quantity,
        "unit_price_cents": unit_price_cents,
        "custom_cycle_days": custom_cycle_days,
    }
    mismatches = [field for field, value in requested_terms.items() if getattr(existing, field) != value]
    if mismatches:
        raise _SubscriptionCreationError(
            "Existing subscription does not match requested service enrollment terms: " + ", ".join(mismatches)
        )


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
    custom_cycle_days: int
    apply_grandfathering: bool
    custom_price_cents: int
    currency_code: str
    service_id: str
    metadata: dict[str, Any]


# ===============================================================================
# SUBSCRIPTION SERVICE
# ===============================================================================


class SubscriptionService:
    """
    Core service for subscription management.

    Handles:
    - Subscription creation and activation
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
            with transaction.atomic():
                from .recurring_billing import (  # noqa: PLC0415  # Deferred: avoids circular import
                    fixed_renewal_schedule,
                    next_billing_period_end,
                )

                if "payment_method_id" in data:
                    raise _SubscriptionCreationError(
                        "A raw gateway payment method cannot authorize recurring charges; "
                        "create a recurring-payment authorization and enroll the subscription separately"
                    )

                # Customer-initiated subscriptions default to RON. Order-backed
                # subscriptions must retain the paid order's currency snapshot.
                currency_code = data.get("currency_code", "RON").upper()
                currency = _resolve_creation_currency(currency_code)
                service, existing = _resolve_creation_service(
                    customer,
                    product,
                    currency,
                    data.get("service_id"),
                )
                billing_cycle = data.get("billing_cycle", "monthly")
                quantity = data.get("quantity", 1)
                custom_cycle_days = data.get("custom_cycle_days")
                unit_price_cents = _resolve_creation_price(product, currency, data)
                if existing is not None:
                    _validate_idempotent_creation_terms(
                        existing,
                        billing_cycle=billing_cycle,
                        quantity=quantity,
                        unit_price_cents=unit_price_cents,
                        custom_cycle_days=custom_cycle_days,
                    )
                    return Ok(existing)

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
                trial_days = data.get("trial_days", 0)
                if trial_days < 0:
                    raise _SubscriptionCreationError("trial_days cannot be negative")
                initial_period_end = next_billing_period_end(
                    now,
                    billing_cycle,
                    anchor_day=now.day,
                    custom_cycle_days=custom_cycle_days,
                )

                # Create subscription
                subscription = Subscription.objects.create(
                    customer=customer,
                    product=product,
                    service=service,
                    currency=currency,
                    billing_cycle=billing_cycle,
                    quantity=quantity,
                    unit_price_cents=unit_price_cents,
                    locked_price_cents=locked_price_cents,
                    locked_price_reason=locked_price_reason,
                    current_period_start=now,
                    current_period_end=initial_period_end,
                    next_billing_date=initial_period_end,
                    billing_anchor_day=now.day,
                    custom_cycle_days=custom_cycle_days,
                    meta=data.get("metadata", {}),
                    status="pending",
                    created_by=user,
                )

                # Handle trial period
                if trial_days > 0:
                    subscription.start_trial(trial_days, user)  # fsm-bypass: start_trial() calls self.save() internally
                else:
                    subscription.activate(user)  # fsm-bypass: activate() calls self.save() internally

                    subscription.current_period_end = next_billing_period_end(
                        subscription.current_period_start,
                        billing_cycle,
                        anchor_day=subscription.billing_anchor_day,
                        custom_cycle_days=custom_cycle_days,
                    )

                next_proforma_at, next_charge_at = fixed_renewal_schedule(subscription.current_period_end)
                subscription.next_proforma_at = next_proforma_at
                subscription.next_charge_at = next_charge_at
                subscription.next_billing_date = next_proforma_at
                subscription.save(
                    update_fields=[
                        "current_period_end",
                        "next_proforma_at",
                        "next_charge_at",
                        "next_billing_date",
                        "updated_at",
                    ]
                )
                if service is not None and (
                    service.expires_at is None or service.expires_at < subscription.current_period_end
                ):
                    service.expires_at = subscription.current_period_end
                    service.save(update_fields=["expires_at", "updated_at"])

                from .metering_models import BillingCycle  # noqa: PLC0415

                initial_cycle = BillingCycle.objects.create(
                    subscription=subscription,
                    period_start=subscription.current_period_start,
                    period_end=subscription.current_period_end,
                    collection_status="waived",
                    base_charge_cents=0,
                    total_cents=0,
                    meta={"source": "initial_subscription_entitlement"},
                )
                initial_cycle.activate()
                initial_cycle.save(update_fields=["status", "updated_at"])

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

        except _SubscriptionCreationError as e:
            return Err(str(e))
        except Exception as e:
            logger.exception(f"Failed to create subscription: {e}")
            return Err(f"Failed to create subscription: {e}")

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
            with transaction.atomic():
                locked_customer = lock_recurring_collection_customer(subscription.customer_id)
                locked_subscription = Subscription.objects.select_for_update(of=("self",)).get(pk=subscription.pk)
                if locked_subscription.customer_id != locked_customer.id:
                    return Err("Subscription customer changed during cancellation")
                locked_subscription.cancel(
                    reason=reason,
                    at_period_end=at_period_end,
                    feedback=feedback,
                    user=user,
                )
                if not at_period_end and locked_subscription.service_id:
                    from apps.provisioning.models import Service  # noqa: PLC0415

                    service = Service.objects.select_for_update(of=("self",)).get(pk=locked_subscription.service_id)
                    service.auto_renew = False
                    update_fields = ["auto_renew", "updated_at"]
                    if service.status in {"active", "suspended"}:
                        service.expire()
                        update_fields.append("status")
                    service.save(update_fields=update_fields)
            return Ok(locked_subscription)
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
            with transaction.atomic():
                locked_subscription = (
                    Subscription.objects.select_for_update(of=("self",))
                    .select_related("service")
                    .get(pk=subscription.pk)
                )
                if locked_subscription.status != "cancelled" and not locked_subscription.cancel_at_period_end:
                    return Err("Subscription is not cancelled")
                if locked_subscription.current_period_end <= timezone.now():
                    return Err("Subscription cannot be reactivated because its paid period has ended")

                service = None
                if locked_subscription.service_id:
                    from apps.provisioning.models import Service  # noqa: PLC0415

                    service = Service.objects.select_for_update(of=("self",)).get(pk=locked_subscription.service_id)
                    if service.status not in {"active", "suspended", "expired"}:
                        return Err(f"Linked service status {service.status} does not allow subscription reactivation")

                # Use FSM transition for cancelled → active; for cancel_at_period_end
                # the status is still active/other, so just clear the flag.
                if locked_subscription.status == "cancelled":
                    locked_subscription._reactivate_now()
                locked_subscription.cancel_at_period_end = False
                locked_subscription.cancelled_at = None
                locked_subscription.ended_at = None
                locked_subscription.cancellation_reason = ""
                locked_subscription.cancellation_feedback = ""
                locked_subscription.save()

                if service is not None:
                    service.auto_renew = True
                    service_update_fields = ["auto_renew", "updated_at"]
                    if service.status == "expired":
                        service.restore_from_expiration()
                        service_update_fields.extend(["status", "activated_at", "suspended_at", "suspension_reason"])
                    service.save(update_fields=service_update_fields)

                log_security_event(
                    event_type="subscription_reactivated",
                    details={
                        "subscription_id": str(locked_subscription.id),
                        "subscription_number": locked_subscription.subscription_number,
                    },
                    user_email=user.email if user else None,
                )

                return Ok(locked_subscription)

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
    def apply_grandfathering_for_price_increase(  # subscription fields  # noqa: PLR0913  # Business logic parameters
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
            with transaction.atomic():
                grandfathering = (
                    PriceGrandfathering.objects.select_for_update()
                    .filter(
                        customer=customer,
                        product=product,
                        is_active=True,
                    )
                    .first()
                )

                if not grandfathering:
                    return Err("No active grandfathering found")

                subscriptions = list(
                    Subscription.objects.select_for_update(of=("self",))
                    .filter(customer=customer, product=product)
                    .order_by("id")
                )
                grandfathering.expire(user)
                for subscription in subscriptions:
                    subscription.locked_price_cents = None
                    subscription.locked_price_reason = ""
                    subscription.locked_price_expires_at = None
                    subscription.save(
                        update_fields=[
                            "locked_price_cents",
                            "locked_price_reason",
                            "locked_price_expires_at",
                            "updated_at",
                        ]
                    )

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
# SUBSCRIPTION LIFECYCLE SERVICE
# ===============================================================================


class SubscriptionLifecycleService:
    """Non-renewal lifecycle handling around the single recurring orchestrator."""

    @staticmethod
    def finalize_period_end_cancellations(as_of: Any = None) -> int:
        """Complete cancellations once the customer's paid-through period ends."""
        run_at = as_of or timezone.now()
        finalized = 0
        subscriptions = Subscription.objects.filter(
            status__in=["active", "trialing", "past_due", "paused"],
            cancel_at_period_end=True,
            current_period_end__lte=run_at,
        ).values_list("id", "customer_id")
        for subscription_id, customer_id in subscriptions:
            try:
                with transaction.atomic():
                    locked_customer = lock_recurring_collection_customer(customer_id)
                    subscription = Subscription.objects.select_for_update(of=("self",)).get(id=subscription_id)
                    if (
                        subscription.customer_id != locked_customer.id
                        or subscription.status not in {"active", "trialing", "past_due", "paused"}
                        or not subscription.cancel_at_period_end
                        or subscription.current_period_end > run_at
                    ):
                        continue
                    subscription._cancel_now()
                    subscription.ended_at = run_at
                    subscription.save()
                    if subscription.service_id is not None:
                        from apps.provisioning.models import Service  # noqa: PLC0415

                        service = Service.objects.select_for_update(of=("self",)).get(id=subscription.service_id)
                        service.auto_renew = False
                        update_fields = ["auto_renew", "updated_at"]
                        if service.status in {"active", "suspended"}:
                            service.expire()
                            update_fields.append("status")
                        service.save(update_fields=update_fields)
                finalized += 1
            except TransitionNotAllowed:
                logger.warning(
                    "Subscription %s could not finalize period-end cancellation because its state changed",
                    subscription_id,
                )
        return finalized

    @staticmethod
    def handle_expired_trials(as_of: Any = None) -> tuple[int, int]:
        """Cancel trials that reached expiry without a successfully paid renewal."""
        run_at = as_of or timezone.now()
        count = 0
        errors = 0
        subscriptions = Subscription.objects.filter(
            status="trialing",
            trial_end__lte=run_at,
        ).values_list("id", "customer_id")

        for subscription_id, customer_id in subscriptions:
            try:
                with transaction.atomic():
                    locked_customer = lock_recurring_collection_customer(customer_id)
                    subscription = Subscription.objects.select_for_update(of=("self",)).get(id=subscription_id)
                    if (
                        subscription.customer_id != locked_customer.id
                        or subscription.status != "trialing"
                        or subscription.trial_end is None
                        or subscription.trial_end > run_at
                    ):
                        continue
                    subscription.cancel(reason="non_payment", at_period_end=False)
                    subscription.ended_at = run_at
                    subscription.save(update_fields=["ended_at", "updated_at"])
                    if subscription.service_id is not None:
                        from apps.provisioning.models import Service  # noqa: PLC0415

                        service = Service.objects.select_for_update(of=("self",)).get(id=subscription.service_id)
                        if service.status in {"active", "suspended"}:
                            service.expire()
                        service.auto_renew = False
                        service.save(update_fields=["status", "auto_renew", "updated_at"])
                count += 1
            except Exception:
                errors += 1
                logger.exception("Error expiring unpaid trial %s", subscription_id)

        return count, errors

    @staticmethod
    def handle_grace_period_expirations(as_of: Any = None) -> tuple[int, int]:
        """Pause or cancel subscriptions whose explicit dunning grace has elapsed."""
        run_at = as_of or timezone.now()
        count = 0
        errors = 0
        retry_limit = get_max_payment_retries()
        subscriptions = Subscription.objects.filter(
            status__in=["past_due", "paused"],
            grace_period_ends_at__lte=run_at,
        ).values_list("id", "customer_id")

        for subscription_id, customer_id in subscriptions:
            try:
                with transaction.atomic():
                    locked_customer = lock_recurring_collection_customer(customer_id)
                    subscription = Subscription.objects.select_for_update(of=("self",)).get(id=subscription_id)
                    if (
                        subscription.customer_id != locked_customer.id
                        or subscription.status not in {"past_due", "paused"}
                        or subscription.grace_period_ends_at is None
                        or subscription.grace_period_ends_at > run_at
                    ):
                        continue
                    cancelled = subscription.failed_payment_count >= retry_limit
                    if cancelled:
                        subscription.cancel(reason="non_payment", at_period_end=False)
                    elif subscription.status == "past_due":
                        subscription._pause_now()
                        subscription.paused_at = run_at
                        subscription.save()
                    else:
                        continue
                    if subscription.service_id is not None:
                        from apps.provisioning.models import Service  # noqa: PLC0415

                        service = Service.objects.select_for_update(of=("self",)).get(id=subscription.service_id)
                        service_update_fields = []
                        if cancelled:
                            service.auto_renew = False
                            service_update_fields.append("auto_renew")
                        if service.status == "active":
                            service.suspend(reason="payment_overdue")
                            service_update_fields.extend(["status", "suspended_at", "suspension_reason"])
                        if service_update_fields:
                            service_update_fields.append("updated_at")
                            service.save(update_fields=service_update_fields)
                count += 1
                log_security_event(
                    event_type=(
                        "subscription_cancelled_nonpayment" if cancelled else "subscription_suspended_nonpayment"
                    ),
                    details={
                        "subscription_id": str(subscription.id),
                        "subscription_number": subscription.subscription_number,
                        "failed_payment_count": subscription.failed_payment_count,
                    },
                )
            except Exception:
                errors += 1
                logger.exception("Error handling grace expiration for %s", subscription_id)

        return count, errors


# ===============================================================================
# EXPORTS
# ===============================================================================

__all__ = [
    "GrandfatheringService",
    "SubscriptionCreateData",
    "SubscriptionLifecycleService",
    "SubscriptionService",
]
