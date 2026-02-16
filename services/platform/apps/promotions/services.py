"""
Promotion services for PRAHO Platform.
Business logic for coupon validation, application, and discount calculation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.db import models, transaction
from django.db.models import F
from django.utils import timezone

from .models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    GiftCardTransaction,
    LoyaltyProgram,
    LoyaltyTier,
    LoyaltyTransaction,
    PromotionRule,
    Referral,
    ReferralCode,
)

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order, OrderItem
    from apps.users.models import User

logger = logging.getLogger(__name__)


# ===============================================================================
# Constants
# ===============================================================================

MAX_CODE_GENERATION_ATTEMPTS = 100  # Prevent infinite loops in code generation (structural safety limit)


# ===============================================================================
# Data Classes for Results
# ===============================================================================


@dataclass
class ValidationResult:
    """
    Result of coupon/promotion validation.

    Attributes:
        is_valid: Whether the coupon/promotion can be applied.
        error_message: Human-readable error message if validation failed.
        error_code: Machine-readable error code for programmatic handling.
            Codes: INVALID_CODE, COUPON_EXPIRED, COUPON_DEPLETED, CUSTOMER_INELIGIBLE,
            MIN_ORDER_NOT_MET, MIN_ITEMS_NOT_MET, NO_ELIGIBLE_PRODUCTS,
            CURRENCY_MISMATCH, ALREADY_APPLIED, EXCLUSIVE_CONFLICT,
            EXISTING_EXCLUSIVE, NOT_STACKABLE
        warnings: Optional list of warnings (e.g., "Coupon expires in 2 days").
    """

    is_valid: bool
    error_message: str = ""
    error_code: str = ""
    warnings: list[str] | None = None


@dataclass
class DiscountResult:
    """
    Result of discount calculation.

    Attributes:
        discount_cents: Calculated discount amount in cents.
        discount_type: Type of discount (percent, fixed, free_shipping, etc.).
        discount_description: Human-readable description (e.g., "20% off").
        applied_to_items: List of order item IDs the discount applies to.
        free_shipping: Whether free shipping is included.
        free_setup: Whether setup fees are waived.
        breakdown: Detailed breakdown of how discount was calculated.
    """

    discount_cents: int = 0
    discount_type: str = ""
    discount_description: str = ""
    applied_to_items: list[str] | None = None
    free_shipping: bool = False
    free_setup: bool = False
    breakdown: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApplyResult:
    """
    Result of applying a discount to an order.

    Attributes:
        success: Whether the discount was successfully applied.
        discount_cents: Amount of discount applied in cents.
        redemption_id: UUID of the CouponRedemption record created.
        error_message: Human-readable error message if application failed.
        warnings: Optional list of warnings about the applied discount.
    """

    success: bool
    discount_cents: int = 0
    redemption_id: str | None = None
    error_message: str = ""
    warnings: list[str] | None = None


# ===============================================================================
# Coupon Service
# ===============================================================================


class CouponService:
    """
    Service for coupon validation, calculation, and application.
    Handles all coupon-related business logic.
    """

    @staticmethod
    def normalize_code(code: str) -> str:
        """Normalize coupon code to uppercase and trimmed."""
        return code.upper().strip()

    @classmethod
    def get_coupon_by_code(cls, code: str) -> Coupon | None:
        """Get coupon by code (case-insensitive)."""
        normalized_code = cls.normalize_code(code)
        try:
            return Coupon.objects.select_related("campaign", "currency", "assigned_customer").get(code=normalized_code)
        except Coupon.DoesNotExist:
            return None

    @classmethod
    def validate_coupon(
        cls,
        code: str,
        order: Order,
        customer: Customer | None = None,
        cached_items: list[OrderItem] | None = None,
    ) -> ValidationResult:
        """
        Validate a coupon code for an order.
        Performs all validation checks and returns detailed result.

        Args:
            code: Coupon code to validate.
            order: Order to validate against.
            customer: Customer attempting to use the coupon.
            cached_items: Pre-fetched order items to avoid N+1 queries.
        """
        coupon = cls.get_coupon_by_code(code)

        if coupon is None:
            return ValidationResult(
                is_valid=False,
                error_message="Invalid coupon code",
                error_code="INVALID_CODE",
            )

        return cls._validate_coupon_instance(coupon, order, customer, cached_items)

    @classmethod
    def _validate_coupon_instance(  # noqa: C901, PLR0911, PLR0912
        cls,
        coupon: Coupon,
        order: Order,
        customer: Customer | None = None,
        cached_items: list[OrderItem] | None = None,
    ) -> ValidationResult:
        """
        Internal validation using a coupon instance.
        Separated to allow validation with locked coupon in apply_coupon.
        """
        # Cache order items to avoid N+1 queries
        if cached_items is None:
            cached_items = list(order.items.select_related("product").all())

        # Basic validity check
        can_use, reason = coupon.can_be_used()
        if not can_use:
            return ValidationResult(
                is_valid=False,
                error_message=reason,
                error_code="COUPON_INVALID",
            )

        # Customer-specific check
        can_customer_use, customer_reason = coupon.can_customer_use(customer)
        if not can_customer_use:
            return ValidationResult(
                is_valid=False,
                error_message=customer_reason,
                error_code="CUSTOMER_INELIGIBLE",
            )

        # Minimum order check
        if coupon.min_order_cents and order.subtotal_cents < coupon.min_order_cents:
            min_order = coupon.min_order_cents / 100
            currency = order.currency.code if order.currency else "RON"
            return ValidationResult(
                is_valid=False,
                error_message=f"Minimum order of {min_order:.2f} {currency} required",
                error_code="MIN_ORDER_NOT_MET",
            )

        # Minimum items check
        if coupon.min_order_items and len(cached_items) < coupon.min_order_items:
            return ValidationResult(
                is_valid=False,
                error_message=f"Minimum {coupon.min_order_items} items required",
                error_code="MIN_ITEMS_NOT_MET",
            )

        # Product restrictions check
        if not coupon.applies_to_all_products:
            valid_items = cls._filter_valid_items_for_coupon(coupon, cached_items)
            if not valid_items:
                return ValidationResult(
                    is_valid=False,
                    error_message="No eligible products in order for this coupon",
                    error_code="NO_ELIGIBLE_PRODUCTS",
                )

        # Currency check for fixed discounts
        if (
            coupon.discount_type == "fixed"
            and coupon.currency
            and order.currency
            and order.currency.code != coupon.currency.code
        ):
            return ValidationResult(
                is_valid=False,
                error_message=f"Coupon only valid for {coupon.currency.code} orders",
                error_code="CURRENCY_MISMATCH",
            )

        # Check if already applied to this order
        if CouponRedemption.objects.filter(coupon=coupon, order=order).exists():
            return ValidationResult(
                is_valid=False,
                error_message="This coupon is already applied to the order",
                error_code="ALREADY_APPLIED",
            )

        # Check exclusivity with other coupons
        if coupon.is_exclusive:
            existing_coupons = order.coupon_redemptions.filter(status="applied")
            if existing_coupons.exists():
                return ValidationResult(
                    is_valid=False,
                    error_message="This coupon cannot be combined with other discounts",
                    error_code="EXCLUSIVE_CONFLICT",
                )

        # Check if existing coupons are exclusive
        existing_exclusive = order.coupon_redemptions.filter(
            status="applied",
            coupon__is_exclusive=True,
        )
        if existing_exclusive.exists():
            return ValidationResult(
                is_valid=False,
                error_message="An exclusive coupon is already applied",
                error_code="EXISTING_EXCLUSIVE",
            )

        # Check stacking limits
        existing_coupons = order.coupon_redemptions.filter(status="applied")
        if existing_coupons.exists():
            # If this coupon is not stackable, it can't be added to existing coupons
            if not coupon.is_stackable:
                return ValidationResult(
                    is_valid=False,
                    error_message="This coupon cannot be stacked with other coupons",
                    error_code="NOT_STACKABLE",
                )
            # If any existing coupon is non-stackable, no new coupons can be added
            existing_non_stackable = existing_coupons.filter(coupon__is_stackable=False)
            if existing_non_stackable.exists():
                return ValidationResult(
                    is_valid=False,
                    error_message="Cannot add more coupons - existing coupon does not allow stacking",
                    error_code="EXISTING_NOT_STACKABLE",
                )

        # All checks passed
        warnings = []
        if coupon.valid_until:
            days_left = (coupon.valid_until - timezone.now()).days
            if days_left <= 3:
                warnings.append(f"Coupon expires in {days_left} day(s)")

        return ValidationResult(is_valid=True, warnings=warnings or None)

    @classmethod
    def _get_valid_items_for_coupon(cls, coupon: Coupon, order: Order) -> list[OrderItem]:
        """
        Get order items that are valid for a coupon's restrictions.
        Fetches items from database - use _filter_valid_items_for_coupon for cached items.
        """
        items = list(order.items.select_related("product").all())
        return cls._filter_valid_items_for_coupon(coupon, items)

    @classmethod
    def _filter_valid_items_for_coupon(
        cls,
        coupon: Coupon,
        items: list[OrderItem],
    ) -> list[OrderItem]:
        """
        Filter pre-fetched order items by coupon restrictions.
        Use this with cached items to avoid N+1 queries.
        """
        valid_items = []
        restrictions = coupon.product_restrictions or {}

        for item in items:
            is_valid = True

            # Check product IDs
            product_ids = restrictions.get("product_ids", [])
            if product_ids and str(item.product_id) not in product_ids:
                is_valid = False

            # Check excluded products
            excluded_ids = restrictions.get("excluded_product_ids", [])
            if excluded_ids and str(item.product_id) in excluded_ids:
                is_valid = False

            # Check product types - use snapshot field on OrderItem
            product_types = restrictions.get("product_types", [])
            if product_types and item.product_type not in product_types:
                is_valid = False

            # Check billing periods
            billing_periods = restrictions.get("billing_periods", [])
            if billing_periods and item.billing_period not in billing_periods:
                is_valid = False

            if is_valid:
                valid_items.append(item)

        return valid_items

    @classmethod
    def calculate_discount(
        cls,
        coupon: Coupon,
        order: Order,
        items: list[OrderItem] | None = None,
    ) -> DiscountResult:
        """
        Calculate the discount amount for a coupon.
        Returns detailed breakdown of the discount.
        """
        if items is None:
            if coupon.applies_to_all_products:
                items = list(order.items.all())
            else:
                items = cls._get_valid_items_for_coupon(coupon, order)

        if not items:
            return DiscountResult()

        # Calculate base amount to apply discount to
        base_amount_cents = sum(item.quantity * item.unit_price_cents + item.setup_cents for item in items)

        discount_cents = 0
        discount_description = ""
        breakdown: dict[str, Any] = {}

        if coupon.discount_type == "percent":
            discount_percent = coupon.discount_percent or Decimal("0")
            discount_cents = int(base_amount_cents * discount_percent / 100)
            discount_description = f"{discount_percent}% off"
            breakdown = {
                "type": "percent",
                "percent": float(discount_percent),
                "base_amount_cents": base_amount_cents,
            }

        elif coupon.discount_type == "fixed":
            discount_cents = coupon.discount_amount_cents or 0
            discount_description = f"{discount_cents / 100:.2f} off"
            breakdown = {
                "type": "fixed",
                "fixed_amount_cents": discount_cents,
            }

        elif coupon.discount_type == "free_shipping":
            # Free shipping would need to be handled by the order model
            return DiscountResult(
                discount_cents=0,
                discount_type="free_shipping",
                discount_description="Free shipping",
                free_shipping=True,
                breakdown={"type": "free_shipping"},
            )

        elif coupon.discount_type == "free_setup":
            # Calculate total setup fees
            setup_fees = sum(item.setup_cents for item in items)
            discount_cents = setup_fees
            discount_description = "Free setup"
            breakdown = {
                "type": "free_setup",
                "setup_fees_waived": setup_fees,
            }
            return DiscountResult(
                discount_cents=discount_cents,
                discount_type="free_setup",
                discount_description=discount_description,
                free_setup=True,
                applied_to_items=[str(item.id) for item in items],
                breakdown=breakdown,
            )

        elif coupon.discount_type == "free_months":
            # Calculate value of free months
            free_months = coupon.free_months or 1
            # This would need integration with billing period calculations
            discount_cents = 0  # Placeholder - would need actual calculation
            discount_description = f"{free_months} free month(s)"
            breakdown = {
                "type": "free_months",
                "free_months": free_months,
            }

        # Apply maximum discount cap
        if coupon.max_discount_cents and discount_cents > coupon.max_discount_cents:
            discount_cents = coupon.max_discount_cents
            breakdown["capped_at"] = coupon.max_discount_cents

        # Ensure discount doesn't exceed base amount
        if discount_cents > base_amount_cents:
            discount_cents = base_amount_cents
            breakdown["limited_to_order_value"] = True

        return DiscountResult(
            discount_cents=discount_cents,
            discount_type=coupon.discount_type,
            discount_description=discount_description,
            applied_to_items=[str(item.id) for item in items],
            breakdown=breakdown,
        )

    @classmethod
    @transaction.atomic
    def apply_coupon(  # noqa: PLR0913
        cls,
        code: str,
        order: Order,
        customer: Customer | None = None,
        user: User | None = None,
        source_ip: str | None = None,
        user_agent: str = "",
    ) -> ApplyResult:
        """
        Apply a coupon to an order with race condition protection.

        Uses SELECT FOR UPDATE to lock the coupon row and prevent concurrent
        applications from exceeding usage limits or campaign budgets.

        Args:
            code: Coupon code to apply.
            order: Order to apply the coupon to.
            customer: Customer applying the coupon.
            user: User performing the action (for audit).
            source_ip: Client IP address (for audit).
            user_agent: Client user agent (for audit).
        """
        normalized_code = cls.normalize_code(code)

        # Pre-fetch order items once for all operations
        cached_items = list(order.items.select_related("product").all())

        # Quick validation without lock (fast-fail for invalid codes)
        coupon = cls.get_coupon_by_code(code)
        if coupon is None:
            return ApplyResult(success=False, error_message="Invalid coupon code")

        # RACE CONDITION FIX: Lock the coupon row to prevent concurrent applications
        # This prevents multiple requests from using the last available coupon use
        try:
            locked_coupon = (
                Coupon.objects.select_for_update()
                .select_related("campaign", "currency", "assigned_customer")
                .get(code=normalized_code)
            )
        except Coupon.DoesNotExist:
            return ApplyResult(success=False, error_message="Coupon not found")

        # Re-validate with locked coupon (state may have changed)
        validation = cls._validate_coupon_instance(locked_coupon, order, customer, cached_items)
        if not validation.is_valid:
            logger.warning(
                "Coupon validation failed after lock: %s for order %s - %s",
                code,
                order.order_number,
                validation.error_message,
                extra={
                    "coupon_code": code,
                    "order_id": str(order.id),
                    "error": validation.error_message,
                },
            )
            return ApplyResult(
                success=False,
                error_message=validation.error_message,
            )

        # Calculate discount with cached items
        discount_result = cls.calculate_discount(locked_coupon, order, items=cached_items)

        # Create redemption record
        redemption = CouponRedemption.objects.create(
            coupon=locked_coupon,
            order=order,
            customer=customer,
            status="pending",
            discount_type=locked_coupon.discount_type,
            discount_value=(
                locked_coupon.discount_percent
                if locked_coupon.discount_type == "percent"
                else Decimal(locked_coupon.discount_amount_cents or 0) / 100
            ),
            discount_cents=discount_result.discount_cents,
            currency_code=order.currency.code if order.currency else "RON",
            order_subtotal_cents=order.subtotal_cents,
            order_total_cents=order.total_cents,
            applied_to_items=discount_result.applied_to_items or [],
            source_ip=source_ip,
            user_agent=user_agent,
        )

        # Apply discount to order
        order.discount_cents += discount_result.discount_cents
        order.save(update_fields=["discount_cents"])

        # Recalculate order totals
        order.calculate_totals()

        # Update redemption with final order total and mark as applied
        # This also updates coupon.total_uses atomically with F() expression
        redemption.order_total_cents = order.total_cents
        redemption.mark_applied(discount_result.discount_cents)

        logger.info(
            "Coupon applied: %s to order %s for %d cents",
            code,
            order.order_number,
            discount_result.discount_cents,
            extra={
                "coupon_code": code,
                "order_id": str(order.id),
                "discount_cents": discount_result.discount_cents,
                "redemption_id": str(redemption.id),
            },
        )

        return ApplyResult(
            success=True,
            discount_cents=discount_result.discount_cents,
            redemption_id=str(redemption.id),
            warnings=validation.warnings,
        )

    @classmethod
    @transaction.atomic
    def remove_coupon(
        cls,
        order: Order,
        coupon: Coupon | None = None,
        redemption_id: str | None = None,
    ) -> bool:
        """
        Remove a coupon from an order.
        Can specify either coupon or redemption_id.
        """
        if redemption_id:
            redemptions = CouponRedemption.objects.filter(
                id=redemption_id,
                order=order,
                status="applied",
            )
        elif coupon:
            redemptions = CouponRedemption.objects.filter(
                coupon=coupon,
                order=order,
                status="applied",
            )
        else:
            # Remove all coupons from order
            redemptions = CouponRedemption.objects.filter(
                order=order,
                status="applied",
            )

        for redemption in redemptions:
            # Reverse the redemption
            redemption.mark_reversed()

            # Update order discount
            order.discount_cents = max(0, order.discount_cents - redemption.discount_cents)

        order.save(update_fields=["discount_cents"])
        order.calculate_totals()

        return True

    @classmethod
    def get_available_coupons_for_order(
        cls,
        order: Order,
        customer: Customer | None = None,
        include_private: bool = False,
    ) -> list[Coupon]:
        """
        Get list of coupons that could be applied to an order.
        Used for suggesting coupons to customers.
        """
        now = timezone.now()

        # Base query for active, valid coupons
        queryset = Coupon.objects.filter(
            is_active=True,
            status="active",
            valid_from__lte=now,
        ).filter(models.Q(valid_until__isnull=True) | models.Q(valid_until__gte=now))

        if not include_private:
            queryset = queryset.filter(is_public=True)

        # Include personal coupons for this customer
        if customer:
            queryset = queryset.filter(models.Q(assigned_customer__isnull=True) | models.Q(assigned_customer=customer))
        else:
            queryset = queryset.filter(assigned_customer__isnull=True)

        # Filter out depleted coupons
        queryset = queryset.exclude(
            usage_limit_type="single_use",
            total_uses__gte=1,
        ).exclude(
            usage_limit_type="limited",
            total_uses__gte=models.F("max_total_uses"),
        )

        available = []
        for coupon in queryset.select_related("campaign", "currency"):
            validation = cls.validate_coupon(coupon.code, order, customer)
            if validation.is_valid:
                available.append(coupon)

        return available


# ===============================================================================
# Promotion Rule Service
# ===============================================================================


class PromotionRuleService:
    """
    Service for automatic promotion rules.
    Handles rule matching and discount application.
    """

    @classmethod
    def get_applicable_rules(
        cls,
        order: Order,
        cached_items: list[OrderItem] | None = None,
    ) -> list[PromotionRule]:
        """
        Get all promotion rules that apply to an order.

        Args:
            order: Order to check rules against.
            cached_items: Pre-fetched order items to avoid N+1 queries.
        """
        now = timezone.now()

        # Cache items if not provided
        if cached_items is None:
            cached_items = list(order.items.select_related("product").all())

        queryset = (
            PromotionRule.objects.filter(
                is_active=True,
                valid_from__lte=now,
            )
            .filter(models.Q(valid_until__isnull=True) | models.Q(valid_until__gte=now))
            .select_related("campaign", "currency")
            .order_by("priority")
        )

        applicable = [rule for rule in queryset if cls._rule_matches_order(rule, order, cached_items)]

        return applicable

    @classmethod
    def _rule_matches_order(
        cls,
        rule: PromotionRule,
        order: Order,
        cached_items: list[OrderItem],
    ) -> bool:
        """
        Check if a rule's conditions match an order.

        Args:
            rule: Promotion rule to check.
            order: Order to check against.
            cached_items: Pre-fetched order items.
        """
        conditions = rule.conditions or {}

        # Minimum order amount
        min_order = conditions.get("min_order_cents")
        if min_order and order.subtotal_cents < min_order:
            return False

        # Maximum order amount
        max_order = conditions.get("max_order_cents")
        if max_order and order.subtotal_cents > max_order:
            return False

        # Minimum items - use cached items
        min_items = conditions.get("min_items")
        if min_items and len(cached_items) < min_items:
            return False

        # Customer type
        customer_types = conditions.get("customer_types")
        if customer_types and order.customer and order.customer.customer_type not in customer_types:
            return False

        # Product type requirements - use cached items
        required_product_types = conditions.get("required_product_types")
        if required_product_types:
            order_types = {item.product_type for item in cached_items}
            if not order_types.intersection(required_product_types):
                return False

        return True

    @classmethod
    def calculate_rule_discount(
        cls,
        rule: PromotionRule,
        order: Order,
        cached_items: list[OrderItem] | None = None,
    ) -> DiscountResult:
        """
        Calculate discount for a promotion rule.

        Args:
            rule: Promotion rule to calculate discount for.
            order: Order to calculate discount against.
            cached_items: Pre-fetched order items to avoid N+1 queries.
        """
        # Cache items if not provided
        if cached_items is None:
            cached_items = list(order.items.select_related("product").all())

        items = cached_items
        if not rule.applies_to_all_products:
            items = cls._filter_valid_items_for_rule(rule, cached_items)

        if not items:
            return DiscountResult()

        base_amount_cents = sum(item.quantity * item.unit_price_cents + item.setup_cents for item in items)

        discount_cents = 0
        breakdown: dict[str, Any] = {}

        if rule.discount_type == "percent":
            discount_percent = rule.discount_percent or Decimal("0")
            discount_cents = int(base_amount_cents * discount_percent / 100)
            breakdown = {"type": "percent", "percent": float(discount_percent)}

        elif rule.discount_type == "fixed":
            discount_cents = rule.discount_amount_cents or 0
            breakdown = {"type": "fixed", "amount": discount_cents}

        elif rule.discount_type in ("tiered_percent", "tiered_fixed"):
            discount_cents = cls._calculate_tiered_discount(rule, cached_items, base_amount_cents)
            breakdown = {"type": "tiered", "tiers": rule.tiers}

        # Apply cap
        if rule.max_discount_cents and discount_cents > rule.max_discount_cents:
            discount_cents = rule.max_discount_cents
            breakdown["capped"] = True

        return DiscountResult(
            discount_cents=discount_cents,
            discount_type=rule.discount_type,
            discount_description=rule.display_name or rule.name,
            applied_to_items=[str(item.id) for item in items],
            breakdown=breakdown,
        )

    @classmethod
    def _filter_valid_items_for_rule(
        cls,
        rule: PromotionRule,
        items: list[OrderItem],
    ) -> list[OrderItem]:
        """
        Filter pre-fetched items by rule restrictions.

        Args:
            rule: Promotion rule with restrictions.
            items: Pre-fetched order items.
        """
        valid_items = []
        restrictions = rule.product_restrictions or {}

        for item in items:
            is_valid = True

            # Use snapshot field on OrderItem
            product_types = restrictions.get("product_types", [])
            if product_types and item.product_type not in product_types:
                is_valid = False

            excluded_types = restrictions.get("excluded_product_types", [])
            if excluded_types and item.product_type in excluded_types:
                is_valid = False

            if is_valid:
                valid_items.append(item)

        return valid_items

    @classmethod
    def _calculate_tiered_discount(
        cls,
        rule: PromotionRule,
        cached_items: list[OrderItem],
        base_amount_cents: int,
    ) -> int:
        """
        Calculate discount based on tiered thresholds.

        Args:
            rule: Promotion rule with tier configuration.
            cached_items: Pre-fetched order items.
            base_amount_cents: Base amount to calculate discount on.
        """
        tiers = rule.tiers or []
        if not tiers:
            return 0

        # Pre-calculate total quantity for quantity-based tiers
        total_quantity = sum(item.quantity for item in cached_items)

        # Find applicable tier based on order amount or quantity
        applicable_tier = None
        for tier in sorted(tiers, key=lambda t: t.get("threshold", 0), reverse=True):
            threshold = tier.get("threshold", 0)
            threshold_type = tier.get("threshold_type", "amount")

            if threshold_type == "amount":
                if base_amount_cents >= threshold:
                    applicable_tier = tier
                    break
            elif threshold_type == "quantity" and total_quantity >= threshold:
                applicable_tier = tier
                break

        if not applicable_tier:
            return 0

        if rule.discount_type == "tiered_percent":
            percent = Decimal(str(applicable_tier.get("percent", 0)))
            return int(base_amount_cents * percent / 100)
        else:
            return applicable_tier.get("amount_cents", 0)


# ===============================================================================
# Gift Card Service
# ===============================================================================


class GiftCardService:
    """Service for gift card operations."""

    @classmethod
    def validate_gift_card(cls, code: str) -> ValidationResult:
        """Validate a gift card code."""
        code = code.upper().strip()
        try:
            gift_card = GiftCard.objects.get(code=code)
        except GiftCard.DoesNotExist:
            return ValidationResult(
                is_valid=False,
                error_message="Invalid gift card code",
                error_code="INVALID_CODE",
            )

        if not gift_card.is_valid:
            if gift_card.status == "depleted":
                return ValidationResult(
                    is_valid=False,
                    error_message="Gift card has no remaining balance",
                    error_code="DEPLETED",
                )
            elif gift_card.status == "expired":
                return ValidationResult(
                    is_valid=False,
                    error_message="Gift card has expired",
                    error_code="EXPIRED",
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message="Gift card is not active",
                    error_code="INACTIVE",
                )

        return ValidationResult(is_valid=True)

    @classmethod
    @transaction.atomic
    def redeem_gift_card(
        cls,
        code: str,
        order: Order,
        amount_cents: int | None = None,
        customer: Customer | None = None,
        user: User | None = None,
    ) -> ApplyResult:
        """
        Redeem a gift card for an order.
        If amount_cents is None, uses order total up to card balance.
        """
        validation = cls.validate_gift_card(code)
        if not validation.is_valid:
            return ApplyResult(success=False, error_message=validation.error_message)

        gift_card = GiftCard.objects.select_for_update().get(code=code.upper().strip())

        # Calculate amount to redeem
        order_remaining = order.total_cents
        if amount_cents is None:
            amount_cents = min(gift_card.current_balance_cents, order_remaining)
        else:
            amount_cents = min(amount_cents, gift_card.current_balance_cents, order_remaining)

        if amount_cents <= 0:
            return ApplyResult(
                success=False,
                error_message="No amount to redeem",
            )

        # Update gift card balance
        gift_card.current_balance_cents -= amount_cents
        if gift_card.current_balance_cents == 0:
            gift_card.status = "depleted"
        else:
            gift_card.status = "partially_used"

        if customer and not gift_card.redeemed_by:
            gift_card.redeemed_by = customer

        gift_card.save()

        # Create transaction record
        GiftCardTransaction.objects.create(
            gift_card=gift_card,
            transaction_type="redemption",
            amount_cents=-amount_cents,
            balance_after_cents=gift_card.current_balance_cents,
            order=order,
            customer=customer,
            description=f"Redeemed on order {order.order_number}",
            created_by=user,
        )

        # Apply to order discount
        order.discount_cents += amount_cents
        order.save(update_fields=["discount_cents"])
        order.calculate_totals()

        return ApplyResult(
            success=True,
            discount_cents=amount_cents,
        )

    @classmethod
    @transaction.atomic
    def activate_gift_card(
        cls,
        gift_card: GiftCard,
        user: User | None = None,
    ) -> bool:
        """Activate a gift card after purchase."""
        if gift_card.status != "pending":
            return False

        gift_card.status = "active"
        gift_card.current_balance_cents = gift_card.initial_value_cents
        gift_card.activated_at = timezone.now()
        gift_card.save()

        GiftCardTransaction.objects.create(
            gift_card=gift_card,
            transaction_type="activation",
            amount_cents=gift_card.initial_value_cents,
            balance_after_cents=gift_card.current_balance_cents,
            description="Gift card activated",
            created_by=user,
        )

        return True


# ===============================================================================
# Referral Service
# ===============================================================================


class ReferralService:
    """Service for referral program operations."""

    @classmethod
    def get_or_create_referral_code(cls, customer: Customer) -> ReferralCode:
        """Get or create a referral code for a customer."""
        try:
            return ReferralCode.objects.get(owner=customer)
        except ReferralCode.DoesNotExist:
            code = ReferralCode.generate_code_for_customer(customer)
            return ReferralCode.objects.create(
                code=code,
                owner=customer,
            )

    @classmethod
    @transaction.atomic
    def create_referral(
        cls,
        referral_code: ReferralCode,
        referred_customer: Customer,
    ) -> Referral | None:
        """Create a referral relationship."""
        # Check if customer was already referred
        if Referral.objects.filter(referred_customer=referred_customer).exists():
            return None

        # Can't refer yourself
        if referral_code.owner == referred_customer:
            return None

        referral = Referral.objects.create(
            referral_code=referral_code,
            referred_customer=referred_customer,
            status="pending",
        )

        # Update referral code stats atomically to prevent race conditions
        ReferralCode.objects.filter(pk=referral_code.pk).update(total_referrals=F("total_referrals") + 1)
        referral_code.refresh_from_db()

        return referral

    @classmethod
    @transaction.atomic
    def qualify_referral(
        cls,
        referral: Referral,
        order: Order,
    ) -> bool:
        """Mark a referral as qualified after first order."""
        if referral.status != "pending":
            return False

        referral.status = "qualified"
        referral.qualifying_order = order
        referral.qualified_at = timezone.now()
        referral.save()

        return True

    @classmethod
    @transaction.atomic
    def process_referral_rewards(
        cls,
        referral: Referral,
        user: User | None = None,
    ) -> bool:
        """Process rewards for a qualified referral."""
        if referral.status != "qualified":
            return False

        referral_code = referral.referral_code

        # Give referrer reward
        if referral_code.referrer_credit_cents:
            # Add credit to referrer account
            # This would integrate with the billing CreditLedger
            referral.referrer_reward_cents = referral_code.referrer_credit_cents
            referral.referrer_reward_given_at = timezone.now()

        # Mark as rewarded
        referral.status = "rewarded"
        referral.rewarded_at = timezone.now()
        referral.save()

        # Update referral code stats atomically to prevent race conditions
        total_reward = referral.referrer_reward_cents + referral.referee_reward_cents
        ReferralCode.objects.filter(pk=referral_code.pk).update(
            successful_referrals=F("successful_referrals") + 1,
            total_rewards_cents=F("total_rewards_cents") + total_reward,
        )
        referral_code.refresh_from_db()

        return True


# ===============================================================================
# Loyalty Service
# ===============================================================================


class LoyaltyService:
    """Service for loyalty program operations."""

    @classmethod
    def get_or_create_membership(
        cls,
        customer: Customer,
        program: LoyaltyProgram | None = None,
    ) -> CustomerLoyalty:
        """Get or create loyalty membership for a customer."""
        from .models import LoyaltyProgram  # noqa: PLC0415

        if program is None:
            program = LoyaltyProgram.objects.filter(is_active=True).first()

        if program is None:
            raise ValueError("No active loyalty program found")

        membership, created = CustomerLoyalty.objects.get_or_create(
            customer=customer,
            program=program,
            defaults={"is_active": True},
        )

        if created:
            cls._assign_initial_tier(membership)

        return membership

    @classmethod
    def _assign_initial_tier(cls, membership: CustomerLoyalty) -> None:
        """Assign initial tier to new member."""

        initial_tier = (
            LoyaltyTier.objects.filter(
                program=membership.program,
                min_points_lifetime=0,
            )
            .order_by("sort_order")
            .first()
        )

        if initial_tier:
            membership.current_tier = initial_tier
            membership.save(update_fields=["current_tier"])

    @classmethod
    @transaction.atomic
    def earn_points(
        cls,
        membership: CustomerLoyalty,
        order: Order,
        user: User | None = None,
    ) -> int:
        """Award points for an order."""
        program = membership.program

        # Calculate points
        amount_cents = order.total_cents
        points_per_unit = program.points_per_currency_unit

        # Convert cents to currency units and calculate points
        points = int(Decimal(amount_cents) / 100 * points_per_unit)

        # Apply tier multiplier
        if membership.current_tier and membership.current_tier.points_multiplier:
            points = int(points * membership.current_tier.points_multiplier)

        if points <= 0:
            return 0

        # Update membership atomically to prevent race conditions
        CustomerLoyalty.objects.filter(pk=membership.pk).update(
            points_balance=F("points_balance") + points,
            points_lifetime=F("points_lifetime") + points,
            total_spend_cents=F("total_spend_cents") + order.total_cents,
            total_orders=F("total_orders") + 1,
        )
        membership.refresh_from_db()

        # Create transaction
        LoyaltyTransaction.objects.create(
            customer_loyalty=membership,
            transaction_type="earn",
            points=points,
            balance_after=membership.points_balance,
            order=order,
            description=f"Points earned from order {order.order_number}",
            created_by=user,
        )

        # Check for tier upgrade
        cls._check_tier_upgrade(membership)

        return points

    @classmethod
    @transaction.atomic
    def redeem_points(
        cls,
        membership: CustomerLoyalty,
        points: int,
        order: Order | None = None,
        user: User | None = None,
    ) -> DiscountResult:
        """Redeem points for a discount."""
        program = membership.program

        # Validate points
        points = min(points, membership.points_balance)

        if points < program.min_points_to_redeem:
            return DiscountResult()

        # Calculate discount
        discount_cents = int(points / program.points_per_discount_unit * 100)

        # Apply maximum discount
        if order and program.max_discount_percent:
            max_discount = int(order.subtotal_cents * program.max_discount_percent / 100)
            if discount_cents > max_discount:
                discount_cents = max_discount
                # Recalculate points needed
                points = int(discount_cents / 100 * program.points_per_discount_unit)

        # Update membership atomically to prevent race conditions
        CustomerLoyalty.objects.filter(pk=membership.pk).update(
            points_balance=F("points_balance") - points,
            points_redeemed=F("points_redeemed") + points,
        )
        membership.refresh_from_db()

        # Create transaction
        LoyaltyTransaction.objects.create(
            customer_loyalty=membership,
            transaction_type="redeem",
            points=-points,
            balance_after=membership.points_balance,
            order=order,
            description=f"Points redeemed for {discount_cents / 100:.2f} discount",
            created_by=user,
        )

        return DiscountResult(
            discount_cents=discount_cents,
            discount_type="loyalty_points",
            discount_description=f"{points} points redeemed",
            breakdown={"points_used": points},
        )

    @classmethod
    def _check_tier_upgrade(cls, membership: CustomerLoyalty) -> None:
        """Check and apply tier upgrade if eligible."""

        current_tier_order = membership.current_tier.sort_order if membership.current_tier else -1

        eligible_tier = (
            LoyaltyTier.objects.filter(
                program=membership.program,
                min_points_lifetime__lte=membership.points_lifetime,
                sort_order__gt=current_tier_order,
            )
            .order_by("-sort_order")
            .first()
        )

        if eligible_tier:
            membership.current_tier = eligible_tier
            membership.save(update_fields=["current_tier"])

            logger.info(
                f"Customer {membership.customer} upgraded to {eligible_tier.name}",
                extra={
                    "customer_id": str(membership.customer.id),
                    "new_tier": eligible_tier.name,
                },
            )
