"""
Promotions and Coupons models for PRAHO Platform.
Comprehensive discount management system with Romanian compliance.

Supports:
- Coupon codes (single-use, multi-use, unique per customer)
- Promotional campaigns (time-based, event-based)
- Discount types (percentage, fixed amount, free shipping, BOGO)
- Stacking rules (exclusive, stackable, priority-based)
- Customer segmentation (new customers, loyalty tiers, referrals)
- Usage limits (per customer, per order, total redemptions)
- Product/category restrictions
- Minimum order requirements
- Geographic restrictions
"""

from __future__ import annotations

import logging
import secrets
import string
import uuid
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import F, Sum
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order
    from apps.users.models import User

logger = logging.getLogger(__name__)

# ===============================================================================
# Constants and TypedDicts
# ===============================================================================

COUPON_CODE_LENGTH = 12
COUPON_CODE_CHARS = string.ascii_uppercase + string.digits

# Security limits
MAX_DISCOUNT_PERCENT = Decimal("100.00")
MAX_DISCOUNT_AMOUNT_CENTS = 100_000_000  # 1M in major currency units
MAX_USAGE_LIMIT = 1_000_000
MAX_JSON_SIZE = 10_000


class CouponMetadata(TypedDict, total=False):
    """Metadata structure for coupons."""

    campaign_id: str
    affiliate_id: str
    partner_code: str
    internal_notes: str
    source: str
    utm_campaign: str
    utm_source: str
    utm_medium: str


class RestrictionConfig(TypedDict, total=False):
    """Configuration for coupon restrictions."""

    product_ids: list[str]
    product_types: list[str]
    category_slugs: list[str]
    excluded_product_ids: list[str]
    customer_types: list[str]
    countries: list[str]
    billing_periods: list[str]
    min_order_items: int
    max_order_items: int
    first_order_only: bool
    new_customer_only: bool
    requires_account: bool


class StackingConfig(TypedDict, total=False):
    """Configuration for coupon stacking rules."""

    stackable: bool
    exclusive_group: str
    priority: int
    max_stack_count: int
    incompatible_codes: list[str]


# ===============================================================================
# Promotion Campaign Model
# ===============================================================================


class PromotionCampaign(models.Model):
    """
    Marketing campaign that groups related promotions and coupons.
    Provides high-level organization and analytics tracking.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Campaign identification
    name = models.CharField(max_length=200, help_text=_("Internal campaign name"))
    slug = models.SlugField(max_length=100, unique=True, help_text=_("URL-friendly identifier"))
    description = models.TextField(blank=True, help_text=_("Campaign description and goals"))

    # Campaign type
    CAMPAIGN_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("seasonal", _("Seasonal Sale")),
        ("holiday", _("Holiday Promotion")),
        ("flash_sale", _("Flash Sale")),
        ("loyalty", _("Loyalty Reward")),
        ("referral", _("Referral Program")),
        ("new_customer", _("New Customer")),
        ("win_back", _("Win-Back Campaign")),
        ("partner", _("Partner/Affiliate")),
        ("influencer", _("Influencer")),
        ("email", _("Email Campaign")),
        ("social", _("Social Media")),
        ("other", _("Other")),
    )
    campaign_type = models.CharField(max_length=20, choices=CAMPAIGN_TYPES, default="other")

    # Timing
    start_date = models.DateTimeField(help_text=_("When campaign becomes active"))
    end_date = models.DateTimeField(null=True, blank=True, help_text=_("When campaign ends (null = no end)"))

    # Budget limits
    budget_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Maximum total discount budget in cents"),
    )
    spent_cents = models.BigIntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("Total discounts given so far"),
    )

    # Status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("draft", "Draft"),
        ("scheduled", "Scheduled"),
        ("active", "Active"),
        ("paused", "Paused"),
        ("completed", "Completed"),
        ("cancelled", "Cancelled"),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    is_active = models.BooleanField(default=True, help_text=_("Master switch for campaign"))

    # Tracking
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_promotion_campaigns",
    )

    class Meta:
        db_table = "promotion_campaigns"
        verbose_name = _("Promotion Campaign")
        verbose_name_plural = _("Promotion Campaigns")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["slug"]),
            models.Index(fields=["status", "is_active"]),
            models.Index(fields=["start_date", "end_date"]),
            models.Index(fields=["campaign_type", "status"]),
        )

    def __str__(self) -> str:
        return self.name

    @property
    def is_within_dates(self) -> bool:
        """Check if campaign is within valid date range."""
        now = timezone.now()
        if self.start_date > now:
            return False
        if self.end_date and self.end_date < now:
            return False
        return True

    @property
    def is_within_budget(self) -> bool:
        """Check if campaign is within budget."""
        if self.budget_cents is None:
            return True
        return self.spent_cents < self.budget_cents

    @property
    def remaining_budget_cents(self) -> int | None:
        """Get remaining budget in cents."""
        if self.budget_cents is None:
            return None
        return max(0, self.budget_cents - self.spent_cents)

    def can_apply(self) -> bool:
        """Check if campaign can currently be applied."""
        return self.is_active and self.status == "active" and self.is_within_dates and self.is_within_budget


# ===============================================================================
# Coupon Model
# ===============================================================================


class Coupon(models.Model):
    """
    Coupon code that provides discounts.
    Supports various discount types, restrictions, and usage limits.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Coupon identification
    code = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_("Unique coupon code (case-insensitive)"),
    )
    name = models.CharField(max_length=200, help_text=_("Internal name for this coupon"))
    description = models.TextField(blank=True, help_text=_("Description shown to customers"))
    internal_notes = models.TextField(blank=True, help_text=_("Internal notes for staff"))

    # Campaign relationship
    campaign = models.ForeignKey(
        PromotionCampaign,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="coupons",
        help_text=_("Associated marketing campaign"),
    )

    # Discount type and value
    DISCOUNT_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("percent", _("Percentage Discount")),
        ("fixed", _("Fixed Amount Discount")),
        ("free_shipping", _("Free Shipping")),
        ("free_setup", _("Free Setup Fee")),
        ("bogo", _("Buy One Get One")),
        ("tiered", _("Tiered Discount")),
        ("free_months", _("Free Months")),
    )
    discount_type = models.CharField(max_length=20, choices=DISCOUNT_TYPES, default="percent")

    # Discount values (interpretation depends on discount_type)
    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Percentage discount (0-100)"),
    )
    discount_amount_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Fixed discount amount in cents"),
    )
    free_months = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(36)],
        help_text=_("Number of free months for subscription discounts"),
    )

    # Cap on discount
    max_discount_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Maximum discount amount in cents (caps percentage discounts)"),
    )

    # Minimum requirements
    min_order_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Minimum order amount in cents to qualify"),
    )
    min_order_items = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_("Minimum number of items in order"),
    )

    # Validity period
    valid_from = models.DateTimeField(default=timezone.now, help_text=_("When coupon becomes valid"))
    valid_until = models.DateTimeField(null=True, blank=True, help_text=_("When coupon expires (null = never)"))

    # Usage limits
    USAGE_LIMIT_TYPES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("unlimited", "Unlimited"),
        ("single_use", "Single Use (One Time)"),
        ("limited", "Limited Total Uses"),
        ("per_customer", "Limited Per Customer"),
    )
    usage_limit_type = models.CharField(max_length=20, choices=USAGE_LIMIT_TYPES, default="unlimited")
    max_total_uses = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MaxValueValidator(MAX_USAGE_LIMIT)],
        help_text=_("Maximum total redemptions"),
    )
    max_uses_per_customer = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MaxValueValidator(1000)],
        help_text=_("Maximum uses per customer"),
    )

    # Current usage tracking
    total_uses = models.PositiveIntegerField(default=0, help_text=_("Current total redemption count"))
    total_discount_cents = models.BigIntegerField(default=0, help_text=_("Total discount amount given"))

    # Customer targeting
    CUSTOMER_TARGET_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("all", "All Customers"),
        ("new", "New Customers Only"),
        ("existing", "Existing Customers Only"),
        ("specific", "Specific Customers"),
        ("segment", "Customer Segment"),
    )
    customer_target = models.CharField(max_length=20, choices=CUSTOMER_TARGET_CHOICES, default="all")
    first_order_only = models.BooleanField(default=False, help_text=_("Only valid for customer's first order"))

    # Specific customer assignment (for personal coupons)
    assigned_customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="assigned_coupons",
        help_text=_("Customer this coupon is assigned to (for personal codes)"),
    )

    # Product restrictions
    applies_to_all_products = models.BooleanField(default=True, help_text=_("Applies to all products"))
    product_restrictions = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Product/category restrictions as JSON"),
    )

    # Stacking rules
    # NOTE: is_stackable and is_exclusive are actively used in validation.
    # stacking_priority and stacking_config are reserved for future advanced
    # stacking scenarios (e.g., complex priority-based discount ordering,
    # category-specific stacking rules). Currently not implemented in services.
    is_stackable = models.BooleanField(default=False, help_text=_("Can be combined with other coupons"))
    is_exclusive = models.BooleanField(default=False, help_text=_("Cannot be combined with any other discounts"))
    stacking_priority = models.PositiveIntegerField(
        default=100,
        help_text=_("Priority when stacking (lower = applied first). Reserved for future use."),
    )
    stacking_config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Advanced stacking rules. Reserved for future use."),
    )

    # Status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("expired", "Expired"),
        ("depleted", "Depleted (Usage Limit Reached)"),
        ("cancelled", "Cancelled"),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    is_active = models.BooleanField(default=True, help_text=_("Master switch for coupon"))
    is_public = models.BooleanField(default=False, help_text=_("Show on public promotions page"))

    # Currency (for fixed discounts)
    currency = models.ForeignKey(
        "billing.Currency",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        help_text=_("Currency for fixed amount discounts"),
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True, help_text=_("Tags for filtering and reporting"))

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_coupons",
    )

    class Meta:
        db_table = "promotion_coupons"
        verbose_name = _("Coupon")
        verbose_name_plural = _("Coupons")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["code"]),
            models.Index(fields=["status", "is_active"]),
            models.Index(fields=["valid_from", "valid_until"]),
            models.Index(fields=["discount_type"]),
            models.Index(fields=["campaign"]),
            models.Index(fields=["customer_target"]),
            models.Index(fields=["assigned_customer"]),
            models.Index(fields=["created_at"]),
            # Performance indexes
            models.Index(fields=["is_active", "status", "valid_from", "valid_until"], name="idx_coupon_validity"),
            models.Index(fields=["is_public", "is_active", "status"], name="idx_coupon_public"),
        )

    def __str__(self) -> str:
        return f"{self.code} - {self.name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Normalize code to uppercase before saving."""
        if self.code:
            self.code = self.code.upper().strip()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate coupon configuration."""
        super().clean()
        self._validate_discount_values()
        self._validate_usage_limits()
        self._validate_dates()

    def _validate_discount_values(self) -> None:
        """Validate discount type and value consistency."""
        if self.discount_type == "percent":
            if self.discount_percent is None:
                raise ValidationError("Percentage discount requires discount_percent value")
            if self.discount_percent < 0 or self.discount_percent > 100:
                raise ValidationError("Percentage must be between 0 and 100")
        elif self.discount_type == "fixed":
            if self.discount_amount_cents is None:
                raise ValidationError("Fixed discount requires discount_amount_cents value")
            if self.discount_amount_cents < 0:
                raise ValidationError("Fixed discount amount cannot be negative")
        elif self.discount_type == "free_months":
            if self.free_months is None:
                raise ValidationError("Free months discount requires free_months value")

    def _validate_usage_limits(self) -> None:
        """Validate usage limit configuration."""
        if self.usage_limit_type == "limited" and self.max_total_uses is None:
            raise ValidationError("Limited usage requires max_total_uses value")
        if self.usage_limit_type == "per_customer" and self.max_uses_per_customer is None:
            raise ValidationError("Per-customer limit requires max_uses_per_customer value")

    def _validate_dates(self) -> None:
        """Validate date range."""
        if self.valid_until and self.valid_from and self.valid_until < self.valid_from:
            raise ValidationError("valid_until must be after valid_from")

    @property
    def is_expired(self) -> bool:
        """Check if coupon has expired."""
        if self.valid_until is None:
            return False
        return timezone.now() > self.valid_until

    @property
    def is_not_yet_valid(self) -> bool:
        """Check if coupon is not yet valid."""
        return timezone.now() < self.valid_from

    @property
    def is_depleted(self) -> bool:
        """Check if coupon has reached usage limit."""
        if self.usage_limit_type == "unlimited":
            return False
        if self.usage_limit_type == "single_use":
            return self.total_uses >= 1
        if self.usage_limit_type == "limited" and self.max_total_uses:
            return self.total_uses >= self.max_total_uses
        return False

    @property
    def remaining_uses(self) -> int | None:
        """Get remaining uses, or None if unlimited."""
        if self.usage_limit_type == "unlimited":
            return None
        if self.usage_limit_type == "single_use":
            return max(0, 1 - self.total_uses)
        if self.usage_limit_type == "limited" and self.max_total_uses:
            return max(0, self.max_total_uses - self.total_uses)
        return None

    def can_be_used(self) -> tuple[bool, str]:
        """
        Check if coupon can be used (basic validity check).
        Returns (is_valid, reason_if_invalid).
        """
        if not self.is_active:
            return False, "Coupon is inactive"
        if self.status != "active":
            return False, f"Coupon status is {self.status}"
        if self.is_expired:
            return False, "Coupon has expired"
        if self.is_not_yet_valid:
            return False, "Coupon is not yet valid"
        if self.is_depleted:
            return False, "Coupon usage limit reached"
        if self.campaign and not self.campaign.can_apply():
            return False, "Campaign is not active"
        return True, ""

    def get_customer_uses(self, customer: Customer) -> int:
        """Get number of times customer has used this coupon."""
        return self.redemptions.filter(customer=customer, status="applied").count()

    def can_customer_use(self, customer: Customer | None) -> tuple[bool, str]:
        """
        Check if specific customer can use this coupon.
        Returns (is_valid, reason_if_invalid).
        """
        # Basic validity check
        can_use, reason = self.can_be_used()
        if not can_use:
            return False, reason

        if customer is None:
            if self.first_order_only or self.customer_target != "all":
                return False, "Customer account required for this coupon"
            return True, ""

        # Personal coupon check
        if self.assigned_customer and self.assigned_customer != customer:
            return False, "This coupon is assigned to a different customer"

        # Customer target check
        if self.customer_target == "new":
            if customer.orders.exclude(status="draft").exists():  # type: ignore[attr-defined]
                return False, "Coupon only valid for new customers"
        elif self.customer_target == "existing":
            if not customer.orders.exclude(status="draft").exists():  # type: ignore[attr-defined]
                return False, "Coupon only valid for existing customers"
        elif self.customer_target == "specific":
            if not self.assigned_customer:
                return False, "Coupon configuration error"

        # First order only check
        if self.first_order_only:
            if customer.orders.exclude(status="draft").exists():  # type: ignore[attr-defined]
                return False, "Coupon only valid for first order"

        # Per-customer usage limit
        if self.max_uses_per_customer:
            customer_uses = self.get_customer_uses(customer)
            if customer_uses >= self.max_uses_per_customer:
                return False, "You have reached the usage limit for this coupon"

        return True, ""

    # Maximum attempts for code generation to prevent infinite loops
    MAX_CODE_GENERATION_ATTEMPTS = 100

    @classmethod
    def generate_code(
        cls,
        length: int = COUPON_CODE_LENGTH,
        prefix: str = "",
        max_attempts: int | None = None,
    ) -> str:
        """
        Generate a unique coupon code.

        Args:
            length: Length of the random part of the code.
            prefix: Optional prefix for the code.
            max_attempts: Maximum attempts before raising an error.
                         Defaults to MAX_CODE_GENERATION_ATTEMPTS.

        Raises:
            ValueError: If a unique code cannot be generated within max_attempts.
        """
        if max_attempts is None:
            max_attempts = cls.MAX_CODE_GENERATION_ATTEMPTS

        for attempt in range(max_attempts):
            random_part = "".join(secrets.choice(COUPON_CODE_CHARS) for _ in range(length))
            code = f"{prefix}{random_part}" if prefix else random_part
            if not cls.objects.filter(code=code).exists():
                return code

        raise ValueError(
            f"Could not generate unique coupon code after {max_attempts} attempts. "
            f"Consider using a longer code length or different prefix."
        )

    @classmethod
    def generate_batch(
        cls,
        count: int,
        prefix: str = "",
        length: int = COUPON_CODE_LENGTH,
        validate: bool = True,
        **coupon_defaults: Any,
    ) -> list[Coupon]:
        """
        Generate a batch of unique coupon codes.

        Args:
            count: Number of coupons to generate.
            prefix: Optional prefix for all codes.
            length: Length of the random part of each code.
            validate: If True, validates each coupon before bulk_create.
            **coupon_defaults: Default field values for all coupons.

        Returns:
            List of created Coupon instances.

        Raises:
            ValidationError: If validate=True and any coupon fails validation.
        """
        coupons = []
        for _ in range(count):
            code = cls.generate_code(length=length, prefix=prefix)
            coupon = cls(code=code, **coupon_defaults)

            # Validate each coupon to catch issues before bulk insert
            if validate:
                coupon.full_clean()

            coupons.append(coupon)

        return cls.objects.bulk_create(coupons)


# ===============================================================================
# Coupon Redemption Model
# ===============================================================================


class CouponRedemption(models.Model):
    """
    Tracks each use of a coupon code.
    Provides audit trail and analytics for coupon performance.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationships
    coupon = models.ForeignKey(
        Coupon,
        on_delete=models.PROTECT,
        related_name="redemptions",
        help_text=_("The coupon that was redeemed"),
    )
    order = models.ForeignKey(
        "orders.Order",
        on_delete=models.CASCADE,
        related_name="coupon_redemptions",
        help_text=_("The order this redemption applies to"),
    )
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="coupon_redemptions",
        help_text=_("Customer who redeemed the coupon"),
    )

    # Redemption details
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending Application"),
        ("applied", "Applied"),
        ("failed", "Failed to Apply"),
        ("reversed", "Reversed (Order Cancelled)"),
        ("expired", "Expired Before Application"),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Discount calculation snapshot
    discount_type = models.CharField(max_length=20, help_text=_("Discount type at time of redemption"))
    discount_value = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text=_("Discount value (percent or amount) at time of redemption"),
    )
    discount_cents = models.BigIntegerField(
        default=0,
        help_text=_("Actual discount amount applied in cents"),
    )
    currency_code = models.CharField(max_length=3, default="RON", help_text=_("Currency of discount"))

    # Order context at redemption
    order_subtotal_cents = models.BigIntegerField(help_text=_("Order subtotal before discount"))
    order_total_cents = models.BigIntegerField(help_text=_("Order total after discount"))

    # Applied to specific items (for item-level discounts)
    applied_to_items = models.JSONField(
        default=list,
        blank=True,
        help_text=_("List of order item IDs this discount was applied to"),
    )

    # Source tracking
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    referrer = models.URLField(blank=True)

    # Failure information
    failure_reason = models.TextField(blank=True, help_text=_("Reason if redemption failed"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    applied_at = models.DateTimeField(null=True, blank=True, help_text=_("When discount was applied"))
    reversed_at = models.DateTimeField(null=True, blank=True, help_text=_("When redemption was reversed"))

    class Meta:
        db_table = "promotion_coupon_redemptions"
        verbose_name = _("Coupon Redemption")
        verbose_name_plural = _("Coupon Redemptions")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["coupon", "-created_at"]),
            models.Index(fields=["order"]),
            models.Index(fields=["customer", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["applied_at"]),
            # Analytics indexes
            models.Index(fields=["coupon", "status", "-applied_at"], name="idx_redemption_analytics"),
            models.Index(fields=["customer", "status"], name="idx_redemption_customer"),
        )
        constraints: ClassVar[tuple[models.UniqueConstraint, ...]] = (
            # Prevent same coupon being applied to same order twice
            models.UniqueConstraint(
                fields=["coupon", "order"],
                name="unique_coupon_per_order",
            ),
        )

    def __str__(self) -> str:
        return f"{self.coupon.code} on {self.order.order_number}"

    def mark_applied(self, discount_cents: int) -> None:
        """Mark redemption as successfully applied."""
        self.status = "applied"
        self.discount_cents = discount_cents
        self.applied_at = timezone.now()
        self.save(update_fields=["status", "discount_cents", "applied_at"])

        # Update coupon usage statistics
        Coupon.objects.filter(pk=self.coupon_id).update(
            total_uses=F("total_uses") + 1,
            total_discount_cents=F("total_discount_cents") + discount_cents,
        )

        # Update campaign spending if applicable
        if self.coupon.campaign:
            PromotionCampaign.objects.filter(pk=self.coupon.campaign_id).update(
                spent_cents=F("spent_cents") + discount_cents
            )

    def mark_failed(self, reason: str) -> None:
        """Mark redemption as failed."""
        self.status = "failed"
        self.failure_reason = reason
        self.save(update_fields=["status", "failure_reason"])

    def mark_reversed(self) -> None:
        """Mark redemption as reversed (e.g., order cancelled)."""
        if self.status != "applied":
            return

        self.status = "reversed"
        self.reversed_at = timezone.now()
        self.save(update_fields=["status", "reversed_at"])

        # Decrement coupon usage statistics
        Coupon.objects.filter(pk=self.coupon_id).update(
            total_uses=F("total_uses") - 1,
            total_discount_cents=F("total_discount_cents") - self.discount_cents,
        )

        # Update campaign spending if applicable
        if self.coupon.campaign:
            PromotionCampaign.objects.filter(pk=self.coupon.campaign_id).update(
                spent_cents=F("spent_cents") - self.discount_cents
            )


# ===============================================================================
# Promotion Rule Model (for complex promotions)
# ===============================================================================


class PromotionRule(models.Model):
    """
    Defines automatic promotions that apply without a code.
    Supports complex rule-based discounts and tiered pricing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Rule identification
    name = models.CharField(max_length=200, help_text=_("Internal rule name"))
    description = models.TextField(blank=True, help_text=_("Rule description"))

    # Campaign relationship
    campaign = models.ForeignKey(
        PromotionCampaign,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rules",
    )

    # Rule type
    RULE_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("automatic", _("Automatic (always applies)")),
        ("threshold", _("Order Threshold")),
        ("quantity", _("Quantity Based")),
        ("bundle", _("Bundle Discount")),
        ("tiered", _("Tiered Pricing")),
        ("time_based", _("Time-Based")),
        ("customer_segment", _("Customer Segment")),
        ("product_combination", _("Product Combination")),
    )
    rule_type = models.CharField(max_length=30, choices=RULE_TYPES, default="automatic")

    # Discount configuration (same as Coupon)
    DISCOUNT_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("percent", _("Percentage Discount")),
        ("fixed", _("Fixed Amount Discount")),
        ("free_shipping", _("Free Shipping")),
        ("free_setup", _("Free Setup Fee")),
        ("tiered_percent", _("Tiered Percentage")),
        ("tiered_fixed", _("Tiered Fixed Amount")),
    )
    discount_type = models.CharField(max_length=20, choices=DISCOUNT_TYPES, default="percent")

    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    discount_amount_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
    )
    max_discount_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
    )

    # Conditions
    conditions = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Rule conditions as JSON"),
    )

    # Tiered discount configuration
    tiers = models.JSONField(
        default=list,
        blank=True,
        help_text=_("Tier thresholds and discounts as JSON array"),
    )

    # Product restrictions
    applies_to_all_products = models.BooleanField(default=True)
    product_restrictions = models.JSONField(default=dict, blank=True)

    # Validity
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)

    # Stacking
    is_stackable = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)

    # Status
    is_active = models.BooleanField(default=True)

    # Display
    display_name = models.CharField(max_length=200, blank=True, help_text=_("Name shown to customers"))
    display_badge = models.CharField(max_length=50, blank=True, help_text=_("Badge text (e.g., 'SALE', '-20%')"))

    # Currency
    currency = models.ForeignKey(
        "billing.Currency",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_promotion_rules",
    )

    class Meta:
        db_table = "promotion_rules"
        verbose_name = _("Promotion Rule")
        verbose_name_plural = _("Promotion Rules")
        ordering: ClassVar[tuple[str, ...]] = ("priority", "-created_at")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["rule_type", "is_active"]),
            models.Index(fields=["valid_from", "valid_until"]),
            models.Index(fields=["priority"]),
            models.Index(fields=["campaign"]),
        )

    def __str__(self) -> str:
        return self.name

    @property
    def is_valid(self) -> bool:
        """Check if rule is currently valid."""
        if not self.is_active:
            return False
        now = timezone.now()
        if self.valid_from > now:
            return False
        if self.valid_until and self.valid_until < now:
            return False
        if self.campaign and not self.campaign.can_apply():
            return False
        return True


# ===============================================================================
# Referral Code Model
# ===============================================================================


class ReferralCode(models.Model):
    """
    Customer referral codes for refer-a-friend programs.
    Tracks referrals and rewards for both referrer and referee.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Code
    code = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_("Unique referral code"),
    )

    # Owner
    owner = models.OneToOneField(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="referral_code",
        help_text=_("Customer who owns this referral code"),
    )

    # Rewards configuration
    referrer_discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("10.00"),
        help_text=_("Discount for referrer on next order"),
    )
    referrer_credit_cents = models.BigIntegerField(
        null=True,
        blank=True,
        help_text=_("Account credit for referrer in cents"),
    )
    referee_discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("10.00"),
        help_text=_("Discount for new customer on first order"),
    )
    referee_credit_cents = models.BigIntegerField(
        null=True,
        blank=True,
        help_text=_("Account credit for new customer in cents"),
    )

    # Associated coupon (auto-generated)
    referee_coupon = models.OneToOneField(
        Coupon,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="referral_code",
        help_text=_("Coupon used by referees"),
    )

    # Statistics
    total_referrals = models.PositiveIntegerField(default=0)
    successful_referrals = models.PositiveIntegerField(default=0)
    total_rewards_cents = models.BigIntegerField(default=0)

    # Status
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "promotion_referral_codes"
        verbose_name = _("Referral Code")
        verbose_name_plural = _("Referral Codes")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["code"]),
            models.Index(fields=["owner"]),
            models.Index(fields=["is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.code} ({self.owner})"

    @classmethod
    def generate_code_for_customer(cls, customer: Customer, max_attempts: int = 100) -> str:
        """Generate a unique referral code for a customer.

        Args:
            customer: The customer to generate a code for.
            max_attempts: Maximum number of attempts to generate a unique code.

        Returns:
            A unique referral code.

        Raises:
            RuntimeError: If unable to generate a unique code within max_attempts.
        """
        # Use customer name initials + random string
        name_part = "".join(
            word[0].upper() for word in str(customer.name).split()[:2] if word
        )[:3]
        if not name_part:
            name_part = "REF"

        for attempt in range(max_attempts):
            random_part = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            code = f"{name_part}{random_part}"
            if not cls.objects.filter(code=code).exists():
                return code

        raise RuntimeError(
            f"Unable to generate unique referral code after {max_attempts} attempts. "
            "This may indicate code space exhaustion."
        )


class Referral(models.Model):
    """
    Tracks individual referral relationships.
    Links referrer to referred customer with reward tracking.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationships
    referral_code = models.ForeignKey(
        ReferralCode,
        on_delete=models.PROTECT,
        related_name="referrals",
    )
    referred_customer = models.OneToOneField(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="referred_by",
    )

    # Status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending First Order"),
        ("qualified", "Qualified (Order Placed)"),
        ("rewarded", "Rewarded"),
        ("expired", "Expired"),
        ("cancelled", "Cancelled"),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Qualifying order
    qualifying_order = models.ForeignKey(
        "orders.Order",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="referral_qualifications",
    )

    # Rewards given
    referrer_reward_cents = models.BigIntegerField(default=0)
    referee_reward_cents = models.BigIntegerField(default=0)
    referrer_reward_given_at = models.DateTimeField(null=True, blank=True)
    referee_reward_given_at = models.DateTimeField(null=True, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    qualified_at = models.DateTimeField(null=True, blank=True)
    rewarded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "promotion_referrals"
        verbose_name = _("Referral")
        verbose_name_plural = _("Referrals")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["referral_code", "status"]),
            models.Index(fields=["referred_customer"]),
            models.Index(fields=["status", "-created_at"]),
        )

    def __str__(self) -> str:
        return f"Referral: {self.referred_customer} via {self.referral_code.code}"


# ===============================================================================
# Gift Card Model
# ===============================================================================


class GiftCard(models.Model):
    """
    Gift cards that can be purchased and redeemed for account credit.
    Supports both physical and digital gift cards.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Code
    code = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_("Unique gift card code"),
    )

    # Value
    initial_value_cents = models.BigIntegerField(
        validators=[MinValueValidator(100)],  # Minimum 1.00
        help_text=_("Original value in cents"),
    )
    current_balance_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text=_("Current remaining balance in cents"),
    )
    currency = models.ForeignKey(
        "billing.Currency",
        on_delete=models.PROTECT,
    )

    # Type
    CARD_TYPES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("digital", "Digital"),
        ("physical", "Physical"),
    )
    card_type = models.CharField(max_length=20, choices=CARD_TYPES, default="digital")

    # Purchase information
    purchased_by = models.ForeignKey(
        "customers.Customer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="purchased_gift_cards",
    )
    purchase_order = models.ForeignKey(
        "orders.Order",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gift_cards_purchased",
    )

    # Recipient information
    recipient_email = models.EmailField(blank=True)
    recipient_name = models.CharField(max_length=200, blank=True)
    personal_message = models.TextField(blank=True)
    delivery_date = models.DateTimeField(null=True, blank=True)

    # Redemption
    redeemed_by = models.ForeignKey(
        "customers.Customer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="redeemed_gift_cards",
    )

    # Validity
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)

    # Status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending Payment"),
        ("active", "Active"),
        ("partially_used", "Partially Used"),
        ("depleted", "Depleted"),
        ("expired", "Expired"),
        ("cancelled", "Cancelled"),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    activated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "promotion_gift_cards"
        verbose_name = _("Gift Card")
        verbose_name_plural = _("Gift Cards")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["code"]),
            models.Index(fields=["status", "is_active"]),
            models.Index(fields=["redeemed_by"]),
            models.Index(fields=["purchased_by"]),
            models.Index(fields=["valid_until"]),
        )

    def __str__(self) -> str:
        return f"Gift Card {self.code} ({self.current_balance_cents / 100:.2f} {self.currency.code})"

    @property
    def is_valid(self) -> bool:
        """Check if gift card can be used."""
        if not self.is_active or self.status not in ("active", "partially_used"):
            return False
        if self.current_balance_cents <= 0:
            return False
        if self.valid_until and timezone.now() > self.valid_until:
            return False
        return True

    @classmethod
    def generate_code(cls, max_attempts: int = 100) -> str:
        """Generate a unique gift card code.

        Args:
            max_attempts: Maximum number of attempts to generate a unique code.

        Returns:
            A unique gift card code in format XXXX-XXXX-XXXX-XXXX.

        Raises:
            RuntimeError: If unable to generate a unique code within max_attempts.
        """
        for attempt in range(max_attempts):
            # Format: XXXX-XXXX-XXXX-XXXX
            parts = [
                "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
                for _ in range(4)
            ]
            code = "-".join(parts)
            if not cls.objects.filter(code=code).exists():
                return code

        raise RuntimeError(
            f"Unable to generate unique gift card code after {max_attempts} attempts. "
            "This may indicate code space exhaustion."
        )


class GiftCardTransaction(models.Model):
    """
    Tracks all transactions on a gift card (purchases, redemptions, refunds).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Gift card
    gift_card = models.ForeignKey(
        GiftCard,
        on_delete=models.PROTECT,
        related_name="transactions",
    )

    # Transaction type
    TRANSACTION_TYPES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("activation", "Activation"),
        ("redemption", "Redemption"),
        ("refund", "Refund"),
        ("adjustment", "Manual Adjustment"),
        ("expiration", "Expiration"),
    )
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)

    # Amount (positive = credit, negative = debit)
    amount_cents = models.BigIntegerField(help_text=_("Transaction amount in cents"))
    balance_after_cents = models.BigIntegerField(help_text=_("Balance after transaction"))

    # Related objects
    order = models.ForeignKey(
        "orders.Order",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gift_card_transactions",
    )
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    # Description
    description = models.TextField(blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "promotion_gift_card_transactions"
        verbose_name = _("Gift Card Transaction")
        verbose_name_plural = _("Gift Card Transactions")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["gift_card", "-created_at"]),
            models.Index(fields=["transaction_type", "-created_at"]),
            models.Index(fields=["order"]),
        )

    def __str__(self) -> str:
        return f"{self.transaction_type}: {self.amount_cents / 100:.2f} on {self.gift_card.code}"


# ===============================================================================
# Loyalty Points Model
# ===============================================================================


class LoyaltyProgram(models.Model):
    """
    Configuration for customer loyalty program.
    Supports point-based rewards and tier levels.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Program identity
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Point earning rates
    points_per_currency_unit = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal("1.00"),
        help_text=_("Points earned per currency unit spent"),
    )
    bonus_multiplier_new_customer = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("1.00"),
        help_text=_("Point multiplier for new customers"),
    )

    # Point redemption
    points_per_discount_unit = models.PositiveIntegerField(
        default=100,
        help_text=_("Points needed for 1 currency unit discount"),
    )
    min_points_to_redeem = models.PositiveIntegerField(
        default=100,
        help_text=_("Minimum points needed to redeem"),
    )
    max_discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("50.00"),
        help_text=_("Maximum discount percentage from points"),
    )

    # Point expiration
    points_expire_months = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_("Months until points expire (null = never)"),
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Currency
    currency = models.ForeignKey(
        "billing.Currency",
        on_delete=models.PROTECT,
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "promotion_loyalty_programs"
        verbose_name = _("Loyalty Program")
        verbose_name_plural = _("Loyalty Programs")

    def __str__(self) -> str:
        return self.name


class LoyaltyTier(models.Model):
    """
    Loyalty program tier levels with benefits.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Program
    program = models.ForeignKey(
        LoyaltyProgram,
        on_delete=models.CASCADE,
        related_name="tiers",
    )

    # Tier identity
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=50)
    description = models.TextField(blank=True)

    # Qualification
    min_points_lifetime = models.PositiveIntegerField(
        default=0,
        help_text=_("Minimum lifetime points to reach this tier"),
    )
    min_spend_cents = models.BigIntegerField(
        default=0,
        help_text=_("Minimum lifetime spend in cents"),
    )

    # Benefits
    points_multiplier = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("1.00"),
        help_text=_("Point earning multiplier"),
    )
    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text=_("Automatic discount for tier members"),
    )
    free_shipping = models.BooleanField(default=False)
    priority_support = models.BooleanField(default=False)

    # Benefits configuration
    benefits = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional tier benefits as JSON"),
    )

    # Display
    badge_color = models.CharField(max_length=20, default="gray")
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "promotion_loyalty_tiers"
        verbose_name = _("Loyalty Tier")
        verbose_name_plural = _("Loyalty Tiers")
        ordering: ClassVar[tuple[str, ...]] = ("sort_order",)
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("program", "slug"),)

    def __str__(self) -> str:
        return f"{self.program.name} - {self.name}"


class CustomerLoyalty(models.Model):
    """
    Customer's loyalty status and points balance.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Customer and program
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="loyalty_memberships",
    )
    program = models.ForeignKey(
        LoyaltyProgram,
        on_delete=models.CASCADE,
        related_name="memberships",
    )

    # Current status
    current_tier = models.ForeignKey(
        LoyaltyTier,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="members",
    )

    # Points
    points_balance = models.PositiveIntegerField(default=0)
    points_lifetime = models.PositiveIntegerField(default=0)
    points_redeemed = models.PositiveIntegerField(default=0)
    points_expired = models.PositiveIntegerField(default=0)

    # Spend tracking
    total_spend_cents = models.BigIntegerField(default=0)
    total_orders = models.PositiveIntegerField(default=0)

    # Status
    is_active = models.BooleanField(default=True)
    enrolled_at = models.DateTimeField(auto_now_add=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "promotion_customer_loyalty"
        verbose_name = _("Customer Loyalty")
        verbose_name_plural = _("Customer Loyalties")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("customer", "program"),)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "program"]),
            models.Index(fields=["current_tier"]),
            models.Index(fields=["points_balance"]),
        )

    def __str__(self) -> str:
        return f"{self.customer} - {self.program.name}"


class LoyaltyTransaction(models.Model):
    """
    Tracks all loyalty point transactions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Customer loyalty
    customer_loyalty = models.ForeignKey(
        CustomerLoyalty,
        on_delete=models.CASCADE,
        related_name="transactions",
    )

    # Transaction type
    TRANSACTION_TYPES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("earn", "Points Earned"),
        ("redeem", "Points Redeemed"),
        ("expire", "Points Expired"),
        ("adjust", "Manual Adjustment"),
        ("bonus", "Bonus Points"),
        ("refund", "Points Refunded"),
        ("tier_bonus", "Tier Bonus"),
    )
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)

    # Points (positive = credit, negative = debit)
    points = models.IntegerField(help_text=_("Points change (positive or negative)"))
    balance_after = models.PositiveIntegerField(help_text=_("Balance after transaction"))

    # Related objects
    order = models.ForeignKey(
        "orders.Order",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="loyalty_transactions",
    )
    coupon_redemption = models.ForeignKey(
        CouponRedemption,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    # Description
    description = models.TextField(blank=True)

    # Expiration tracking (for earned points)
    expires_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "promotion_loyalty_transactions"
        verbose_name = _("Loyalty Transaction")
        verbose_name_plural = _("Loyalty Transactions")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer_loyalty", "-created_at"]),
            models.Index(fields=["transaction_type", "-created_at"]),
            models.Index(fields=["order"]),
            models.Index(fields=["expires_at"]),
        )

    def __str__(self) -> str:
        return f"{self.transaction_type}: {self.points:+d} points"
