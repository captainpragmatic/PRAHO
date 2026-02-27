"""
Django Admin configuration for the Promotions app.
"""

from typing import Any

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    GiftCardTransaction,
    LoyaltyProgram,
    LoyaltyTier,
    LoyaltyTransaction,
    PromotionCampaign,
    PromotionRule,
    Referral,
    ReferralCode,
)

# ===============================================================================
# Inline Admin Classes
# ===============================================================================


class CouponInline(admin.TabularInline):
    """Inline for coupons within a campaign."""

    model = Coupon
    extra = 0
    readonly_fields = ("code", "total_uses", "total_discount_cents", "created_at")
    fields = ("code", "name", "discount_type", "status", "is_active", "total_uses")
    show_change_link = True


class CouponRedemptionInline(admin.TabularInline):
    """Inline for redemptions within a coupon."""

    model = CouponRedemption
    extra = 0
    readonly_fields = ("order", "customer", "status", "discount_cents", "applied_at")
    fields = ("order", "customer", "status", "discount_cents", "applied_at")
    can_delete = False
    max_num = 0


class GiftCardTransactionInline(admin.TabularInline):
    """Inline for transactions within a gift card."""

    model = GiftCardTransaction
    extra = 0
    readonly_fields = ("transaction_type", "amount_cents", "balance_after_cents", "created_at")
    fields = ("transaction_type", "amount_cents", "balance_after_cents", "order", "created_at")
    can_delete = False
    max_num = 0


class LoyaltyTierInline(admin.TabularInline):
    """Inline for tiers within a loyalty program."""

    model = LoyaltyTier
    extra = 0
    fields = ("name", "slug", "min_points_lifetime", "points_multiplier", "discount_percent", "sort_order")


class LoyaltyTransactionInline(admin.TabularInline):
    """Inline for transactions within customer loyalty."""

    model = LoyaltyTransaction
    extra = 0
    readonly_fields = ("transaction_type", "points", "balance_after", "order", "created_at")
    fields = ("transaction_type", "points", "balance_after", "order", "created_at")
    can_delete = False
    max_num = 0


# ===============================================================================
# Model Admin Classes
# ===============================================================================


@admin.register(PromotionCampaign)
class PromotionCampaignAdmin(admin.ModelAdmin):
    """Admin for promotion campaigns."""

    list_display = (
        "name",
        "campaign_type",
        "status",
        "is_active",
        "start_date",
        "end_date",
        "budget_display",
        "spent_display",
        "coupon_count",
    )
    list_filter = ("status", "is_active", "campaign_type", "created_at")
    search_fields = ("name", "slug", "description")
    readonly_fields = ("spent_cents", "created_at", "updated_at", "created_by")
    prepopulated_fields = {"slug": ("name",)}
    date_hierarchy = "created_at"
    inlines = [CouponInline]

    fieldsets = (
        (None, {"fields": ("name", "slug", "description", "campaign_type")}),
        (_("Schedule"), {"fields": ("start_date", "end_date", "status", "is_active")}),
        (_("Budget"), {"fields": ("budget_cents", "spent_cents")}),
        (_("Tracking"), {"fields": ("utm_source", "utm_medium", "utm_campaign"), "classes": ("collapse",)}),
        (_("Metadata"), {"fields": ("metadata", "created_at", "updated_at", "created_by"), "classes": ("collapse",)}),
    )

    def budget_display(self, obj: Any) -> str:
        if obj.budget_cents:
            return f"{obj.budget_cents / 100:.2f}"
        return "-"

    budget_display.short_description = _("Budget")

    def spent_display(self, obj: Any) -> str:
        return f"{obj.spent_cents / 100:.2f}"

    spent_display.short_description = _("Spent")

    def coupon_count(self, obj: Any) -> int:
        return int(obj.coupons.count())

    coupon_count.short_description = _("Coupons")

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    """Admin for coupons."""

    list_display = (
        "code",
        "name",
        "discount_display",
        "status",
        "is_active",
        "usage_display",
        "valid_until",
        "campaign",
    )
    list_filter = (
        "status",
        "is_active",
        "discount_type",
        "customer_target",
        "campaign",
        "created_at",
    )
    search_fields = ("code", "name", "description")
    readonly_fields = ("total_uses", "total_discount_cents", "created_at", "updated_at", "created_by")
    raw_id_fields = ("campaign", "assigned_customer", "currency")
    date_hierarchy = "created_at"
    inlines = [CouponRedemptionInline]

    fieldsets = (
        (None, {"fields": ("code", "name", "description", "internal_notes", "campaign")}),
        (
            _("Discount"),
            {
                "fields": (
                    "discount_type",
                    "discount_percent",
                    "discount_amount_cents",
                    "free_months",
                    "max_discount_cents",
                    "currency",
                )
            },
        ),
        (_("Requirements"), {"fields": ("min_order_cents", "min_order_items")}),
        (_("Validity"), {"fields": ("valid_from", "valid_until", "status", "is_active", "is_public")}),
        (
            _("Usage Limits"),
            {
                "fields": (
                    "usage_limit_type",
                    "max_total_uses",
                    "max_uses_per_customer",
                    "total_uses",
                    "total_discount_cents",
                )
            },
        ),
        (_("Customer Targeting"), {"fields": ("customer_target", "first_order_only", "assigned_customer")}),
        (
            _("Product Restrictions"),
            {"fields": ("applies_to_all_products", "product_restrictions"), "classes": ("collapse",)},
        ),
        (
            _("Stacking Rules"),
            {
                "fields": ("is_stackable", "is_exclusive", "stacking_priority", "stacking_config"),
                "classes": ("collapse",),
            },
        ),
        (
            _("Metadata"),
            {"fields": ("metadata", "tags", "created_at", "updated_at", "created_by"), "classes": ("collapse",)},
        ),
    )

    def discount_display(self, obj: Any) -> str:
        if obj.discount_type == "percent":
            return f"{obj.discount_percent}%"
        elif obj.discount_type == "fixed":
            return f"{obj.discount_amount_cents / 100:.2f}"
        return str(obj.get_discount_type_display())

    discount_display.short_description = _("Discount")

    def usage_display(self, obj: Any) -> str:
        if obj.max_total_uses:
            return f"{obj.total_uses}/{obj.max_total_uses}"
        return str(obj.total_uses)

    usage_display.short_description = _("Usage")

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(CouponRedemption)
class CouponRedemptionAdmin(admin.ModelAdmin):
    """Admin for coupon redemptions."""

    list_display = (
        "coupon",
        "order",
        "customer",
        "status",
        "discount_cents_display",
        "applied_at",
    )
    list_filter = ("status", "discount_type", "applied_at")
    search_fields = ("coupon__code", "order__order_number", "customer__name")
    readonly_fields = (
        "coupon",
        "order",
        "customer",
        "discount_type",
        "discount_value",
        "discount_cents",
        "order_subtotal_cents",
        "order_total_cents",
        "applied_to_items",
        "source_ip",
        "created_at",
        "applied_at",
        "reversed_at",
    )
    date_hierarchy = "created_at"

    def discount_cents_display(self, obj: Any) -> str:
        return f"{obj.discount_cents / 100:.2f}"

    discount_cents_display.short_description = _("Discount")

    def has_add_permission(self, request: Any) -> bool:
        return False

    def has_change_permission(self, request: Any, obj: Any = None) -> bool:
        return False


@admin.register(PromotionRule)
class PromotionRuleAdmin(admin.ModelAdmin):
    """Admin for promotion rules."""

    list_display = (
        "name",
        "rule_type",
        "discount_display",
        "is_active",
        "priority",
        "valid_from",
        "valid_until",
    )
    list_filter = ("rule_type", "discount_type", "is_active", "is_stackable")
    search_fields = ("name", "description", "display_name")
    readonly_fields = ("created_at", "updated_at", "created_by")

    fieldsets = (
        (None, {"fields": ("name", "description", "campaign")}),
        (_("Rule Type"), {"fields": ("rule_type", "conditions", "tiers")}),
        (
            _("Discount"),
            {
                "fields": (
                    "discount_type",
                    "discount_percent",
                    "discount_amount_cents",
                    "max_discount_cents",
                    "currency",
                )
            },
        ),
        (
            _("Product Restrictions"),
            {"fields": ("applies_to_all_products", "product_restrictions"), "classes": ("collapse",)},
        ),
        (_("Validity"), {"fields": ("valid_from", "valid_until", "is_active")}),
        (_("Stacking"), {"fields": ("is_stackable", "priority")}),
        (_("Display"), {"fields": ("display_name", "display_badge")}),
        (_("Metadata"), {"fields": ("created_at", "updated_at", "created_by"), "classes": ("collapse",)}),
    )

    def discount_display(self, obj: Any) -> str:
        if obj.discount_type in ("percent", "tiered_percent"):
            return f"{obj.discount_percent}%"
        elif obj.discount_type in ("fixed", "tiered_fixed"):
            return f"{obj.discount_amount_cents / 100:.2f}"
        return str(obj.get_discount_type_display())

    discount_display.short_description = _("Discount")

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(GiftCard)
class GiftCardAdmin(admin.ModelAdmin):
    """Admin for gift cards."""

    list_display = (
        "code",
        "card_type",
        "status",
        "initial_value_display",
        "balance_display",
        "currency",
        "purchased_by",
        "redeemed_by",
    )
    list_filter = ("status", "card_type", "currency", "created_at")
    search_fields = ("code", "recipient_email", "recipient_name")
    readonly_fields = (
        "code",
        "current_balance_cents",
        "activated_at",
        "created_at",
        "updated_at",
    )
    raw_id_fields = ("purchased_by", "redeemed_by", "purchase_order", "currency")
    date_hierarchy = "created_at"
    inlines = [GiftCardTransactionInline]

    fieldsets = (
        (None, {"fields": ("code", "card_type", "status", "is_active")}),
        (_("Value"), {"fields": ("initial_value_cents", "current_balance_cents", "currency")}),
        (_("Purchase"), {"fields": ("purchased_by", "purchase_order")}),
        (_("Recipient"), {"fields": ("recipient_email", "recipient_name", "personal_message", "delivery_date")}),
        (_("Redemption"), {"fields": ("redeemed_by",)}),
        (_("Validity"), {"fields": ("valid_from", "valid_until", "activated_at")}),
        (_("Metadata"), {"fields": ("created_at", "updated_at"), "classes": ("collapse",)}),
    )

    def initial_value_display(self, obj: Any) -> str:
        return f"{obj.initial_value_cents / 100:.2f}"

    initial_value_display.short_description = _("Initial Value")

    def balance_display(self, obj: Any) -> str:
        return f"{obj.current_balance_cents / 100:.2f}"

    balance_display.short_description = _("Balance")


@admin.register(ReferralCode)
class ReferralCodeAdmin(admin.ModelAdmin):
    """Admin for referral codes."""

    list_display = (
        "code",
        "owner",
        "is_active",
        "total_referrals",
        "successful_referrals",
        "rewards_display",
    )
    list_filter = ("is_active", "created_at")
    search_fields = ("code", "owner__name", "owner__primary_email")
    readonly_fields = (
        "total_referrals",
        "successful_referrals",
        "total_rewards_cents",
        "created_at",
        "updated_at",
    )
    raw_id_fields = ("owner", "referee_coupon")

    def rewards_display(self, obj: Any) -> str:
        return f"{obj.total_rewards_cents / 100:.2f}"

    rewards_display.short_description = _("Total Rewards")


@admin.register(Referral)
class ReferralAdmin(admin.ModelAdmin):
    """Admin for referrals."""

    list_display = (
        "referral_code",
        "referred_customer",
        "status",
        "qualifying_order",
        "referrer_reward_display",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = (
        "referral_code__code",
        "referred_customer__name",
        "referral_code__owner__name",
    )
    readonly_fields = (
        "referral_code",
        "referred_customer",
        "qualifying_order",
        "referrer_reward_cents",
        "referee_reward_cents",
        "created_at",
        "qualified_at",
        "rewarded_at",
    )
    date_hierarchy = "created_at"

    def referrer_reward_display(self, obj: Any) -> str:
        return f"{obj.referrer_reward_cents / 100:.2f}"

    referrer_reward_display.short_description = _("Referrer Reward")


@admin.register(LoyaltyProgram)
class LoyaltyProgramAdmin(admin.ModelAdmin):
    """Admin for loyalty programs."""

    list_display = (
        "name",
        "is_active",
        "points_per_currency_unit",
        "points_per_discount_unit",
        "min_points_to_redeem",
        "member_count",
    )
    list_filter = ("is_active", "currency")
    search_fields = ("name", "description")
    readonly_fields = ("created_at", "updated_at")
    raw_id_fields = ("currency",)
    inlines = [LoyaltyTierInline]

    def member_count(self, obj: Any) -> int:
        return int(obj.memberships.filter(is_active=True).count())

    member_count.short_description = _("Members")


@admin.register(LoyaltyTier)
class LoyaltyTierAdmin(admin.ModelAdmin):
    """Admin for loyalty tiers."""

    list_display = (
        "name",
        "program",
        "min_points_lifetime",
        "points_multiplier",
        "discount_percent",
        "free_shipping",
        "sort_order",
    )
    list_filter = ("program", "free_shipping", "priority_support")
    search_fields = ("name", "program__name")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(CustomerLoyalty)
class CustomerLoyaltyAdmin(admin.ModelAdmin):
    """Admin for customer loyalty memberships."""

    list_display = (
        "customer",
        "program",
        "current_tier",
        "points_balance",
        "points_lifetime",
        "total_spend_display",
        "is_active",
    )
    list_filter = ("program", "current_tier", "is_active")
    search_fields = ("customer__name", "customer__primary_email")
    readonly_fields = (
        "points_balance",
        "points_lifetime",
        "points_redeemed",
        "points_expired",
        "total_spend_cents",
        "total_orders",
        "enrolled_at",
        "created_at",
        "updated_at",
    )
    raw_id_fields = ("customer", "program", "current_tier")
    date_hierarchy = "enrolled_at"
    inlines = [LoyaltyTransactionInline]

    def total_spend_display(self, obj: Any) -> str:
        return f"{obj.total_spend_cents / 100:.2f}"

    total_spend_display.short_description = _("Total Spend")


@admin.register(LoyaltyTransaction)
class LoyaltyTransactionAdmin(admin.ModelAdmin):
    """Admin for loyalty transactions."""

    list_display = (
        "customer_loyalty",
        "transaction_type",
        "points_display",
        "balance_after",
        "order",
        "created_at",
    )
    list_filter = ("transaction_type", "created_at")
    search_fields = (
        "customer_loyalty__customer__name",
        "customer_loyalty__customer__primary_email",
    )
    readonly_fields = (
        "customer_loyalty",
        "transaction_type",
        "points",
        "balance_after",
        "order",
        "coupon_redemption",
        "description",
        "expires_at",
        "created_at",
        "created_by",
    )
    date_hierarchy = "created_at"

    def points_display(self, obj: Any) -> str:
        color = "green" if obj.points > 0 else "red"
        return format_html(
            '<span style="color: {};">{:+d}</span>',
            color,
            obj.points,
        )

    points_display.short_description = _("Points")

    def has_add_permission(self, request: Any) -> bool:
        return False

    def has_change_permission(self, request: Any, obj: Any = None) -> bool:
        return False
