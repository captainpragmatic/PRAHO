"""
Signal handlers for Promotions app.
Provides comprehensive audit logging for all promotion-related events.
Integrates with the audit module for compliance and security tracking.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from apps.audit.models import AuditEvent
from apps.audit.services import AuditService

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

logger = logging.getLogger(__name__)


# ===============================================================================
# Helper Functions
# ===============================================================================


def create_audit_event(
    action: str,
    instance: Any,
    category: str = "business_operation",
    severity: str = "low",
    old_values: dict | None = None,
    new_values: dict | None = None,
    description: str = "",
    user: Any | None = None,
    is_sensitive: bool = False,
    metadata: dict | None = None,
) -> AuditEvent:
    """Create an audit event for a promotion-related action via the audit service."""
    return AuditService.log_simple_event(
        event_type=action,
        user=user,
        content_object=instance,
        description=description,
        old_values=old_values,
        new_values=new_values,
        metadata=metadata,
    )


def _serialize_value(value: Any) -> Any:
    """Serialize a value for JSON storage in audit events."""
    from datetime import date, datetime
    from decimal import Decimal
    from uuid import UUID

    if value is None:
        return None
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "pk"):
        return str(value.pk)
    return value


def get_model_changes(instance: Any, fields: list[str]) -> tuple[dict, dict]:
    """Get old and new values for specified fields."""
    old_values = {}
    new_values = {}

    for field in fields:
        old_value = getattr(instance, f"_old_{field}", None)
        new_value = getattr(instance, field, None)

        if old_value != new_value:
            old_values[field] = _serialize_value(old_value)
            new_values[field] = _serialize_value(new_value)

    return old_values, new_values


# ===============================================================================
# Campaign Signals
# ===============================================================================


@receiver(pre_save, sender=PromotionCampaign)
def campaign_pre_save(sender: type, instance: PromotionCampaign, **kwargs: Any) -> None:
    """Store old values before campaign save."""
    if instance.pk:
        try:
            old_instance = PromotionCampaign.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
            instance._old_is_active = old_instance.is_active
            instance._old_budget_cents = old_instance.budget_cents
        except PromotionCampaign.DoesNotExist:
            pass


@receiver(post_save, sender=PromotionCampaign)
def campaign_post_save(
    sender: type,
    instance: PromotionCampaign,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log campaign creation and updates."""
    if created:
        create_audit_event(
            action="promotion_campaign_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "name": instance.name,
                "campaign_type": instance.campaign_type,
                "status": instance.status,
                "start_date": str(instance.start_date),
                "end_date": str(instance.end_date) if instance.end_date else None,
                "budget_cents": instance.budget_cents,
            },
            description=f"Promotion campaign '{instance.name}' created",
            user=instance.created_by,
        )
        logger.info(f"Campaign created: {instance.name}")
    else:
        old_values, new_values = get_model_changes(
            instance,
            ["status", "is_active", "budget_cents"],
        )
        if old_values:
            # Determine severity based on change type
            severity = "low"
            if "status" in new_values:
                if new_values["status"] == "cancelled":
                    severity = "medium"
                elif new_values["status"] == "active":
                    severity = "low"

            create_audit_event(
                action="promotion_campaign_updated",
                instance=instance,
                category="business_operation",
                severity=severity,
                old_values=old_values,
                new_values=new_values,
                description=f"Promotion campaign '{instance.name}' updated",
            )
            logger.info(f"Campaign updated: {instance.name}")


# ===============================================================================
# Coupon Signals
# ===============================================================================


@receiver(pre_save, sender=Coupon)
def coupon_pre_save(sender: type, instance: Coupon, **kwargs: Any) -> None:
    """Store old values before coupon save."""
    if instance.pk:
        try:
            old_instance = Coupon.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
            instance._old_is_active = old_instance.is_active
            instance._old_discount_percent = old_instance.discount_percent
            instance._old_discount_amount_cents = old_instance.discount_amount_cents
            instance._old_max_total_uses = old_instance.max_total_uses
            instance._old_valid_until = old_instance.valid_until
        except Coupon.DoesNotExist:
            pass


@receiver(post_save, sender=Coupon)
def coupon_post_save(
    sender: type,
    instance: Coupon,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log coupon creation and updates."""
    if created:
        create_audit_event(
            action="coupon_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "code": instance.code,
                "name": instance.name,
                "discount_type": instance.discount_type,
                "discount_percent": float(instance.discount_percent) if instance.discount_percent else None,
                "discount_amount_cents": instance.discount_amount_cents,
                "usage_limit_type": instance.usage_limit_type,
                "max_total_uses": instance.max_total_uses,
                "valid_from": str(instance.valid_from),
                "valid_until": str(instance.valid_until) if instance.valid_until else None,
                "customer_target": instance.customer_target,
                "is_stackable": instance.is_stackable,
                "is_exclusive": instance.is_exclusive,
            },
            description=f"Coupon '{instance.code}' created",
            user=instance.created_by,
            is_sensitive=True,  # Coupon codes can be sensitive
        )
        logger.info(f"Coupon created: {instance.code}")
    else:
        old_values, new_values = get_model_changes(
            instance,
            ["status", "is_active", "discount_percent", "discount_amount_cents", "max_total_uses", "valid_until"],
        )
        if old_values:
            severity = "low"
            if "status" in new_values:
                if new_values["status"] == "cancelled":
                    severity = "medium"

            create_audit_event(
                action="coupon_updated",
                instance=instance,
                category="business_operation",
                severity=severity,
                old_values=old_values,
                new_values=new_values,
                description=f"Coupon '{instance.code}' updated",
                is_sensitive=True,
            )
            logger.info(f"Coupon updated: {instance.code}")


@receiver(pre_delete, sender=Coupon)
def coupon_pre_delete(sender: type, instance: Coupon, **kwargs: Any) -> None:
    """Log coupon deletion."""
    create_audit_event(
        action="coupon_deleted",
        instance=instance,
        category="business_operation",
        severity="medium",
        old_values={
            "code": instance.code,
            "name": instance.name,
            "total_uses": instance.total_uses,
            "total_discount_cents": instance.total_discount_cents,
        },
        description=f"Coupon '{instance.code}' deleted",
        is_sensitive=True,
    )
    logger.warning(f"Coupon deleted: {instance.code}")


# ===============================================================================
# Coupon Redemption Signals
# ===============================================================================


@receiver(pre_save, sender=CouponRedemption)
def redemption_pre_save(sender: type, instance: CouponRedemption, **kwargs: Any) -> None:
    """Store old values before redemption save."""
    if instance.pk:
        try:
            old_instance = CouponRedemption.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        except CouponRedemption.DoesNotExist:
            pass


@receiver(post_save, sender=CouponRedemption)
def redemption_post_save(
    sender: type,
    instance: CouponRedemption,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log coupon redemption events."""
    if created:
        create_audit_event(
            action="coupon_redemption_initiated",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "coupon_code": instance.coupon.code,
                "order_number": instance.order.order_number,
                "customer_id": str(instance.customer.id) if instance.customer else None,
                "discount_type": instance.discount_type,
                "discount_value": float(instance.discount_value),
            },
            description=f"Coupon '{instance.coupon.code}' redemption initiated for order {instance.order.order_number}",
            metadata={
                "source_ip": instance.source_ip,
                "order_subtotal_cents": instance.order_subtotal_cents,
            },
            is_sensitive=True,
        )
    else:
        old_status = getattr(instance, "_old_status", None)
        if old_status and old_status != instance.status:
            # Determine action based on status change
            action = "coupon_redemption_updated"
            severity = "low"

            if instance.status == "applied":
                action = "coupon_redemption_applied"
                description = f"Coupon '{instance.coupon.code}' applied to order {instance.order.order_number}"
            elif instance.status == "failed":
                action = "coupon_redemption_failed"
                severity = "medium"
                description = f"Coupon '{instance.coupon.code}' redemption failed: {instance.failure_reason}"
            elif instance.status == "reversed":
                action = "coupon_redemption_reversed"
                severity = "medium"
                description = f"Coupon '{instance.coupon.code}' redemption reversed on order {instance.order.order_number}"
            else:
                description = f"Coupon redemption status changed to {instance.status}"

            create_audit_event(
                action=action,
                instance=instance,
                category="business_operation",
                severity=severity,
                old_values={"status": old_status},
                new_values={
                    "status": instance.status,
                    "discount_cents": instance.discount_cents,
                },
                description=description,
                is_sensitive=True,
            )
            logger.info(f"Coupon redemption {instance.status}: {instance.coupon.code}")


# ===============================================================================
# Promotion Rule Signals
# ===============================================================================


@receiver(post_save, sender=PromotionRule)
def rule_post_save(
    sender: type,
    instance: PromotionRule,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log promotion rule creation and updates."""
    if created:
        create_audit_event(
            action="promotion_rule_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "name": instance.name,
                "rule_type": instance.rule_type,
                "discount_type": instance.discount_type,
                "is_active": instance.is_active,
            },
            description=f"Promotion rule '{instance.name}' created",
            user=instance.created_by,
        )


# ===============================================================================
# Gift Card Signals
# ===============================================================================


@receiver(pre_save, sender=GiftCard)
def gift_card_pre_save(sender: type, instance: GiftCard, **kwargs: Any) -> None:
    """Store old values before gift card save."""
    if instance.pk:
        try:
            old_instance = GiftCard.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
            instance._old_current_balance_cents = old_instance.current_balance_cents
        except GiftCard.DoesNotExist:
            pass


@receiver(post_save, sender=GiftCard)
def gift_card_post_save(
    sender: type,
    instance: GiftCard,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log gift card creation and status changes."""
    if created:
        create_audit_event(
            action="gift_card_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "code": instance.code,
                "initial_value_cents": instance.initial_value_cents,
                "card_type": instance.card_type,
            },
            description=f"Gift card '{instance.code}' created with value {instance.initial_value_cents / 100:.2f}",
            is_sensitive=True,
        )
    else:
        old_status = getattr(instance, "_old_status", None)
        if old_status and old_status != instance.status:
            action = "gift_card_status_changed"
            severity = "low"

            if instance.status == "active" and old_status == "pending":
                action = "gift_card_activated"
                description = f"Gift card '{instance.code}' activated"
            elif instance.status == "depleted":
                action = "gift_card_depleted"
                description = f"Gift card '{instance.code}' fully redeemed"
            elif instance.status == "cancelled":
                action = "gift_card_cancelled"
                severity = "medium"
                description = f"Gift card '{instance.code}' cancelled"
            else:
                description = f"Gift card '{instance.code}' status changed to {instance.status}"

            create_audit_event(
                action=action,
                instance=instance,
                category="business_operation",
                severity=severity,
                old_values={"status": old_status},
                new_values={"status": instance.status},
                description=description,
                is_sensitive=True,
            )


@receiver(post_save, sender=GiftCardTransaction)
def gift_card_transaction_post_save(
    sender: type,
    instance: GiftCardTransaction,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log gift card transactions."""
    if created:
        action_map = {
            "activation": "gift_card_activated",
            "redemption": "gift_card_redeemed",
            "refund": "gift_card_refunded",
            "adjustment": "gift_card_adjusted",
            "expiration": "gift_card_expired",
        }

        action = action_map.get(instance.transaction_type, "gift_card_transaction")
        severity = "low" if instance.transaction_type in ("activation", "redemption") else "medium"

        create_audit_event(
            action=action,
            instance=instance,
            category="business_operation",
            severity=severity,
            new_values={
                "gift_card_code": instance.gift_card.code,
                "transaction_type": instance.transaction_type,
                "amount_cents": instance.amount_cents,
                "balance_after_cents": instance.balance_after_cents,
                "order_number": instance.order.order_number if instance.order else None,
            },
            description=instance.description or f"Gift card {instance.transaction_type}",
            user=instance.created_by,
            is_sensitive=True,
        )


# ===============================================================================
# Referral Signals
# ===============================================================================


@receiver(post_save, sender=ReferralCode)
def referral_code_post_save(
    sender: type,
    instance: ReferralCode,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log referral code creation."""
    if created:
        create_audit_event(
            action="referral_code_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "code": instance.code,
                "owner_id": str(instance.owner.id),
                "referrer_discount_percent": float(instance.referrer_discount_percent),
                "referee_discount_percent": float(instance.referee_discount_percent),
            },
            description=f"Referral code '{instance.code}' created for customer",
        )


@receiver(pre_save, sender=Referral)
def referral_pre_save(sender: type, instance: Referral, **kwargs: Any) -> None:
    """Store old values before referral save."""
    if instance.pk:
        try:
            old_instance = Referral.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        except Referral.DoesNotExist:
            pass


@receiver(post_save, sender=Referral)
def referral_post_save(
    sender: type,
    instance: Referral,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log referral creation and status changes."""
    if created:
        create_audit_event(
            action="referral_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "referral_code": instance.referral_code.code,
                "referred_customer_id": str(instance.referred_customer.id),
            },
            description=f"New referral via code '{instance.referral_code.code}'",
        )
    else:
        old_status = getattr(instance, "_old_status", None)
        if old_status and old_status != instance.status:
            action_map = {
                "qualified": "referral_qualified",
                "rewarded": "referral_rewarded",
                "expired": "referral_expired",
                "cancelled": "referral_cancelled",
            }

            action = action_map.get(instance.status, "referral_updated")

            create_audit_event(
                action=action,
                instance=instance,
                category="business_operation",
                severity="low",
                old_values={"status": old_status},
                new_values={
                    "status": instance.status,
                    "referrer_reward_cents": instance.referrer_reward_cents,
                    "referee_reward_cents": instance.referee_reward_cents,
                },
                description=f"Referral status changed to {instance.status}",
            )


# ===============================================================================
# Loyalty Signals
# ===============================================================================


@receiver(post_save, sender=LoyaltyProgram)
def loyalty_program_post_save(
    sender: type,
    instance: LoyaltyProgram,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log loyalty program creation and updates."""
    if created:
        create_audit_event(
            action="loyalty_program_created",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "name": instance.name,
                "points_per_currency_unit": float(instance.points_per_currency_unit),
                "points_per_discount_unit": instance.points_per_discount_unit,
            },
            description=f"Loyalty program '{instance.name}' created",
        )


@receiver(post_save, sender=CustomerLoyalty)
def customer_loyalty_post_save(
    sender: type,
    instance: CustomerLoyalty,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log customer loyalty enrollment."""
    if created:
        create_audit_event(
            action="loyalty_member_enrolled",
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "customer_id": str(instance.customer.id),
                "program_name": instance.program.name,
                "initial_tier": instance.current_tier.name if instance.current_tier else None,
            },
            description=f"Customer enrolled in loyalty program '{instance.program.name}'",
        )


@receiver(pre_save, sender=CustomerLoyalty)
def customer_loyalty_pre_save(sender: type, instance: CustomerLoyalty, **kwargs: Any) -> None:
    """Store old tier before save."""
    if instance.pk:
        try:
            old_instance = CustomerLoyalty.objects.get(pk=instance.pk)
            instance._old_current_tier = old_instance.current_tier
            instance._old_points_balance = old_instance.points_balance
        except CustomerLoyalty.DoesNotExist:
            pass


@receiver(post_save, sender=CustomerLoyalty)
def customer_loyalty_tier_change(
    sender: type,
    instance: CustomerLoyalty,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log loyalty tier changes."""
    if not created:
        old_tier = getattr(instance, "_old_current_tier", None)
        if old_tier != instance.current_tier and instance.current_tier:
            old_tier_name = old_tier.name if old_tier else "None"
            new_tier_name = instance.current_tier.name

            create_audit_event(
                action="loyalty_tier_changed",
                instance=instance,
                category="business_operation",
                severity="low",
                old_values={"tier": old_tier_name},
                new_values={"tier": new_tier_name},
                description=f"Customer loyalty tier changed from {old_tier_name} to {new_tier_name}",
            )


@receiver(post_save, sender=LoyaltyTransaction)
def loyalty_transaction_post_save(
    sender: type,
    instance: LoyaltyTransaction,
    created: bool,
    **kwargs: Any,
) -> None:
    """Log loyalty point transactions."""
    if created:
        action_map = {
            "earn": "loyalty_points_earned",
            "redeem": "loyalty_points_redeemed",
            "expire": "loyalty_points_expired",
            "adjust": "loyalty_points_adjusted",
            "bonus": "loyalty_points_bonus",
            "refund": "loyalty_points_refunded",
            "tier_bonus": "loyalty_tier_bonus",
        }

        action = action_map.get(instance.transaction_type, "loyalty_transaction")

        create_audit_event(
            action=action,
            instance=instance,
            category="business_operation",
            severity="low",
            new_values={
                "transaction_type": instance.transaction_type,
                "points": instance.points,
                "balance_after": instance.balance_after,
                "order_number": instance.order.order_number if instance.order else None,
            },
            description=instance.description or f"Loyalty {instance.transaction_type}: {instance.points:+d} points",
            user=instance.created_by,
        )
