"""
Streamlined product signals for PRAHO Platform
Focus ONLY on product creation and pricing/availability changes for catalog management.
"""

import logging
from decimal import Decimal
from typing import Any

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import ProductsAuditService

from .models import Product, ProductPrice

logger = logging.getLogger(__name__)

# NOTE: VAT rates are NOT constants — use TaxService.get_vat_rate('RO'). See ADR-0005, ADR-0015.
PRICING_THRESHOLDS: dict[str, Any] = {
    "significant_change_percent": 15,  # Alert when price changes by more than 15%
    "high_value_product_ron": 500,  # Products over 500 RON need approval tracking
    "promotional_discount_limit": 50,  # Maximum promotional discount percentage
    "vat_compliance_check": True,  # Always verify VAT calculations
}

# Product categories requiring special audit attention
HIGH_ATTENTION_CATEGORIES: list[str] = [
    "dedicated",  # Dedicated servers require detailed tracking
    "vps",  # VPS changes affect multiple customers
    "ssl",  # SSL certificates have legal compliance aspects
    "domain",  # Domain registrations have ROTLD compliance
]


@receiver(pre_save, sender=Product)
def capture_product_changes(sender: type[Product], instance: Product, **kwargs: Any) -> None:
    """
    Capture product changes to determine what changed for audit logging.

    This pre_save signal captures the old values so we can compare in post_save.
    Focus on pricing, availability, and key business fields.
    """
    try:
        if instance.pk:
            # Get the old instance from database to compare
            old_instance = Product.objects.get(pk=instance.pk)
            instance._old_is_active = old_instance.is_active
            instance._old_is_public = old_instance.is_public
            instance._old_is_featured = old_instance.is_featured
            instance._old_includes_vat = old_instance.includes_vat
            instance._old_product_type = old_instance.product_type
        else:
            # New product - no old values
            instance._old_is_active = None
            instance._old_is_public = None
            instance._old_is_featured = None
            instance._old_includes_vat = None
            instance._old_product_type = None
    except Product.DoesNotExist:
        # Handle edge case where product was deleted
        logger.warning("🚨 [Products] Product %s not found in pre_save", instance.pk)
        instance._old_is_active = None
        instance._old_is_public = None
        instance._old_is_featured = None
        instance._old_includes_vat = None
        instance._old_product_type = None
    except Exception as e:
        logger.error("🔥 [Products] Error capturing product changes: %s", e)


@receiver(post_save, sender=Product)
def log_product_lifecycle_events(sender: type[Product], instance: Product, created: bool, **kwargs: Any) -> None:
    """
    Log product creation and key business changes for catalog management.

    Events logged:
    - Product creation with initial configuration
    - Availability changes (active/inactive, public/private)
    - VAT configuration changes (Romanian compliance)
    - Product type changes (affects provisioning)
    """
    try:
        if created:
            # New product created
            from apps.common.tax_service import TaxService  # noqa: PLC0415

            romanian_context = {
                "vat_rate_applied": float(TaxService.get_vat_rate("RO", as_decimal=False)),
                "includes_vat": instance.includes_vat,
                "product_category": instance.product_type,
                "requires_rotld_compliance": instance.product_type == "domain",
                "high_attention_category": instance.product_type in HIGH_ATTENTION_CATEGORIES,
            }

            ProductsAuditService.log_product_created(
                product=instance, romanian_business_context=romanian_context, context=None
            )

        else:
            # Check for availability changes
            availability_changed = _check_availability_changes(instance)
            if availability_changed:
                ProductsAuditService.log_product_availability_changed(
                    product=instance,
                    changes=availability_changed,
                    romanian_business_context={
                        "vat_compliance_affected": availability_changed.get("vat_setting_changed", False),
                        "customer_impact_level": _assess_customer_impact(instance),
                    },
                    context=None,
                )

    except Exception as e:
        logger.error("🔥 [Products] Error in product lifecycle logging: %s", e)


@receiver(pre_save, sender=ProductPrice)
def capture_price_changes(sender: type[ProductPrice], instance: ProductPrice, **kwargs: Any) -> None:
    """
    Capture price changes for Romanian VAT compliance and billing transparency.
    Updated for simplified pricing model.
    """
    try:
        if instance.pk:
            # Get the old instance from database to compare pricing
            old_instance = ProductPrice.objects.get(pk=instance.pk)
            instance._old_monthly_price_cents = old_instance.monthly_price_cents  # type: ignore[attr-defined]
            instance._old_setup_cents = old_instance.setup_cents  # type: ignore[attr-defined]
            instance._old_promo_price_cents = old_instance.promo_price_cents  # type: ignore[attr-defined]
            instance._old_is_active = old_instance.is_active  # type: ignore[attr-defined]
            instance._old_semiannual_discount_percent = old_instance.semiannual_discount_percent  # type: ignore[attr-defined]
            instance._old_annual_discount_percent = old_instance.annual_discount_percent  # type: ignore[attr-defined]
        else:
            # New price - no old values
            instance._old_monthly_price_cents = None  # type: ignore[attr-defined]
            instance._old_setup_cents = None  # type: ignore[attr-defined]
            instance._old_promo_price_cents = None  # type: ignore[attr-defined]
            instance._old_is_active = None  # type: ignore[attr-defined]
            instance._old_semiannual_discount_percent = None  # type: ignore[attr-defined]
            instance._old_annual_discount_percent = None  # type: ignore[attr-defined]
    except ProductPrice.DoesNotExist:
        logger.warning("🚨 [Products] ProductPrice %s not found in pre_save", instance.pk)
        instance._old_monthly_price_cents = None  # type: ignore[attr-defined]
        instance._old_setup_cents = None  # type: ignore[attr-defined]
        instance._old_promo_price_cents = None  # type: ignore[attr-defined]
        instance._old_is_active = None  # type: ignore[attr-defined]
        instance._old_semiannual_discount_percent = None  # type: ignore[attr-defined]
        instance._old_annual_discount_percent = None  # type: ignore[attr-defined]
    except Exception as e:
        logger.error("🔥 [Products] Error capturing price changes: %s", e)


@receiver(post_save, sender=ProductPrice)
def log_price_changes(sender: type[ProductPrice], instance: ProductPrice, created: bool, **kwargs: Any) -> None:
    """
    Log pricing changes for Romanian VAT compliance and customer transparency.

    Important for:
    - Grandfathered pricing for existing customers
    - VAT compliance (Romanian rate via TaxService)
    - Promotional pricing audits
    - Billing accuracy
    """
    try:
        if created:
            from apps.common.tax_service import TaxService  # noqa: PLC0415

            # New price created - log initial pricing setup
            romanian_context = {
                "currency": instance.currency.code,
                "billing_model": "simplified_monthly",  # New simplified model
                "includes_vat": instance.product.includes_vat,
                "vat_rate_applied": float(TaxService.get_vat_rate("RO", as_decimal=False)),
                "high_value_product": instance.monthly_price_cents > (PRICING_THRESHOLDS["high_value_product_ron"] * 100),
                "semiannual_discount": float(instance.semiannual_discount_percent),
                "annual_discount": float(instance.annual_discount_percent),
            }

            # We don't log every new price creation as it's too verbose
            # Only log if it's for a high-attention category or high-value product
            if instance.product.product_type in HIGH_ATTENTION_CATEGORIES or instance.monthly_price_cents > (
                PRICING_THRESHOLDS["high_value_product_ron"] * 100
            ):
                ProductsAuditService.log_product_pricing_changed(
                    product_price=instance,
                    change_type="price_created",
                    changes={"new_monthly_price_cents": instance.monthly_price_cents},
                    romanian_business_context=romanian_context,
                    context=None,
                )
        else:
            # Check for significant pricing changes
            pricing_changes = _check_pricing_changes(instance)
            if pricing_changes:
                romanian_context = {
                    "currency": instance.currency.code,
                    "billing_model": "simplified_monthly",
                    "vat_compliance_verified": True,
                    "grandfathered_customers_affected": pricing_changes.get("price_increased", False),
                    "promotional_pricing_active": bool(instance.promo_price_cents),
                    "discount_adjustments": {
                        "semiannual": float(instance.semiannual_discount_percent),
                        "annual": float(instance.annual_discount_percent),
                    },
                }

                ProductsAuditService.log_product_pricing_changed(
                    product_price=instance,
                    change_type="price_updated",
                    changes=pricing_changes,
                    romanian_business_context=romanian_context,
                    context=None,
                )

    except Exception as e:
        logger.error("🔥 [Products] Error in price change logging: %s", e)


def _check_availability_changes(instance: Product) -> dict[str, Any] | None:
    """
    Check what availability-related fields changed on a product.

    Returns dictionary of changes or None if no significant changes.
    """
    changes = {}

    # Check activity status changes
    if hasattr(instance, "_old_is_active") and instance._old_is_active != instance.is_active:
        changes["availability_changed"] = {
            "from": instance._old_is_active,
            "to": instance.is_active,
            "impact": "high" if not instance.is_active else "medium",
        }

    # Check public visibility changes
    if hasattr(instance, "_old_is_public") and instance._old_is_public != instance.is_public:
        changes["visibility_changed"] = {"from": instance._old_is_public, "to": instance.is_public, "impact": "medium"}

    # Check featured status changes
    if hasattr(instance, "_old_is_featured") and instance._old_is_featured != instance.is_featured:
        changes["featured_changed"] = {"from": instance._old_is_featured, "to": instance.is_featured, "impact": "low"}

    # Check VAT setting changes (important for Romanian compliance)
    if hasattr(instance, "_old_includes_vat") and instance._old_includes_vat != instance.includes_vat:
        changes["vat_setting_changed"] = {
            "from": instance._old_includes_vat,
            "to": instance.includes_vat,
            "impact": "high",  # VAT changes are critical for compliance
            "requires_price_recalculation": True,
        }

    # Check product type changes (affects provisioning)
    if hasattr(instance, "_old_product_type") and instance._old_product_type != instance.product_type:
        changes["product_type_changed"] = {
            "from": instance._old_product_type,
            "to": instance.product_type,
            "impact": "high",  # Product type changes are significant
            "provisioning_impact": True,
        }

    return changes if changes else None


def _check_pricing_changes(instance: ProductPrice) -> dict[str, Any] | None:
    """
    Check what pricing fields changed and calculate impact.
    Updated for simplified pricing model.

    Returns dictionary of changes or None if no significant changes.
    """
    changes = {}

    # Check monthly price changes (main price in simplified model)
    if (
        hasattr(instance, "_old_monthly_price_cents")
        and instance._old_monthly_price_cents != instance.monthly_price_cents
        and instance._old_monthly_price_cents
    ):
        old_amount = Decimal(instance._old_monthly_price_cents) / 100
        new_amount = Decimal(instance.monthly_price_cents) / 100
        percent_change = abs((new_amount - old_amount) / old_amount * 100)

        # Only log if change is significant
        if percent_change >= PRICING_THRESHOLDS["significant_change_percent"]:
            changes["monthly_price_changed"] = {
                "from_cents": instance._old_monthly_price_cents,
                "to_cents": instance.monthly_price_cents,
                "from_amount": float(old_amount),
                "to_amount": float(new_amount),
                "percent_change": float(percent_change),
                "price_increased": new_amount > old_amount,
                "significant": True,
            }

    # Check setup fee changes
    if hasattr(instance, "_old_setup_cents") and instance._old_setup_cents != instance.setup_cents:
        changes["setup_fee_changed"] = {
            "from_cents": instance._old_setup_cents,
            "to_cents": instance.setup_cents,
            "from_amount": float(Decimal(instance._old_setup_cents or 0) / 100),
            "to_amount": float(Decimal(instance.setup_cents) / 100),
        }

    # Check promotional pricing changes
    if hasattr(instance, "_old_promo_price_cents") and instance._old_promo_price_cents != instance.promo_price_cents:
        changes["promotional_pricing_changed"] = {
            "from_cents": instance._old_promo_price_cents,
            "to_cents": instance.promo_price_cents,
            "promotion_added": instance.promo_price_cents and not instance._old_promo_price_cents,
            "promotion_removed": not instance.promo_price_cents and instance._old_promo_price_cents,
        }

    # Check semiannual discount changes
    if (
        hasattr(instance, "_old_semiannual_discount_percent")
        and instance._old_semiannual_discount_percent != instance.semiannual_discount_percent
    ):
        changes["semiannual_discount_changed"] = {
            "from_percent": float(instance._old_semiannual_discount_percent or 0),
            "to_percent": float(instance.semiannual_discount_percent),
            "discount_increased": instance.semiannual_discount_percent > (instance._old_semiannual_discount_percent or 0),
        }

    # Check annual discount changes
    if (
        hasattr(instance, "_old_annual_discount_percent")
        and instance._old_annual_discount_percent != instance.annual_discount_percent
    ):
        changes["annual_discount_changed"] = {
            "from_percent": float(instance._old_annual_discount_percent or 0),
            "to_percent": float(instance.annual_discount_percent),
            "discount_increased": instance.annual_discount_percent > (instance._old_annual_discount_percent or 0),
        }

    # Check availability changes
    if hasattr(instance, "_old_is_active") and instance._old_is_active != instance.is_active:
        changes["price_availability_changed"] = {
            "from": instance._old_is_active,
            "to": instance.is_active,
            "price_disabled": not instance.is_active,
        }

    return changes if changes else None


def _assess_customer_impact(product: Product) -> str:
    """
    Assess the potential impact of product changes on customers.

    Returns impact level: 'low', 'medium', 'high', 'critical'
    """
    # High attention categories automatically get higher impact
    if product.product_type in HIGH_ATTENTION_CATEGORIES:
        return "high"

    # Featured products have medium impact
    if product.is_featured:
        return "medium"

    # Check if product becomes unavailable
    if not product.is_active:
        return "high"

    # Default to low impact
    return "low"
