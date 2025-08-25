"""
Product Catalog models for PRAHO Platform
Defines the master catalog of products and services that customers can order.
Includes pricing, relationships, and configuration for Romanian hosting provider.
"""

import uuid
from decimal import Decimal
from typing import Any, Optional

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# PRODUCT CATALOG MODELS
# ===============================================================================

class Product(models.Model):
    """
    Core product definition for hosting services.
    This is the master catalog from which customers can order.
    Romanian hosting provider specific fields included.
    """

    # Use UUID for better security and referencing
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Basic Information
    slug = models.SlugField(
        unique=True,
        max_length=100,
        help_text=_("URL-friendly identifier")
    )
    name = models.CharField(
        max_length=200,
        help_text=_("Display name for customers")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Detailed product description")
    )
    short_description = models.CharField(
        max_length=500,
        blank=True,
        help_text=_("Brief description for listings")
    )

    # Product categorization
    PRODUCT_TYPES = [
        ('shared_hosting', _('Shared Hosting')),
        ('vps', _('VPS')),
        ('dedicated', _('Dedicated Server')),
        ('domain', _('Domain Registration')),
        ('ssl', _('SSL Certificate')),
        ('email', _('Email Hosting')),
        ('backup', _('Backup Service')),
        ('addon', _('Add-on Service')),
        ('license', _('Software License')),
        ('support', _('Support Package')),
    ]
    product_type = models.CharField(
        max_length=30,
        choices=PRODUCT_TYPES,
        help_text=_("Product category")
    )

    # Module configuration for provisioning
    module = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Provisioning module name (e.g., 'cpanel', 'plesk', 'virtualmin')")
    )
    module_config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Module-specific configuration for provisioning")
    )

    # Status and availability
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether product is available for purchase")
    )
    is_featured = models.BooleanField(
        default=False,
        help_text=_("Show prominently on website")
    )
    is_public = models.BooleanField(
        default=True,
        help_text=_("Visible on public website")
    )

    # Requirements and constraints
    requires_domain = models.BooleanField(
        default=False,
        help_text=_("Customer must provide a domain")
    )
    domain_required_at_signup = models.BooleanField(
        default=False,
        help_text=_("Domain must be specified during order")
    )

    # Display and ordering
    sort_order = models.PositiveIntegerField(
        default=0,
        help_text=_("Display order (lower numbers first)")
    )

        # SEO and metadata
    meta_title = models.CharField(max_length=255, blank=True)
    meta_description = models.TextField(blank=True)

    # Tags - using JSONField for SQLite compatibility
    tags = models.JSONField(
        default=list,
        blank=True,
        help_text="Tags for filtering and search (as JSON array)"
    )

    # Romanian specific
    includes_vat = models.BooleanField(
        default=False,
        help_text=_("Whether displayed prices include VAT")
    )

    # Additional metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional product metadata")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'products'
        verbose_name = _('Product')
        verbose_name_plural = _('Products')
        ordering = ['sort_order', 'name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['product_type', 'is_active']),
            models.Index(fields=['is_active', 'is_public']),
            models.Index(fields=['sort_order']),
        ]

    def __str__(self) -> str:
        return self.name

    def get_active_prices(self) -> QuerySet['ProductPrice']:
        """Get all active prices for this product"""
        return self.prices.filter(is_active=True)

    def get_price_for_period(self, currency_code: str, billing_period: str) -> Optional['ProductPrice']:
        """Get price for specific currency and billing period"""
        try:
            return self.prices.get(
                currency__code=currency_code,
                billing_period=billing_period,
                is_active=True
            )
        except ProductPrice.DoesNotExist:
            return None


class ProductPrice(models.Model):
    """
    Multi-currency, multi-period pricing for products.
    Supports one-time and recurring billing with Romanian specifics.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Product relationship
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='prices'
    )

    # Currency
    currency = models.ForeignKey(
        'billing.Currency',
        on_delete=models.PROTECT,
        help_text=_("Currency for this price")
    )

    # Billing configuration
    BILLING_PERIODS = [
        ('once', _('One Time')),
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
        ('semiannual', _('Semi-Annual')),
        ('annual', _('Annual')),
        ('biennial', _('Biennial')),
        ('triennial', _('Triennial')),
    ]
    billing_period = models.CharField(
        max_length=20,
        choices=BILLING_PERIODS,
        help_text=_("Billing frequency")
    )

    # Pricing in cents to avoid float precision issues
    amount_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text=_("Recurring price in cents (e.g., 2999 for 29.99 RON)")
    )
    setup_cents = models.BigIntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("One-time setup fee in cents")
    )

    # Optional pricing features
    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Percentage discount (0-100)")
    )

    # Minimum commitment
    minimum_quantity = models.PositiveIntegerField(
        default=1,
        help_text=_("Minimum quantity that can be ordered")
    )
    maximum_quantity = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_("Maximum quantity (blank for unlimited)")
    )

    # Promotional pricing
    promo_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Promotional price in cents")
    )
    promo_valid_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When promotional pricing expires")
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this price is available")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'product_prices'
        verbose_name = _('Product Price')
        verbose_name_plural = _('Product Prices')
        unique_together = [['product', 'currency', 'billing_period']]
        ordering = ['billing_period', 'amount_cents']
        indexes = [
            models.Index(fields=['currency', 'billing_period']),
            models.Index(fields=['is_active']),
        ]

    @property
    def amount(self) -> Decimal:
        """Return amount in currency units (e.g., 29.99)"""
        return Decimal(self.amount_cents) / 100

    @property
    def setup_fee(self) -> Decimal:
        """Return setup fee in currency units"""
        return Decimal(self.setup_cents) / 100

    @property
    def effective_price_cents(self) -> int:
        """Get effective price considering promotions"""
        if (self.promo_price_cents and
            self.promo_valid_until and
            timezone.now() <= self.promo_valid_until):
            return self.promo_price_cents
        return self.amount_cents

    @property
    def effective_price(self) -> Decimal:
        """Get effective price in currency units"""
        return Decimal(self.effective_price_cents) / 100

    def __str__(self) -> str:
        return f"{self.product.name} - {self.currency.code} {self.amount} {self.billing_period}"


class ProductRelationship(models.Model):
    """
    Define relationships between products for upsells, requirements, bundles, etc.
    Enables complex product catalog relationships.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Product relationships
    source_product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='relationships_from'
    )
    target_product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='relationships_to'
    )

    # Relationship types
    RELATIONSHIP_TYPES = [
        ('requires', _('Requires')),              # Source requires target
        ('includes', _('Includes')),              # Source includes target
        ('upgrades_to', _('Can Upgrade To')),     # Source can upgrade to target
        ('cross_sell', _('Cross-sell')),          # Suggest target with source
        ('upsell', _('Upsell')),                  # Higher-tier alternative
        ('downsell', _('Downsell')),              # Lower-tier alternative
        ('incompatible', _('Incompatible With')), # Cannot be ordered together
        ('replaces', _('Replaces')),              # Source replaces target
    ]
    relationship_type = models.CharField(
        max_length=20,
        choices=RELATIONSHIP_TYPES,
        help_text=_("Type of relationship between products")
    )

    # Optional configuration
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Relationship-specific configuration")
    )

    # Ordering and priority
    sort_order = models.PositiveIntegerField(
        default=0,
        help_text=_("Display order for relationships of same type")
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this relationship is active")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'product_relationships'
        verbose_name = _('Product Relationship')
        verbose_name_plural = _('Product Relationships')
        unique_together = [['source_product', 'target_product', 'relationship_type']]
        ordering = ['sort_order', 'created_at']
        indexes = [
            models.Index(fields=['source_product', 'relationship_type']),
            models.Index(fields=['target_product', 'relationship_type']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.source_product.name} {self.get_relationship_type_display()} {self.target_product.name}"


class ProductBundle(models.Model):
    """
    Product bundles - collections of products sold together at a discount.
    Useful for hosting packages that include multiple services.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Basic information
    name = models.CharField(
        max_length=200,
        help_text=_("Bundle name")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Bundle description")
    )

    # Status
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether bundle is available")
    )

    # Discount configuration
    discount_type = models.CharField(
        max_length=20,
        choices=[
            ('percent', _('Percentage Discount')),
            ('fixed', _('Fixed Amount Discount')),
            ('override', _('Override Total Price')),
        ],
        default='percent'
    )
    discount_value = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_("Discount percentage or fixed amount")
    )

    # Metadata
    meta = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'product_bundles'
        verbose_name = _('Product Bundle')
        verbose_name_plural = _('Product Bundles')
        ordering = ['name']

    def __str__(self) -> str:
        return self.name


class ProductBundleItem(models.Model):
    """
    Individual products within a bundle with specific quantities and pricing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Bundle relationship
    bundle = models.ForeignKey(
        ProductBundle,
        on_delete=models.CASCADE,
        related_name='items'
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='bundle_items'
    )

    # Quantity and configuration
    quantity = models.PositiveIntegerField(
        default=1,
        help_text=_("Quantity of this product in the bundle")
    )

    # Optional price override
    override_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Override price for this product in bundle (in cents)")
    )

    # Configuration
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Product configuration within bundle")
    )

    # Optional requirement
    is_required = models.BooleanField(
        default=True,
        help_text=_("Whether this product is required in the bundle")
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'product_bundle_items'
        verbose_name = _('Product Bundle Item')
        verbose_name_plural = _('Product Bundle Items')
        unique_together = [['bundle', 'product']]
        ordering = ['created_at']

    @property
    def override_price(self) -> Optional[Decimal]:
        """Return override price in currency units"""
        if self.override_price_cents:
            return Decimal(self.override_price_cents) / 100
        return None

    def __str__(self) -> str:
        return f"{self.bundle.name} - {self.product.name} x{self.quantity}"
