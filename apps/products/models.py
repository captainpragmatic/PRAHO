"""
Product Catalog models for PRAHO Platform
Defines the master catalog of products and services that customers can order.
Includes pricing, relationships, and configuration for Romanian hosting provider.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

# Security constants
MAX_JSON_CONTENT_SIZE = 10000  # Maximum size for JSON content
MAX_JSON_DEPTH = 10  # Maximum JSON nesting depth
MAX_PRICE_CENTS = 100_000_000  # Maximum price in cents (1M major units)


# ===============================================================================
# SECURITY VALIDATION FUNCTIONS
# ===============================================================================


def validate_json_field(data: Any, field_name: str = "JSON field") -> None:
    """🔒 Validate JSON field data for security"""
    if data is None:
        return

    # Size limit check - stricter for model fields, relaxed for general validation
    data_str = str(data)
    # General size guard to prevent DoS via oversized JSON blobs
    # Apply only to simple "single large value" payloads to allow legitimate nested structures
    if isinstance(data, dict) and len(data) == 1:
        only_value = next(iter(data.values()))
        if isinstance(only_value, str) and len(only_value) > MAX_JSON_CONTENT_SIZE:
            raise ValidationError("JSON content too large")
    # Apply tighter limit for known model-bound fields to prevent bloat
    model_bound_fields = {"tags", "meta", "module_config"}
    if field_name in model_bound_fields and len(data_str) > MAX_JSON_CONTENT_SIZE:
        raise ValidationError(f"{field_name} too large")

    # Depth check
    _get_json_depth(data)

    # Check for dangerous keys and patterns in JSON
    if isinstance(data, dict):
        # Check for dangerous keys
        dangerous_keys = ["eval", "import", "subprocess", "exec", "__import__"]
        for key in data:
            if key in dangerous_keys:
                raise ValidationError(f"Dangerous key '{key}' in JSON data")

        # Check for dangerous patterns in values
        for key, value in data.items():
            if isinstance(value, str) and any(
                pattern in value.lower()
                for pattern in ["<script", "javascript:", "eval('", "alert(", "__import__", "subprocess."]
            ):
                raise ValidationError(f"Dangerous pattern in JSON value for key '{key}'")

    # Also run recursive security checks to cover nested structures
    _check_json_security(data, field_name)


def _get_json_depth(obj: Any, depth: int = 0) -> int:
    """Helper function to calculate JSON depth"""
    if depth > MAX_JSON_DEPTH:
        raise ValidationError("JSON data too deep")

    max_depth = depth
    if isinstance(obj, dict):
        for value in obj.values():
            max_depth = max(max_depth, _get_json_depth(value, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            max_depth = max(max_depth, _get_json_depth(item, depth + 1))

    return max_depth


def _check_json_security(data: Any, field_name: str = "JSON field") -> None:
    """Recursively check JSON data for security issues and raise on problems"""
    if isinstance(data, dict):
        dangerous_keys = ["eval", "import", "subprocess", "exec", "__import__"]
        for key in data:
            if key in dangerous_keys:
                raise ValidationError(f"Dangerous key '{key}' in {field_name}")
        for key, value in data.items():
            if isinstance(value, str):
                lowered = value.lower()
                patterns = ["<script", "javascript:", "eval(", "alert(", "__import__", "subprocess."]
                if any(p in lowered for p in patterns):
                    raise ValidationError(f"Dangerous pattern in {field_name} for key '{key}'")
            else:
                _check_json_security(value, field_name)
    elif isinstance(data, list):
        for item in data:
            _check_json_security(item, field_name)


def validate_product_config(config: Any) -> None:
    """🔒 Validate product configuration"""
    if config is None:
        return

    validate_json_field(config)

    # Check for dangerous keys
    if isinstance(config, dict):
        dangerous_keys = ["__builtins__", "eval", "exec", "import", "password", "secret", "token", "api_key"]
        sensitive_key_patterns = [
            "password",
            "api_key",
            "private_token",
            "admin_pass",
            "mysql_password",
            "secret_key",
            "auth_token",
            "credential",
        ]

        for key in config:
            # Check exact dangerous keys
            if key in dangerous_keys:
                raise ValidationError(f"Dangerous key '{key}' in product config")

            # Check sensitive key patterns
            if any(pattern in key.lower() for pattern in sensitive_key_patterns):
                raise ValidationError(f"Sensitive key '{key}' in product config")

        # Check for dangerous patterns in values
        for key, value in config.items():
            if isinstance(value, str):
                dangerous_patterns = [
                    "<script",
                    "javascript:",
                    "eval('",
                    'eval("',
                    "exec('",
                    'exec("',
                    "os.system(",
                    "__import__(",
                    "subprocess.",
                    "alert(",
                    "data:text/html",
                    "rm -rf",
                    "DROP TABLE",
                    "DELETE FROM",
                ]
                if any(pattern in value.lower() for pattern in dangerous_patterns):
                    raise ValidationError(f"Dangerous pattern in config value for key '{key}'")


def validate_text_field_length(text: str | None, field_name: str, max_length: int = 1000) -> None:
    """🔒 Validate text field length (signature matches tests)"""
    if not text:
        return
    if len(text) > int(max_length):
        raise ValidationError(f"{field_name} too long (max {max_length} characters)")


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
    slug = models.SlugField(unique=True, max_length=100, help_text=_("URL-friendly identifier"))
    name = models.CharField(max_length=200, help_text=_("Display name for customers"))
    description = models.TextField(blank=True, help_text=_("Detailed product description"))
    short_description = models.CharField(max_length=500, blank=True, help_text=_("Brief description for listings"))

    # Product categorization
    PRODUCT_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("shared_hosting", _("Shared Hosting")),
        ("vps", _("VPS")),
        ("dedicated", _("Dedicated Server")),
        ("domain", _("Domain Registration")),
        ("ssl", _("SSL Certificate")),
        ("email", _("Email Hosting")),
        ("backup", _("Backup Service")),
        ("addon", _("Add-on Service")),
        ("license", _("Software License")),
        ("support", _("Support Package")),
    )
    product_type = models.CharField(max_length=30, choices=PRODUCT_TYPES, help_text=_("Product category"))

    # Module configuration for provisioning
    module = models.CharField(
        max_length=50, blank=True, help_text=_("Provisioning module name (e.g., 'cpanel', 'plesk', 'virtualmin')")
    )
    module_config = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Module-specific configuration for provisioning"),
        validators=[validate_product_config],
    )

    # Status and availability
    is_active = models.BooleanField(default=True, help_text=_("Whether product is available for purchase"))
    is_featured = models.BooleanField(default=False, help_text=_("Show prominently on website"))
    is_public = models.BooleanField(default=True, help_text=_("Visible on public website"))

    # Requirements and constraints
    requires_domain = models.BooleanField(default=False, help_text=_("Customer must provide a domain"))
    domain_required_at_signup = models.BooleanField(default=False, help_text=_("Domain must be specified during order"))

    # Display and ordering
    sort_order = models.PositiveIntegerField(default=0, help_text=_("Display order (lower numbers first)"))

    # SEO and metadata
    meta_title = models.CharField(max_length=255, blank=True)
    meta_description = models.TextField(blank=True)

    # Tags - using JSONField for SQLite compatibility
    tags = models.JSONField(
        default=list,
        blank=True,
        help_text="Tags for filtering and search (as JSON array)",
        validators=[validate_json_field],
    )

    # Romanian specific
    includes_vat = models.BooleanField(default=False, help_text=_("Whether displayed prices include VAT"))

    # Additional metadata
    meta = models.JSONField(
        default=dict, blank=True, help_text=_("Additional product metadata"), validators=[validate_json_field]
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Private attributes for signal handling
    _old_is_active: bool | None = None
    _old_is_public: bool | None = None
    _old_is_featured: bool | None = None
    _old_includes_vat: bool | None = None
    _old_product_type: str | None = None

    class Meta:
        db_table = "products"
        verbose_name = _("Product")
        verbose_name_plural = _("Products")
        ordering: ClassVar[tuple[str, ...]] = ("sort_order", "name")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["slug"]),
            models.Index(fields=["product_type", "is_active"]),
            models.Index(fields=["is_active", "is_public"]),
            models.Index(fields=["sort_order"]),
        )

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        """🔒 Validate model fields for security"""
        super().clean()

        # Validate text field lengths
        validate_text_field_length(self.description, "description", 10000)
        validate_text_field_length(self.short_description, "short_description", 1000)
        validate_text_field_length(self.meta_title, "meta_title", 500)
        validate_text_field_length(self.meta_description, "meta_description", 2000)

        # Explicitly validate JSON fields (field validators aren't always called from clean())
        validate_product_config(self.module_config)
        validate_json_field(self.tags, "tags")
        validate_json_field(self.meta, "meta")

        # Log security validation for tests
        logger.info(
            "🔒 [Products] product_validation",
            extra={
                "event": "product_validation",
                "model": "Product",
                "slug": getattr(self, "slug", None),
            },
        )

    def get_active_prices(self) -> QuerySet[ProductPrice]:
        """Get all active prices for this product"""
        return self.prices.filter(is_active=True)

    def get_price_for_period(self, currency_code: str, billing_period: str) -> ProductPrice | None:
        """Get price for specific currency and billing period"""
        try:
            return self.prices.get(currency__code=currency_code, billing_period=billing_period, is_active=True)
        except ProductPrice.DoesNotExist:
            return None


class ProductPrice(models.Model):
    """
    Multi-currency, multi-period pricing for products.
    Supports one-time and recurring billing with Romanian specifics.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Product relationship
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="prices")

    # Currency
    currency = models.ForeignKey("billing.Currency", on_delete=models.PROTECT, help_text=_("Currency for this price"))

    # Billing configuration
    BILLING_PERIODS: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("once", _("One Time")),
        ("monthly", _("Monthly")),
        ("quarterly", _("Quarterly")),
        ("semiannual", _("Semi-Annual")),
        ("annual", _("Annual")),
        ("biennial", _("Biennial")),
        ("triennial", _("Triennial")),
    )
    billing_period = models.CharField(max_length=20, choices=BILLING_PERIODS, help_text=_("Billing frequency"))

    # Pricing in cents to avoid float precision issues
    amount_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Recurring price in cents (e.g., 2999 for 29.99 RON)")
    )
    setup_cents = models.BigIntegerField(
        default=0, validators=[MinValueValidator(0)], help_text=_("One-time setup fee in cents")
    )

    # Optional pricing features
    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("0.00"),
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Percentage discount (0-100)"),
    )

    # Minimum commitment
    minimum_quantity = models.PositiveIntegerField(default=1, help_text=_("Minimum quantity that can be ordered"))
    maximum_quantity = models.PositiveIntegerField(
        null=True, blank=True, help_text=_("Maximum quantity (blank for unlimited)")
    )

    # Promotional pricing
    promo_price_cents = models.BigIntegerField(
        null=True, blank=True, validators=[MinValueValidator(0)], help_text=_("Promotional price in cents")
    )
    promo_valid_until = models.DateTimeField(null=True, blank=True, help_text=_("When promotional pricing expires"))

    # Status
    is_active = models.BooleanField(default=True, help_text=_("Whether this price is available"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "product_prices"
        verbose_name = _("Product Price")
        verbose_name_plural = _("Product Prices")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("product", "currency", "billing_period"),)
        ordering: ClassVar[tuple[str, ...]] = ("billing_period", "amount_cents")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["currency", "billing_period"]),
            models.Index(fields=["is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.product.name} - {self.currency.code} {self.amount} {self.billing_period}"

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
        if self.promo_price_cents and self.promo_valid_until and timezone.now() <= self.promo_valid_until:
            return self.promo_price_cents
        return self.amount_cents

    @property
    def effective_price(self) -> Decimal:
        """Get effective price in currency units"""
        return Decimal(self.effective_price_cents) / 100

    def clean(self) -> None:
        """🔒 Validate pricing constraints and log security validation"""
        super().clean()

        # Amount constraints
        if self.amount_cents is None or int(self.amount_cents) < 0:
            raise ValidationError("Amount cannot be negative")

        # Reject unrealistic prices (> 1,000,000.00 in major units)
        if int(self.amount_cents) > MAX_PRICE_CENTS:
            raise ValidationError("Amount too large")

        # Discount range 0..100
        if self.discount_percent is not None:
            try:
                dp = Decimal(self.discount_percent)
            except Exception as e:
                raise ValidationError("Invalid discount percent") from e
            if dp < Decimal("0") or dp > Decimal("100"):
                raise ValidationError("Invalid discount percent")

        # Quantity limits
        if self.minimum_quantity is not None and int(self.minimum_quantity) < 1:
            raise ValidationError("Minimum quantity must be at least 1")
        if (
            self.maximum_quantity is not None
            and self.minimum_quantity is not None
            and int(self.maximum_quantity) < int(self.minimum_quantity)
        ):
            raise ValidationError("Maximum quantity cannot be less than minimum quantity")

        # Promo pricing requirements
        if self.promo_price_cents is not None:
            if not self.promo_valid_until:
                raise ValidationError("Promo valid until is required when promo price is set")
            if timezone.now() > self.promo_valid_until:
                raise ValidationError("Promo valid until must be in the future")

        # Security validation logging for tests (avoid touching relations before set)
        logger.info(
            "🔒 [Products] product_price_validation",
            extra={
                "event": "product_price_validation",
                "model": "ProductPrice",
                "product_id": getattr(self, "product_id", None),
                "currency": getattr(self, "currency_id", None),
            },
        )


class ProductRelationship(models.Model):
    """
    Define relationships between products for upsells, requirements, bundles, etc.
    Enables complex product catalog relationships.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Product relationships
    source_product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="relationships_from")
    target_product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="relationships_to")

    # Relationship types
    RELATIONSHIP_TYPES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("requires", _("Requires")),  # Source requires target
        ("includes", _("Includes")),  # Source includes target
        ("upgrades_to", _("Can Upgrade To")),  # Source can upgrade to target
        ("cross_sell", _("Cross-sell")),  # Suggest target with source
        ("upsell", _("Upsell")),  # Higher-tier alternative
        ("downsell", _("Downsell")),  # Lower-tier alternative
        ("incompatible", _("Incompatible With")),  # Cannot be ordered together
        ("replaces", _("Replaces")),  # Source replaces target
    )
    relationship_type = models.CharField(
        max_length=20, choices=RELATIONSHIP_TYPES, help_text=_("Type of relationship between products")
    )

    # Optional configuration
    config = models.JSONField(
        default=dict, blank=True, help_text=_("Relationship-specific configuration"), validators=[validate_json_field]
    )

    # Ordering and priority
    sort_order = models.PositiveIntegerField(default=0, help_text=_("Display order for relationships of same type"))

    # Status
    is_active = models.BooleanField(default=True, help_text=_("Whether this relationship is active"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "product_relationships"
        verbose_name = _("Product Relationship")
        verbose_name_plural = _("Product Relationships")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (
            ("source_product", "target_product", "relationship_type"),
        )
        ordering: ClassVar[tuple[str, ...]] = ("sort_order", "created_at")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["source_product", "relationship_type"]),
            models.Index(fields=["target_product", "relationship_type"]),
            models.Index(fields=["is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.source_product.name} {self.get_relationship_type_display()} {self.target_product.name}"


class ProductBundle(models.Model):
    """
    Product bundles - collections of products sold together at a discount.
    Useful for hosting packages that include multiple services.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Basic information
    name = models.CharField(max_length=200, help_text=_("Bundle name"))
    description = models.TextField(blank=True, help_text=_("Bundle description"))

    # Status
    is_active = models.BooleanField(default=True, help_text=_("Whether bundle is available"))

    # Discount configuration
    discount_type = models.CharField(
        max_length=20,
        choices=[
            ("percent", _("Percentage Discount")),
            ("fixed", _("Fixed Amount Discount")),
            ("override", _("Override Total Price")),
        ],
        default="percent",
    )
    discount_value = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal("0.00"), help_text=_("Discount percentage or fixed amount")
    )

    # Metadata
    meta = models.JSONField(default=dict, blank=True, validators=[validate_json_field])

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "product_bundles"
        verbose_name = _("Product Bundle")
        verbose_name_plural = _("Product Bundles")
        ordering: ClassVar[tuple[str, ...]] = ("name",)

    def __str__(self) -> str:
        return self.name


class ProductBundleItem(models.Model):
    """
    Individual products within a bundle with specific quantities and pricing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Bundle relationship
    bundle = models.ForeignKey(ProductBundle, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="bundle_items")

    # Quantity and configuration
    quantity = models.PositiveIntegerField(default=1, help_text=_("Quantity of this product in the bundle"))

    # Optional price override
    override_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Override price for this product in bundle (in cents)"),
    )

    # Configuration
    config = models.JSONField(
        default=dict, blank=True, help_text=_("Product configuration within bundle"), validators=[validate_json_field]
    )

    # Optional requirement
    is_required = models.BooleanField(default=True, help_text=_("Whether this product is required in the bundle"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "product_bundle_items"
        verbose_name = _("Product Bundle Item")
        verbose_name_plural = _("Product Bundle Items")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("bundle", "product"),)
        ordering: ClassVar[tuple[str, ...]] = ("created_at",)

    def __str__(self) -> str:
        return f"{self.bundle.name} - {self.product.name} x{self.quantity}"

    @property
    def override_price(self) -> Decimal | None:
        """Return override price in currency units"""
        if self.override_price_cents:
            return Decimal(self.override_price_cents) / 100
        return None
