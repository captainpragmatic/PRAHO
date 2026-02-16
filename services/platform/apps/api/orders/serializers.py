"""
Order API Serializers for PRAHO Platform
DRF serializers for order and product catalog endpoints with Romanian compliance.
"""

import logging

from rest_framework import serializers

from apps.orders.models import Order, OrderItem
from apps.orders.price_sealing import create_sealed_price_for_product_price
from apps.products.models import Product, ProductPrice


class ProductPriceSerializer(serializers.ModelSerializer):
    """Slim pricing info for product lists with sealed price tokens (Simplified Model)"""

    monthly_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    semiannual_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    annual_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    setup_fee = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    has_semiannual_discount = serializers.BooleanField(read_only=True)
    has_annual_discount = serializers.BooleanField(read_only=True)
    sealed_price_token = serializers.SerializerMethodField()

    class Meta:
        model = ProductPrice
        fields = [
            "id",
            "monthly_price",
            "semiannual_price",
            "annual_price",
            "setup_fee",
            "has_semiannual_discount",
            "has_annual_discount",
            "is_active",
            "sealed_price_token",
        ]

    def get_sealed_price_token(self, obj: ProductPrice) -> dict[str, str]:
        """🔒 Generate sealed price tokens for all billing periods"""
        logger = logging.getLogger(__name__)

        try:
            # Get client IP from request context
            request = self.context.get("request")
            if not request:
                logger.warning("🚨 [Sealing] No request context available for sealed price tokens")
                return None

            from apps.orders.price_sealing import get_client_ip

            client_ip = get_client_ip(request)

            # Generate tokens for all billing periods
            tokens = {}
            for period in ["monthly", "semiannual", "annual"]:
                try:
                    token = create_sealed_price_for_product_price(obj, client_ip, period)
                    tokens[period] = token
                except Exception as e:
                    # If individual period fails, skip it but continue with others
                    logger.warning(f"🚨 [Sealing] Failed to create token for {period}: {e}")
                    tokens[period] = None

            return tokens
        except Exception as e:
            # If sealing fails completely, return None
            logger.error(f"🔥 [Sealing] Complete failure in sealed price token generation: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return None


class ProductListSerializer(serializers.ModelSerializer):
    """Slim product info for catalog listing"""

    prices = ProductPriceSerializer(many=True, read_only=True)
    product_type_display = serializers.CharField(source="get_product_type_display", read_only=True)

    class Meta:
        model = Product
        fields = [
            "id",
            "slug",
            "name",
            "short_description",
            "product_type",
            "product_type_display",
            "is_featured",
            "requires_domain",
            "is_active",
            "prices",
        ]


class ProductDetailSerializer(serializers.ModelSerializer):
    """Full product info for detail view"""

    prices = ProductPriceSerializer(many=True, read_only=True)
    product_type_display = serializers.CharField(source="get_product_type_display", read_only=True)

    class Meta:
        model = Product
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "short_description",
            "product_type",
            "product_type_display",
            "is_featured",
            "requires_domain",
            "domain_required_at_signup",
            "is_active",
            "prices",
            "meta_title",
            "meta_description",
            "tags",
            "meta",
        ]


class OrderItemSerializer(serializers.ModelSerializer):
    """Order item with pricing snapshot for API responses"""

    unit_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    setup_fee = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    line_total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = OrderItem
        fields = [
            "id",
            "product_name",
            "product_type",
            "quantity",
            "unit_price",
            "setup_fee",
            "tax_rate",
            "tax_amount",
            "subtotal",
            "line_total",
            "domain_name",
            "config",
            "provisioning_status",
        ]


class OrderListSerializer(serializers.ModelSerializer):
    """Slim order info for customer order history"""

    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    currency_code = serializers.CharField(source="currency.code", read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "order_number",
            "status",
            "status_display",
            "subtotal",
            "tax_amount",
            "total",
            "currency_code",
            "created_at",
            "updated_at",
            "completed_at",
        ]


class OrderDetailSerializer(serializers.ModelSerializer):
    """Full order details with items and VAT breakdown"""

    items = OrderItemSerializer(many=True, read_only=True)
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    currency_code = serializers.CharField(source="currency.code", read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "order_number",
            "status",
            "status_display",
            "subtotal",
            "tax_amount",
            "total",
            "currency_code",
            "customer_name",
            "customer_email",
            "customer_company",
            "billing_address",
            "payment_method",
            "notes",
            "created_at",
            "updated_at",
            "completed_at",
            "items",
        ]


# Input Serializers for Order Creation and Calculation


class CartItemInputSerializer(serializers.Serializer):
    """Input serializer for cart items in calculations and order creation (Simplified Model)"""

    product_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, max_value=50)
    billing_period = serializers.ChoiceField(
        choices=[("monthly", "Monthly"), ("semiannual", "Semi-Annual"), ("annual", "Annual")],
        help_text="Simplified billing periods: monthly, semiannual, annual",
    )
    config = serializers.JSONField(default=dict, required=False)
    domain_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    sealed_price_token = serializers.CharField(
        max_length=2000, required=False, allow_blank=True, help_text="🔒 Sealed price token for price validation"
    )


class CartCalculationInputSerializer(serializers.Serializer):
    """Input serializer for cart total calculations"""

    customer_id = serializers.IntegerField()
    currency = serializers.CharField(max_length=3, default="RON")
    items = CartItemInputSerializer(many=True)


class CartCalculationOutputSerializer(serializers.Serializer):
    """Output serializer for cart calculations with Romanian VAT"""

    subtotal_cents = serializers.IntegerField()
    tax_cents = serializers.IntegerField()
    total_cents = serializers.IntegerField()
    currency = serializers.CharField(max_length=3)
    warnings = serializers.ListField(child=serializers.DictField(), default=list)

    # Individual item calculations
    items = serializers.ListField(child=serializers.DictField(), default=list)


class OrderCreateInputSerializer(serializers.Serializer):
    """Input serializer for order creation"""

    customer_id = serializers.IntegerField()
    currency = serializers.CharField(max_length=3, default="RON")
    items = CartItemInputSerializer(many=True)
    notes = serializers.CharField(max_length=500, required=False, allow_blank=True)
    status = serializers.CharField(max_length=20, default="draft")
    source = serializers.CharField(max_length=50, default="api")
    meta = serializers.JSONField(default=dict, required=False)


class PriceWarningSerializer(serializers.Serializer):
    """Serializer for price change warnings"""

    type = serializers.CharField()
    product_name = serializers.CharField()
    message = serializers.CharField()
    old_price = serializers.CharField(required=False)
    new_price = serializers.CharField(required=False)
