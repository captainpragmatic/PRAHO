"""
Order API Serializers for PRAHO Platform
DRF serializers for order and product catalog endpoints with Romanian compliance.
"""

from decimal import Decimal
from rest_framework import serializers
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.products.models import Product, ProductPrice
from apps.orders.price_sealing import create_sealed_price_for_product_price


class ProductPriceSerializer(serializers.ModelSerializer):
    """Slim pricing info for product lists with sealed price tokens"""
    
    effective_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    billing_period_display = serializers.CharField(source='get_billing_period_display', read_only=True)
    setup_fee = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    sealed_price_token = serializers.SerializerMethodField()
    
    class Meta:
        model = ProductPrice
        fields = [
            'id', 'billing_period', 'billing_period_display', 
            'effective_price', 'setup_fee', 'is_active', 'sealed_price_token'
        ]
    
    def get_sealed_price_token(self, obj):
        """🔒 Generate sealed price token to prevent price manipulation"""
        try:
            # Get client IP from request context
            request = self.context.get('request')
            if not request:
                return None
                
            from apps.orders.price_sealing import get_client_ip
            client_ip = get_client_ip(request)
            
            return create_sealed_price_for_product_price(obj, client_ip)
        except Exception:
            # If sealing fails, don't expose the error - just return None
            # The order creation will fail safely if no sealed token provided
            return None


class ProductListSerializer(serializers.ModelSerializer):
    """Slim product info for catalog listing"""
    
    prices = ProductPriceSerializer(many=True, read_only=True)
    product_type_display = serializers.CharField(source='get_product_type_display', read_only=True)
    
    class Meta:
        model = Product
        fields = [
            'id', 'slug', 'name', 'short_description', 
            'product_type', 'product_type_display', 'is_featured',
            'requires_domain', 'is_active', 'prices'
        ]


class ProductDetailSerializer(serializers.ModelSerializer):
    """Full product info for detail view"""
    
    prices = ProductPriceSerializer(many=True, read_only=True)
    product_type_display = serializers.CharField(source='get_product_type_display', read_only=True)
    
    class Meta:
        model = Product
        fields = [
            'id', 'slug', 'name', 'description', 'short_description',
            'product_type', 'product_type_display', 'is_featured',
            'requires_domain', 'domain_required_at_signup', 'is_active', 'prices',
            'meta_title', 'meta_description', 'tags', 'meta'
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
            'id', 'product_name', 'product_type', 'quantity', 'billing_period',
            'unit_price', 'setup_fee', 'tax_rate', 'tax_amount', 'subtotal',
            'line_total', 'domain_name', 'config', 'provisioning_status'
        ]


class OrderListSerializer(serializers.ModelSerializer):
    """Slim order info for customer order history"""
    
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    currency_code = serializers.CharField(source='currency.code', read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'order_number', 'status', 'status_display',
            'subtotal', 'tax_amount', 'total', 'currency_code',
            'created_at', 'updated_at', 'completed_at'
        ]


class OrderDetailSerializer(serializers.ModelSerializer):
    """Full order details with items and VAT breakdown"""
    
    items = OrderItemSerializer(many=True, read_only=True)
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    currency_code = serializers.CharField(source='currency.code', read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'order_number', 'status', 'status_display',
            'subtotal', 'tax_amount', 'total', 'currency_code',
            'customer_name', 'customer_email', 'customer_company',
            'billing_address', 'payment_method', 'notes',
            'created_at', 'updated_at', 'completed_at', 'items'
        ]


# Input Serializers for Order Creation and Calculation

class CartItemInputSerializer(serializers.Serializer):
    """Input serializer for cart items in calculations and order creation"""
    
    product_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, max_value=50)
    billing_period = serializers.CharField(max_length=20)
    config = serializers.JSONField(default=dict, required=False)
    domain_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    sealed_price_token = serializers.CharField(max_length=2000, required=False, allow_blank=True,
                                               help_text="🔒 Sealed price token for price validation")


class CartCalculationInputSerializer(serializers.Serializer):
    """Input serializer for cart total calculations"""
    
    customer_id = serializers.UUIDField()
    currency = serializers.CharField(max_length=3, default='RON')
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
    
    customer_id = serializers.UUIDField()
    currency = serializers.CharField(max_length=3, default='RON')
    items = CartItemInputSerializer(many=True)
    notes = serializers.CharField(max_length=500, required=False, allow_blank=True)
    status = serializers.CharField(max_length=20, default='draft')
    source = serializers.CharField(max_length=50, default='api')
    meta = serializers.JSONField(default=dict, required=False)


class PriceWarningSerializer(serializers.Serializer):
    """Serializer for price change warnings"""
    
    type = serializers.CharField()
    product_name = serializers.CharField()
    message = serializers.CharField()
    old_price = serializers.CharField(required=False)
    new_price = serializers.CharField(required=False)