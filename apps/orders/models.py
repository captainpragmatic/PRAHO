"""
Order Management models for PRAHO Platform
Handles the complete order lifecycle from cart to provisioning.
Romanian hosting provider specific order processing and configuration.
"""

import uuid
from decimal import Decimal
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator
from django.utils import timezone


# ===============================================================================
# ORDER MANAGEMENT MODELS
# ===============================================================================

class Order(models.Model):
    """
    Customer order for products/services.
    Tracks the entire lifecycle from cart to provisioning.
    Romanian compliance and VAT handling included.
    """
    
    # Use UUID for better security and external references
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Order identification
    order_number = models.CharField(
        max_length=50,
        unique=True,
        help_text=_("Human-readable order number")
    )
    
    # Customer relationship
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.PROTECT,
        related_name='orders'
    )
    
    # Order status workflow
    STATUS_CHOICES = [
        ('draft', _('Draft')),             # Cart/Quote stage - can be modified
        ('pending', _('Pending')),         # Awaiting payment
        ('processing', _('Processing')),   # Payment received, provisioning in progress
        ('completed', _('Completed')),     # Fully provisioned and delivered
        ('cancelled', _('Cancelled')),     # Cancelled by customer or admin
        ('failed', _('Failed')),           # Payment or provisioning failed
        ('refunded', _('Refunded')),       # Order was refunded
        ('partially_refunded', _('Partially Refunded')),  # Partial refund processed
    ]
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES,
        default='draft',
        help_text=_("Current order status")
    )
    
    # Financial information
    currency = models.ForeignKey(
        'billing.Currency',
        on_delete=models.PROTECT,
        help_text=_("Order currency")
    )
    exchange_to_ron = models.DecimalField(
        max_digits=18,
        decimal_places=6,
        null=True,
        blank=True,
        help_text=_("Exchange rate to RON at time of order")
    )
    
    # Amounts in cents for precision
    subtotal_cents = models.BigIntegerField(
        default=0,
        help_text=_("Subtotal before tax in cents")
    )
    tax_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total tax amount in cents")
    )
    discount_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total discount amount in cents")
    )
    total_cents = models.BigIntegerField(
        default=0,
        help_text=_("Final total amount in cents")
    )
    
    # Customer information snapshot (for billing)
    customer_email = models.EmailField(
        help_text=_("Customer email at time of order")
    )
    customer_name = models.CharField(
        max_length=255,
        help_text=_("Customer name at time of order")
    )
    customer_company = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Company name if business customer")
    )
    customer_vat_id = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("VAT ID for Romanian compliance")
    )
    
    # Billing address snapshot
    billing_address = models.JSONField(
        default=dict,
        help_text=_("Billing address snapshot")
    )
    
    # Payment processing
    payment_method = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('card', _('Credit/Debit Card')),
            ('bank_transfer', _('Bank Transfer')),
            ('paypal', _('PayPal')),
            ('crypto', _('Cryptocurrency')),
            ('wallet', _('Account Credit')),
            ('manual', _('Manual Payment')),
        ],
        help_text=_("Payment method used")
    )
    transaction_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Payment gateway transaction ID")
    )
    gateway_response = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Payment gateway response data")
    )
    
    # Source tracking
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=_("Customer IP address")
    )
    user_agent = models.TextField(
        blank=True,
        help_text=_("Customer browser user agent")
    )
    referrer = models.URLField(
        blank=True,
        help_text=_("Referrer URL")
    )
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)
    
    # Administrative
    notes = models.TextField(
        blank=True,
        help_text=_("Internal order notes")
    )
    customer_notes = models.TextField(
        blank=True,
        help_text=_("Notes from customer")
    )
    
    # Invoice relationship
    invoice = models.ForeignKey(
        'billing.Invoice',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='orders',
        help_text=_("Generated invoice for this order")
    )
    
    # Metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional order metadata")
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When order was completed")
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When draft order expires")
    )
    
    class Meta:
        db_table = 'orders'
        verbose_name = _('Order')
        verbose_name_plural = _('Orders')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['customer', '-created_at']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['order_number']),
            models.Index(fields=['customer_email']),
            models.Index(fields=['-created_at']),
        ]
    
    @property
    def subtotal(self):
        """Return subtotal in currency units"""
        return Decimal(self.subtotal_cents) / 100
    
    @property
    def tax_amount(self):
        """Return tax amount in currency units"""
        return Decimal(self.tax_cents) / 100
    
    @property
    def discount_amount(self):
        """Return discount amount in currency units"""
        return Decimal(self.discount_cents) / 100
    
    @property
    def total(self):
        """Return total in currency units"""
        return Decimal(self.total_cents) / 100
    
    @property
    def is_draft(self):
        """Check if order is still in draft state"""
        return self.status == 'draft'
    
    @property
    def is_paid(self):
        """Check if order has been paid"""
        return self.status in ['processing', 'completed']
    
    @property
    def can_be_cancelled(self):
        """Check if order can be cancelled"""
        return self.status in ['draft', 'pending']
    
    def calculate_totals(self):
        """
        Recalculate order totals from line items.
        Should be called after adding/removing/updating items.
        """
        items = self.items.all()
        
        # Calculate subtotal from all items
        self.subtotal_cents = sum(
            item.quantity * item.unit_price_cents + item.setup_cents 
            for item in items
        )
        
        # Calculate total tax
        self.tax_cents = sum(item.tax_cents for item in items)
        
        # Apply any order-level discounts
        # (item-level discounts are already included in their unit prices)
        
        # Calculate final total
        self.total_cents = self.subtotal_cents + self.tax_cents - self.discount_cents
        
        # Ensure total is not negative
        self.total_cents = max(0, self.total_cents)
        
        self.save(update_fields=[
            'subtotal_cents', 
            'tax_cents', 
            'total_cents'
        ])
    
    def mark_as_completed(self):
        """Mark order as completed and set completion timestamp"""
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at'])
    
    def generate_order_number(self):
        """Generate a unique order number"""
        if not self.order_number:
            # Format: ORD-YYYYMMDD-XXXXXX
            date_part = timezone.now().strftime('%Y%m%d')
            # Get last order number for today
            today_orders = Order.objects.filter(
                created_at__date=timezone.now().date(),
                order_number__isnull=False
            ).count()
            sequence = str(today_orders + 1).zfill(6)
            self.order_number = f"ORD-{date_part}-{sequence}"
    
    def save(self, *args, **kwargs):
        """Auto-generate order number before saving"""
        if not self.order_number:
            self.generate_order_number()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Order {self.order_number} - {self.customer_email}"


class OrderItem(models.Model):
    """
    Individual line item in an order.
    Links to product and stores pricing/configuration snapshot.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Order relationship
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name='items'
    )
    
    # Product relationship
    product = models.ForeignKey(
        'products.Product',
        on_delete=models.PROTECT,
        help_text=_("Product being ordered")
    )
    
    # Product information snapshot (in case product changes)
    product_name = models.CharField(
        max_length=200,
        help_text=_("Product name at time of order")
    )
    product_type = models.CharField(
        max_length=30,
        help_text=_("Product type at time of order")
    )
    billing_period = models.CharField(
        max_length=20,
        help_text=_("Billing period for this item")
    )
    
    # Quantity and pricing
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        help_text=_("Quantity ordered")
    )
    unit_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text=_("Unit price in cents (snapshot)")
    )
    setup_cents = models.BigIntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("Setup fee in cents")
    )
    
    # Tax calculation
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        default=Decimal('0.0000'),
        help_text=_("Tax rate applied (e.g., 0.1900 for 19%)")
    )
    tax_cents = models.BigIntegerField(
        default=0,
        help_text=_("Tax amount in cents")
    )
    
    # Line total
    line_total_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total for this line including tax")
    )
    
    # Product configuration for provisioning
    config = models.JSONField(
        default=dict,
        help_text=_("Product configuration (domain, username, specs, etc.)")
    )
    
    # Domain association (if applicable)
    domain_name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Associated domain name")
    )
    
    # Service relationship (after provisioning)
    service = models.ForeignKey(
        'provisioning.Service',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='order_items',
        help_text=_("Provisioned service for this order item")
    )
    
    # Provisioning status
    PROVISIONING_STATUS = [
        ('pending', _('Pending')),
        ('in_progress', _('In Progress')),
        ('completed', _('Completed')),
        ('failed', _('Failed')),
        ('cancelled', _('Cancelled')),
    ]
    provisioning_status = models.CharField(
        max_length=20,
        choices=PROVISIONING_STATUS,
        default='pending',
        help_text=_("Provisioning status for this item")
    )
    provisioning_notes = models.TextField(
        blank=True,
        help_text=_("Provisioning notes and error messages")
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    provisioned_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this item was successfully provisioned")
    )
    
    class Meta:
        db_table = 'order_items'
        verbose_name = _('Order Item')
        verbose_name_plural = _('Order Items')
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['order', 'created_at']),
            models.Index(fields=['product']),
            models.Index(fields=['provisioning_status']),
        ]
    
    @property
    def unit_price(self):
        """Return unit price in currency units"""
        return Decimal(self.unit_price_cents) / 100
    
    @property
    def setup_fee(self):
        """Return setup fee in currency units"""
        return Decimal(self.setup_cents) / 100
    
    @property
    def tax_amount(self):
        """Return tax amount in currency units"""
        return Decimal(self.tax_cents) / 100
    
    @property
    def line_total(self):
        """Return line total in currency units"""
        return Decimal(self.line_total_cents) / 100
    
    @property
    def subtotal_cents(self):
        """Calculate subtotal before tax"""
        return (self.unit_price_cents * self.quantity) + self.setup_cents
    
    @property
    def subtotal(self):
        """Return subtotal in currency units"""
        return Decimal(self.subtotal_cents) / 100
    
    def calculate_totals(self):
        """Calculate tax and line total"""
        subtotal = self.subtotal_cents
        self.tax_cents = int(subtotal * self.tax_rate)
        self.line_total_cents = subtotal + self.tax_cents
        return self.line_total_cents
    
    def mark_as_provisioned(self, service=None):
        """Mark this item as successfully provisioned"""
        self.provisioning_status = 'completed'
        self.provisioned_at = timezone.now()
        if service:
            self.service = service
        self.save(update_fields=[
            'provisioning_status', 
            'provisioned_at', 
            'service'
        ])
    
    def save(self, *args, **kwargs):
        """Auto-calculate totals before saving"""
        # Store product details snapshot
        if self.product and not self.product_name:
            self.product_name = self.product.name
            self.product_type = self.product.product_type
        
        # Calculate totals
        self.calculate_totals()
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.product_name} x{self.quantity} ({self.order.order_number})"


class OrderStatusHistory(models.Model):
    """
    Track order status changes for audit trail and customer notifications.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Order relationship
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name='status_history'
    )
    
    # Status change details
    old_status = models.CharField(
        max_length=20,
        blank=True,
        help_text=_("Previous status")
    )
    new_status = models.CharField(
        max_length=20,
        help_text=_("New status")
    )
    
    # Change context
    changed_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_("User who made the change")
    )
    reason = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Reason for status change")
    )
    notes = models.TextField(
        blank=True,
        help_text=_("Additional notes about the change")
    )
    
    # Automatic vs manual change
    is_automatic = models.BooleanField(
        default=False,
        help_text=_("Whether this was an automatic system change")
    )
    
    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'order_status_history'
        verbose_name = _('Order Status History')
        verbose_name_plural = _('Order Status Histories')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['order', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.order.order_number}: {self.old_status} → {self.new_status}"
