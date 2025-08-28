from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.utils import timezone

from apps.billing.models import Currency
from apps.common.types import EmailAddress, Err, Ok, Result
from apps.common.validators import log_security_event

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User

    from .models import Order

"""
Order Management Services for PRAHO Platform
Handles order lifecycle, Romanian VAT compliance, and integration with billing/provisioning.
"""

UserModel = get_user_model()
logger = logging.getLogger(__name__)

# ===============================================================================
# ORDER SERVICE PARAMETER OBJECTS
# ===============================================================================

class OrderFilters(TypedDict, total=False):
    """Type definition for order filtering parameters"""
    status: str
    customer_id: uuid.UUID
    order_number: str
    date_from: str
    date_to: str
    min_total: Decimal
    max_total: Decimal
    search: str

class OrderItemData(TypedDict):
    """Type definition for order item data"""
    product_id: uuid.UUID | None
    service_id: uuid.UUID | None
    quantity: int
    unit_price_cents: int
    description: str
    meta: dict[str, Any]

class BillingAddressData(TypedDict):
    """Type definition for Romanian billing address with compliance fields"""
    company_name: str
    contact_name: str
    email: EmailAddress
    phone: str
    address_line1: str
    address_line2: str
    city: str
    county: str
    postal_code: str
    country: str
    fiscal_code: str  # CUI in Romania
    registration_number: str
    vat_number: str

@dataclass
class OrderCreateData:
    """Parameter object for order creation"""
    customer: Customer
    items: list[OrderItemData]
    billing_address: BillingAddressData
    currency: str = 'RON'
    notes: str = ''
    meta: dict[str, Any] = field(default_factory=dict)

@dataclass
class OrderUpdateData:
    """Parameter object for order updates"""
    billing_address: BillingAddressData | None = None
    notes: str | None = None
    meta: dict[str, Any] | None = None

@dataclass
class StatusChangeData:
    """Parameter object for order status changes"""
    new_status: str
    notes: str = ''
    changed_by: User | None = None

# ===============================================================================
# ORDER CALCULATION SERVICES
# ===============================================================================

class OrderCalculationService:
    """Service for order financial calculations with Romanian VAT compliance"""
    
    VAT_RATE: ClassVar[Decimal] = Decimal('0.19')  # 19% Romanian VAT
    
    @staticmethod
    def calculate_vat(amount_cents: int) -> int:
        """Calculate VAT amount in cents for Romanian tax compliance"""
        amount = Decimal(amount_cents) / 100
        vat_amount = amount * OrderCalculationService.VAT_RATE
        return int(vat_amount * 100)
    
    @staticmethod
    def calculate_order_totals(items: list[OrderItemData]) -> dict[str, int]:
        """Calculate order subtotal, VAT, and total in cents"""
        subtotal_cents = sum(
            item['quantity'] * item['unit_price_cents'] 
            for item in items
        )
        
        tax_cents = OrderCalculationService.calculate_vat(subtotal_cents)
        total_cents = subtotal_cents + tax_cents
        
        return {
            'subtotal_cents': subtotal_cents,
            'tax_cents': tax_cents,
            'total_cents': total_cents
        }

# ===============================================================================
# ORDER NUMBERING SERVICE
# ===============================================================================

class OrderNumberingService:
    """Service for generating sequential order numbers per Romanian compliance"""
    
    @staticmethod
    @transaction.atomic
    def generate_order_number(customer: Customer) -> str:
        """Generate sequential order number for customer compliance"""
        from .models import Order  # noqa: PLC0415 - Circular import prevention
        
        current_year = timezone.now().year
        prefix = f"ORD-{current_year}-{str(customer.pk).zfill(8)}"
        
        # Get the highest existing order number for this customer and year
        latest_order = (
            Order.objects
            .filter(
                customer=customer,
                order_number__startswith=prefix,
                created_at__year=current_year
            )
            .order_by('-order_number')
            .first()
        )
        
        if latest_order and latest_order.order_number.startswith(prefix):
            # Extract sequence number and increment
            try:
                sequence_part = latest_order.order_number.split('-')[-1]
                next_sequence = int(sequence_part) + 1
            except (ValueError, IndexError):
                next_sequence = 1
        else:
            next_sequence = 1
        
        return f"{prefix}-{next_sequence:04d}"

# ===============================================================================
# MAIN ORDER SERVICE
# ===============================================================================

class OrderService:
    """Main service for order management operations"""
    
    @staticmethod
    @transaction.atomic
    def create_order(data: OrderCreateData, created_by: User | None = None) -> Result[Order, str]:
        """Create new order with validation and audit trail"""
        try:
            from .models import Order, OrderItem  # noqa: PLC0415 - Circular import prevention
            
            # Generate order number
            order_number = OrderNumberingService.generate_order_number(data.customer)
            
            # Calculate financial totals
            totals = OrderCalculationService.calculate_order_totals(data.items)
            
            # Get currency instance (Currency already imported at top)
            currency_instance = Currency.objects.get(code=data.currency)
            
            # Create order
            order = Order.objects.create(
                order_number=order_number,
                customer=data.customer,
                currency=currency_instance,
                notes=data.notes,
                meta=data.meta,
                # Customer snapshot fields
                customer_email=data.customer.primary_email,
                customer_name=data.customer.name,
                customer_company=data.customer.company_name or '',
                customer_vat_id=getattr(data.customer.tax_profile, 'vat_number', '') if hasattr(data.customer, 'tax_profile') else '',
                # Billing address as JSON
                billing_address=dict(data.billing_address),
                # Financial totals
                **totals
            )
            
            # Create order items
            for item_data in data.items:
                # Calculate line totals
                subtotal_cents = item_data['quantity'] * item_data['unit_price_cents']
                tax_cents = OrderCalculationService.calculate_vat(subtotal_cents)
                line_total_cents = subtotal_cents + tax_cents
                
                # Handle optional product_id - if None, skip this item or handle appropriately
                product_id = item_data.get('product_id')
                if product_id is None:
                    continue  # Skip items without a product_id
                
                OrderItem.objects.create(
                    order=order,
                    product_id=product_id,
                    quantity=item_data['quantity'],
                    unit_price_cents=item_data['unit_price_cents'],
                    tax_rate=OrderCalculationService.VAT_RATE,
                    tax_cents=tax_cents,
                    line_total_cents=line_total_cents,
                    product_name=item_data['description'],
                    product_type='hosting',  # Default type
                    billing_period='monthly',  # Default period
                    config=item_data.get('meta', {})
                )
            
            # Create status history entry
            OrderService._create_status_history(
                order, None, 'draft', 'Order created', created_by
            )
            
            # Log audit event
            log_security_event(
                'order_created',
                {
                    'order_number': order.order_number,
                    'customer_name': data.customer.name,
                    'order_id': str(order.id),
                    'customer_id': str(data.customer.id),
                    'total_cents': totals['total_cents'],
                    'user_id': str(created_by.id) if created_by else None
                }
            )
            
            return Ok(order)
            
        except Exception as e:
            logger.exception(f"Failed to create order: {e}")
            return Err(f"Failed to create order: {e!s}")
    
    @staticmethod
    @transaction.atomic
    def update_order_status(
        order: Order, 
        status_data: StatusChangeData
    ) -> Result[Order, str]:
        """Update order status with validation and audit trail"""
        try:
            old_status = order.status
            
            # Validate status transition
            if not OrderService._is_valid_status_transition(old_status, status_data.new_status):
                return Err(f"Invalid status transition from {old_status} to {status_data.new_status}")
            
            # Update order status
            order.status = status_data.new_status
            order.save(update_fields=['status', 'updated_at'])
            
            # Create status history entry
            OrderService._create_status_history(
                order, old_status, status_data.new_status, 
                status_data.notes, status_data.changed_by
            )
            
            # Log audit event
            log_security_event(
                'order_status_changed',
                {
                    'order_number': order.order_number,
                    'order_id': str(order.id),
                    'old_status': old_status,
                    'new_status': status_data.new_status,
                    'user_id': str(status_data.changed_by.id) if status_data.changed_by else None,
                    'notes': status_data.notes
                }
            )
            
            return Ok(order)
            
        except Exception as e:
            logger.exception(f"Failed to update order status: {e}")
            return Err(f"Failed to update order status: {e!s}")
    
    @staticmethod
    def _create_status_history(
        order: Order,
        old_status: str | None,
        new_status: str,
        notes: str,
        changed_by: User | None
    ) -> None:
        """Create order status history entry"""
        from .models import OrderStatusHistory  # noqa: PLC0415 - Circular import prevention
        
        OrderStatusHistory.objects.create(
            order=order,
            old_status=old_status or '',  # Convert None to empty string
            new_status=new_status,
            notes=notes,
            changed_by=changed_by
        )
    
    @staticmethod
    def _is_valid_status_transition(old_status: str, new_status: str) -> bool:
        """Validate order status transitions according to business rules"""
        
        # Define valid transitions
        valid_transitions = {
            'draft': ['pending', 'cancelled'],
            'pending': ['processing', 'cancelled', 'failed'],
            'processing': ['completed', 'failed', 'cancelled'],
            'completed': ['refunded', 'partially_refunded'],  # Allow refunds from completed
            'cancelled': [],  # Terminal state  
            'failed': ['pending', 'cancelled'],  # Allow retry
            'refunded': [],  # Terminal state
            'partially_refunded': ['refunded']  # Can complete refund
        }
        
        return new_status in valid_transitions.get(old_status, [])

# ===============================================================================
# ORDER QUERY SERVICE
# ===============================================================================

class OrderQueryService:
    """Service for order querying and filtering operations"""
    
    @staticmethod
    def get_orders_for_customer(
        customer: Customer, 
        filters: OrderFilters | None = None
    ) -> Result[list[Order], str]:
        """Get orders for a specific customer with optional filtering"""
        try:
            from .models import Order  # noqa: PLC0415 - Circular import prevention
            
            queryset = Order.objects.filter(customer=customer).select_related('customer')
            
            if filters:
                if status := filters.get('status'):
                    queryset = queryset.filter(status=status)
                if order_number := filters.get('order_number'):
                    queryset = queryset.filter(order_number__icontains=order_number)
                if search := filters.get('search'):
                    queryset = queryset.filter(
                        models.Q(order_number__icontains=search) |
                        models.Q(customer_company__icontains=search) |
                        models.Q(customer_name__icontains=search)
                    )
                
            orders = list(queryset.order_by('-created_at'))
            return Ok(orders)
            
        except Exception as e:
            logger.exception(f"Failed to get orders for customer: {e}")
            return Err(f"Failed to get orders: {e!s}")
    
    @staticmethod
    def get_order_with_items(order_id: uuid.UUID, customer: Customer | None = None) -> Result[Order, str]:
        """Get order with related items, optionally scoped to customer"""
        try:
            from .models import Order  # noqa: PLC0415 - Circular import prevention
            
            queryset = Order.objects.select_related('customer').prefetch_related(
                'items__product',
                'items__service',
                'status_history__changed_by'
            )
            
            if customer:
                queryset = queryset.filter(customer=customer)
            
            order = queryset.get(id=order_id)
            return Ok(order)
            
        except Order.DoesNotExist:
            return Err("Order not found")
        except Exception as e:
            logger.exception(f"Failed to get order with items: {e}")
            return Err(f"Failed to get order: {e!s}")
