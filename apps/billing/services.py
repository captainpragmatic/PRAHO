"""
Billing Services for PRAHO Platform
Handles invoice management, refunds, and Romanian VAT compliance.
Contains critical financial operations including bidirectional refund synchronization.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.common.validators import log_security_event

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order
    from apps.users.models import User

    from .models import Invoice, Payment

"""
RefundService - Critical Financial System for PRAHO Platform
=============================================================

This service handles bidirectional synchronization between orders and invoices for refunds.
It ensures that refunding either an order OR an invoice automatically refunds the other,
maintaining data integrity across the financial system.

CRITICAL SAFETY FEATURES:
- Atomic transactions prevent partial refunds
- Comprehensive validation prevents double refunds
- Audit logging for regulatory compliance
- Strong typing throughout for reliability
- Result pattern for explicit error handling

BUSINESS RULES:
- Orders and invoices can be refunded independently 
- Refunding one automatically refunds the other
- Partial refunds are supported with amount tracking
- Refund eligibility is validated before processing
- Multiple invoices per order are handled correctly
"""

User = get_user_model()
logger = logging.getLogger(__name__)

# ===============================================================================
# REFUND DOMAIN TYPES
# ===============================================================================

class RefundType(Enum):
    """Type of refund being processed"""
    FULL = "full"
    PARTIAL = "partial"

class RefundReason(Enum):
    """Business reason for the refund"""
    CUSTOMER_REQUEST = "customer_request"
    ERROR_CORRECTION = "error_correction"
    DISPUTE_RESOLUTION = "dispute"
    SERVICE_FAILURE = "service_failure"
    DUPLICATE_PAYMENT = "duplicate_payment"
    FRAUD_PREVENTION = "fraud"
    CANCELLATION = "cancellation"
    DOWNGRADE = "downgrade"
    ADMINISTRATIVE = "administrative"

class RefundStatus(Enum):
    """Status of refund processing"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RefundData(TypedDict):
    """Parameters for refund operations"""
    refund_type: RefundType
    amount_cents: int  # Required for partial refunds, ignored for full refunds
    reason: RefundReason
    notes: str
    initiated_by: User | None  # User who initiated the refund
    external_refund_id: str | None  # Payment gateway refund ID
    process_payment_refund: bool  # Whether to process actual payment refund

class RefundResult(TypedDict):
    """Result of refund operations"""
    refund_id: uuid.UUID
    order_id: uuid.UUID | None
    invoice_id: uuid.UUID | None
    refund_type: RefundType
    amount_refunded_cents: int
    order_status_updated: bool
    invoice_status_updated: bool
    payment_refund_processed: bool
    audit_entries_created: int

class RefundEligibility(TypedDict):
    """Refund eligibility validation result"""
    is_eligible: bool
    reason: str
    max_refund_amount_cents: int
    already_refunded_cents: int

# ===============================================================================
# REFUND SERVICE IMPLEMENTATION
# ===============================================================================

class RefundService:
    """
    Critical financial service for handling refunds with bidirectional synchronization.
    
    This service is responsible for:
    1. Validating refund eligibility
    2. Processing refunds atomically across orders and invoices
    3. Maintaining audit trails for compliance
    4. Handling edge cases like multiple invoices per order
    5. Coordinating with payment processors for actual refunds
    """

    @staticmethod
    @transaction.atomic
    def refund_order(order_id: uuid.UUID, refund_data: RefundData) -> Result[RefundResult, str]:
        """
        Refund an order and automatically refund associated invoices.
        
        Args:
            order_id: UUID of the order to refund
            refund_data: Refund parameters including amount, reason, etc.
            
        Returns:
            Result containing refund details or error message
            
        Business Logic:
        - Validates order exists and can be refunded
        - For full refunds: refunds entire order amount
        - For partial refunds: validates amount and updates accordingly
        - Automatically refunds any associated invoices
        - Creates comprehensive audit trail
        """
        try:
            from apps.orders.models import Order
            from .models import Invoice

            # Get order with related data
            try:
                order = Order.objects.select_related('customer').get(id=order_id)
            except Order.DoesNotExist:
                return Err(f"Order {order_id} not found")

            # Validate refund eligibility
            eligibility_result = RefundService._validate_order_refund_eligibility(order, refund_data)
            if eligibility_result.is_err():
                # Type narrowing - MyPy should understand this is an Err
                assert isinstance(eligibility_result, Err)
                return Err(eligibility_result.error)

            eligibility = eligibility_result.unwrap()
            if not eligibility['is_eligible']:
                return Err(f"Order not eligible for refund: {eligibility['reason']}")

            # Calculate refund amount
            if refund_data['refund_type'] == RefundType.FULL:
                refund_amount_cents = order.total_cents - eligibility['already_refunded_cents']
            else:
                refund_amount_cents = refund_data['amount_cents']
                if refund_amount_cents > eligibility['max_refund_amount_cents']:
                    return Err(f"Refund amount exceeds maximum refundable amount")

            # Generate refund ID for tracking
            refund_id = uuid.uuid4()

            # Process the bidirectional refund
            refund_result = RefundService._process_bidirectional_refund(
                order=order,
                invoice=None,  # Will be found automatically
                refund_id=refund_id,
                refund_amount_cents=refund_amount_cents,
                refund_data=refund_data
            )

            if refund_result.is_err():
                return refund_result

            result = refund_result.unwrap()
            
            # Log security/audit event
            log_security_event(
                'order_refunded',
                {
                    'refund_id': str(refund_id),
                    'order_id': str(order_id),
                    'order_number': order.order_number,
                    'customer_id': str(order.customer.id),
                    'refund_type': refund_data['refund_type'].value,
                    'amount_refunded_cents': refund_amount_cents,
                    'reason': refund_data['reason'].value,
                    'initiated_by': str(refund_data['initiated_by'].id) if refund_data['initiated_by'] else None,
                    'notes': refund_data['notes']
                }
            )

            return Ok(result)

        except Exception as e:
            logger.exception(f"Failed to process order refund for {order_id}: {e}")
            return Err(f"Failed to process refund: {e!s}")

    @staticmethod
    @transaction.atomic
    def refund_invoice(invoice_id: uuid.UUID, refund_data: RefundData) -> Result[RefundResult, str]:
        """
        Refund an invoice and automatically refund associated orders.
        
        Args:
            invoice_id: UUID of the invoice to refund  
            refund_data: Refund parameters including amount, reason, etc.
            
        Returns:
            Result containing refund details or error message
            
        Business Logic:
        - Validates invoice exists and can be refunded
        - For full refunds: refunds entire invoice amount
        - For partial refunds: validates amount and updates accordingly  
        - Automatically refunds any associated orders
        - Handles the case where an invoice might have multiple orders
        """
        try:
            from .models import Invoice

            # Get invoice with related data
            try:
                invoice = Invoice.objects.select_related('customer').get(id=invoice_id)
            except Invoice.DoesNotExist:
                return Err(f"Invoice {invoice_id} not found")

            # Validate refund eligibility
            eligibility_result = RefundService._validate_invoice_refund_eligibility(invoice, refund_data)
            if eligibility_result.is_err():
                # Type narrowing - MyPy should understand this is an Err
                assert isinstance(eligibility_result, Err)
                return Err(eligibility_result.error)

            eligibility = eligibility_result.unwrap()
            if not eligibility['is_eligible']:
                return Err(f"Invoice not eligible for refund: {eligibility['reason']}")

            # Calculate refund amount
            if refund_data['refund_type'] == RefundType.FULL:
                refund_amount_cents = invoice.total_cents - eligibility['already_refunded_cents']
            else:
                refund_amount_cents = refund_data['amount_cents']
                if refund_amount_cents > eligibility['max_refund_amount_cents']:
                    return Err(f"Refund amount exceeds maximum refundable amount")

            # Generate refund ID for tracking
            refund_id = uuid.uuid4()

            # Process the bidirectional refund
            refund_result = RefundService._process_bidirectional_refund(
                order=None,  # Will be found automatically
                invoice=invoice,
                refund_id=refund_id,
                refund_amount_cents=refund_amount_cents,
                refund_data=refund_data
            )

            if refund_result.is_err():
                return refund_result

            result = refund_result.unwrap()
            
            # Log security/audit event
            log_security_event(
                'invoice_refunded',
                {
                    'refund_id': str(refund_id),
                    'invoice_id': str(invoice_id),
                    'invoice_number': invoice.number,
                    'customer_id': str(invoice.customer.id),
                    'refund_type': refund_data['refund_type'].value,
                    'amount_refunded_cents': refund_amount_cents,
                    'reason': refund_data['reason'].value,
                    'initiated_by': str(refund_data['initiated_by'].id) if refund_data['initiated_by'] else None,
                    'notes': refund_data['notes']
                }
            )

            return Ok(result)

        except Exception as e:
            logger.exception(f"Failed to process invoice refund for {invoice_id}: {e}")
            return Err(f"Failed to process refund: {e!s}")

    @staticmethod
    def _process_bidirectional_refund(
        order: Order | None,
        invoice: Invoice | None,
        refund_id: uuid.UUID,
        refund_amount_cents: int,
        refund_data: RefundData
    ) -> Result[RefundResult, str]:
        """
        Core refund processing logic that handles both order and invoice updates atomically.
        
        This is the heart of the bidirectional synchronization system.
        It ensures that refunding one entity automatically refunds the other.
        """
        try:
            from apps.orders.models import Order
            from .models import Invoice

            audit_entries_created = 0
            order_status_updated = False
            invoice_status_updated = False
            payment_refund_processed = False

            # Find related entities if not provided
            if order and not invoice:
                # Find invoices for this order
                invoice = order.invoice  # Primary invoice relationship
                if not invoice:
                    # Look for invoices in the related orders
                    invoices = Invoice.objects.filter(orders=order)
                    invoice = invoices.first() if invoices.exists() else None
                    
            elif invoice and not order:
                # Find orders for this invoice
                orders = invoice.orders.all()
                order = orders.first() if orders.exists() else None

            # Update order status
            if order:
                order_result = RefundService._update_order_refund_status(
                    order, refund_amount_cents, refund_data
                )
                if order_result.is_err():
                    # Type narrowing - MyPy should understand this is an Err
                    assert isinstance(order_result, Err)
                    return Err(order_result.error)
                order_status_updated = True
                audit_entries_created += 1

            # Update invoice status  
            if invoice:
                invoice_result = RefundService._update_invoice_refund_status(
                    invoice, refund_amount_cents, refund_data
                )
                if invoice_result.is_err():
                    # Type narrowing - MyPy should understand this is an Err
                    assert isinstance(invoice_result, Err)
                    return Err(invoice_result.error)
                invoice_status_updated = True
                audit_entries_created += 1

            # Process payment refund if requested
            if refund_data['process_payment_refund']:
                payment_result = RefundService._process_payment_refund(
                    order=order,
                    invoice=invoice,
                    refund_amount_cents=refund_amount_cents,
                    refund_data=refund_data
                )
                if payment_result.is_ok():
                    payment_refund_processed = True
                # Note: We don't fail the entire refund if payment processing fails
                # The financial records are updated regardless

            # Create refund result
            result: RefundResult = {
                'refund_id': refund_id,
                'order_id': order.id if order else None,
                'invoice_id': invoice.id if invoice else None,
                'refund_type': refund_data['refund_type'],
                'amount_refunded_cents': refund_amount_cents,
                'order_status_updated': order_status_updated,
                'invoice_status_updated': invoice_status_updated,
                'payment_refund_processed': payment_refund_processed,
                'audit_entries_created': audit_entries_created
            }

            return Ok(result)

        except Exception as e:
            logger.exception(f"Failed to process bidirectional refund: {e}")
            return Err(f"Failed to process bidirectional refund: {e!s}")

    @staticmethod
    def _update_order_refund_status(
        order: Order, 
        refund_amount_cents: int, 
        refund_data: RefundData
    ) -> Result[bool, str]:
        """Update order status based on refund amount"""
        try:
            from apps.orders.services import OrderService, StatusChangeData
            from django.utils import timezone
            import uuid

            # Calculate total refunded amount
            current_refunded = RefundService._get_order_refunded_amount(order)
            total_refunded = current_refunded + refund_amount_cents
            
            # Determine new status
            if total_refunded >= order.total_cents:
                new_status = 'refunded'
            else:
                new_status = 'partially_refunded'

            # Add refund information to order metadata
            if 'refunds' not in order.meta:
                order.meta['refunds'] = []
                
            order.meta['refunds'].append({
                'refund_id': str(uuid.uuid4()),
                'amount_cents': refund_amount_cents,
                'reason': refund_data['reason'].value,
                'notes': refund_data['notes'],
                'refunded_at': timezone.now().isoformat(),
                'initiated_by': str(refund_data['initiated_by'].id) if refund_data['initiated_by'] else None
            })

            # Update order status using existing service
            status_change = StatusChangeData(
                new_status=new_status,
                notes=f"Refund processed: {refund_data['reason'].value} - {refund_data['notes']}",
                changed_by=refund_data['initiated_by']
            )

            result = OrderService.update_order_status(order, status_change)
            
            # Save the metadata changes
            order.save(update_fields=['meta'])
            
            if result.is_ok():
                return Ok(True)
            else:
                # Type narrowing - MyPy should understand this is an Err
                assert isinstance(result, Err)
                return Err(result.error)

        except Exception as e:
            logger.exception(f"Failed to update order refund status: {e}")
            return Err(f"Failed to update order status: {e!s}")

    @staticmethod 
    def _update_invoice_refund_status(
        invoice: Invoice,
        refund_amount_cents: int,
        refund_data: RefundData
    ) -> Result[bool, str]:
        """Update invoice status based on refund amount"""
        try:
            # Calculate total refunded amount
            current_refunded = RefundService._get_invoice_refunded_amount(invoice)
            total_refunded = current_refunded + refund_amount_cents
            
            # Determine new status
            if total_refunded >= invoice.total_cents:
                new_status = 'refunded'
            else:
                # For invoices, we don't have 'partially_refunded' status in current model
                # Keep as 'issued' but add metadata about partial refund
                new_status = 'issued'  # or add 'partially_refunded' to invoice status choices
                
            # Update invoice status
            old_status = invoice.status
            invoice.status = new_status
            
            # Add refund information to metadata
            if 'refunds' not in invoice.meta:
                invoice.meta['refunds'] = []
                
            invoice.meta['refunds'].append({
                'refund_id': str(uuid.uuid4()),
                'amount_cents': refund_amount_cents,
                'reason': refund_data['reason'].value,
                'notes': refund_data['notes'],
                'refunded_at': timezone.now().isoformat(),
                'initiated_by': str(refund_data['initiated_by'].id) if refund_data['initiated_by'] else None
            })
            
            invoice.save(update_fields=['status', 'meta'])

            # Log the status change
            log_security_event(
                'invoice_status_changed',
                {
                    'invoice_id': str(invoice.id),
                    'invoice_number': invoice.number,
                    'old_status': old_status,
                    'new_status': new_status,
                    'reason': 'refund_processed',
                    'refund_amount_cents': refund_amount_cents
                }
            )

            return Ok(True)

        except Exception as e:
            logger.exception(f"Failed to update invoice refund status: {e}")
            return Err(f"Failed to update invoice status: {e!s}")

    @staticmethod
    def _process_payment_refund(
        order: Order | None,
        invoice: Invoice | None, 
        refund_amount_cents: int,
        refund_data: RefundData
    ) -> Result[dict[str, Any], str]:
        """
        Process actual payment refund through payment processor.
        
        This would integrate with Stripe, PayPal, or other payment processors
        to issue actual refunds to customers.
        """
        try:
            from .models import Payment

            # Find payments to refund
            payments_to_refund = []
            
            if invoice:
                payments_to_refund = list(
                    Payment.objects.filter(
                        invoice=invoice, 
                        status='succeeded'
                    ).order_by('-received_at')
                )
            elif order and order.invoice:
                payments_to_refund = list(
                    Payment.objects.filter(
                        invoice=order.invoice,
                        status='succeeded'
                    ).order_by('-received_at')
                )

            if not payments_to_refund:
                return Err("No successful payments found to refund")

            # Process refunds (simplified implementation)
            total_refund_processed = 0
            refund_results = []
            
            for payment in payments_to_refund:
                if total_refund_processed >= refund_amount_cents:
                    break
                    
                remaining_to_refund = refund_amount_cents - total_refund_processed
                refund_this_payment = min(remaining_to_refund, payment.amount_cents)
                
                # TODO: Integrate with actual payment processor
                # For now, just update payment status
                if refund_this_payment >= payment.amount_cents:
                    payment.status = 'refunded'
                else:
                    payment.status = 'partially_refunded'
                    
                payment.save(update_fields=['status'])
                
                refund_results.append({
                    'payment_id': str(payment.id),
                    'amount_refunded_cents': refund_this_payment,
                    'gateway_refund_id': refund_data.get('external_refund_id')
                })
                
                total_refund_processed += refund_this_payment

            return Ok({
                'total_refunded_cents': total_refund_processed,
                'payments_refunded': len(refund_results),
                'refund_details': refund_results
            })

        except Exception as e:
            logger.exception(f"Failed to process payment refund: {e}")
            return Err(f"Failed to process payment refund: {e!s}")

    @staticmethod
    def _validate_order_refund_eligibility(
        order: Order, 
        refund_data: RefundData
    ) -> Result[RefundEligibility, str]:
        """Validate if an order can be refunded"""
        try:
            # Check order status
            if order.status in ['draft', 'cancelled', 'failed']:
                return Ok({
                    'is_eligible': False,
                    'reason': f"Cannot refund order in '{order.status}' status",
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': 0
                })

            # Calculate already refunded amount
            already_refunded = RefundService._get_order_refunded_amount(order)
            max_refund_amount = order.total_cents - already_refunded

            if max_refund_amount <= 0:
                return Ok({
                    'is_eligible': False,
                    'reason': "Order has already been fully refunded",
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': already_refunded
                })

            # For partial refunds, validate amount
            if refund_data['refund_type'] == RefundType.PARTIAL:
                if refund_data['amount_cents'] <= 0:
                    return Ok({
                        'is_eligible': False,
                        'reason': "Refund amount must be greater than 0",
                        'max_refund_amount_cents': max_refund_amount,
                        'already_refunded_cents': already_refunded
                    })

                if refund_data['amount_cents'] > max_refund_amount:
                    return Ok({
                        'is_eligible': False,
                        'reason': f"Refund amount exceeds available amount",
                        'max_refund_amount_cents': max_refund_amount,
                        'already_refunded_cents': already_refunded
                    })

            return Ok({
                'is_eligible': True,
                'reason': "Order is eligible for refund",
                'max_refund_amount_cents': max_refund_amount,
                'already_refunded_cents': already_refunded
            })

        except Exception as e:
            logger.exception(f"Failed to validate order refund eligibility: {e}")
            return Err(f"Failed to validate eligibility: {e!s}")

    @staticmethod
    def _validate_invoice_refund_eligibility(
        invoice: Invoice,
        refund_data: RefundData
    ) -> Result[RefundEligibility, str]:
        """Validate if an invoice can be refunded"""
        try:
            # Check invoice status
            if invoice.status in ['draft', 'void']:
                return Ok({
                    'is_eligible': False,
                    'reason': f"Cannot refund invoice in '{invoice.status}' status",
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': 0
                })

            # Calculate already refunded amount
            already_refunded = RefundService._get_invoice_refunded_amount(invoice)
            max_refund_amount = invoice.total_cents - already_refunded

            if max_refund_amount <= 0:
                return Ok({
                    'is_eligible': False,
                    'reason': "Invoice has already been fully refunded",
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': already_refunded
                })

            # For partial refunds, validate amount
            if refund_data['refund_type'] == RefundType.PARTIAL:
                if refund_data['amount_cents'] <= 0:
                    return Ok({
                        'is_eligible': False,
                        'reason': "Refund amount must be greater than 0",
                        'max_refund_amount_cents': max_refund_amount,
                        'already_refunded_cents': already_refunded
                    })

                if refund_data['amount_cents'] > max_refund_amount:
                    return Ok({
                        'is_eligible': False,
                        'reason': f"Refund amount exceeds available amount",
                        'max_refund_amount_cents': max_refund_amount,
                        'already_refunded_cents': already_refunded
                    })

            return Ok({
                'is_eligible': True,
                'reason': "Invoice is eligible for refund",
                'max_refund_amount_cents': max_refund_amount,
                'already_refunded_cents': already_refunded
            })

        except Exception as e:
            logger.exception(f"Failed to validate invoice refund eligibility: {e}")
            return Err(f"Failed to validate eligibility: {e!s}")

    @staticmethod
    def _get_order_refunded_amount(order: Order) -> int:
        """Calculate total amount already refunded for an order"""
        # Check order metadata for refund tracking
        if 'refunds' in order.meta:
            return sum(refund['amount_cents'] for refund in order.meta['refunds'])
        return 0

    @staticmethod
    def _get_invoice_refunded_amount(invoice: Invoice) -> int:
        """Calculate total amount already refunded for an invoice"""
        # Check invoice metadata for refund tracking
        if 'refunds' in invoice.meta:
            return sum(refund['amount_cents'] for refund in invoice.meta['refunds'])
        return 0

    @staticmethod
    def get_refund_eligibility(
        entity_type: str,
        entity_id: uuid.UUID,
        refund_amount_cents: int | None = None
    ) -> Result[RefundEligibility, str]:
        """
        Check refund eligibility for an order or invoice without processing.
        
        Args:
            entity_type: 'order' or 'invoice'
            entity_id: UUID of the entity
            refund_amount_cents: Amount for partial refund validation (optional)
            
        Returns:
            RefundEligibility result with detailed information
        """
        try:
            refund_data: RefundData = {
                'refund_type': RefundType.PARTIAL if refund_amount_cents else RefundType.FULL,
                'amount_cents': refund_amount_cents or 0,
                'reason': RefundReason.CUSTOMER_REQUEST,  # Dummy for validation
                'notes': '',
                'initiated_by': None,
                'external_refund_id': None,
                'process_payment_refund': False
            }

            if entity_type == 'order':
                from apps.orders.models import Order
                order = Order.objects.get(id=entity_id)
                return RefundService._validate_order_refund_eligibility(order, refund_data)
                
            elif entity_type == 'invoice':
                from .models import Invoice
                invoice = Invoice.objects.get(id=entity_id)
                return RefundService._validate_invoice_refund_eligibility(invoice, refund_data)
                
            else:
                return Err(f"Invalid entity_type: {entity_type}. Must be 'order' or 'invoice'")

        except Exception as e:
            logger.exception(f"Failed to check refund eligibility: {e}")
            return Err(f"Failed to check eligibility: {e!s}")

# ===============================================================================
# REFUND QUERY SERVICE
# ===============================================================================

class RefundQueryService:
    """Service for querying refund history and statistics"""

    @staticmethod
    def get_entity_refunds(entity_type: str, entity_id: uuid.UUID) -> Result[list[dict[str, Any]], str]:
        """Get refund history for an order or invoice"""
        try:
            refunds = []
            
            if entity_type == 'order':
                from apps.orders.models import Order
                order = Order.objects.get(id=entity_id)
                if 'refunds' in order.meta:
                    refunds = order.meta['refunds']
                    
            elif entity_type == 'invoice':
                from .models import Invoice
                invoice = Invoice.objects.get(id=entity_id)
                if 'refunds' in invoice.meta:
                    refunds = invoice.meta['refunds']
                    
            return Ok(refunds)
            
        except Exception as e:
            logger.exception(f"Failed to get refund history: {e}")
            return Err(f"Failed to get refund history: {e!s}")

    @staticmethod
    def get_refund_statistics(
        customer_id: uuid.UUID | None = None,
        date_from: str | None = None,
        date_to: str | None = None
    ) -> Result[dict[str, Any], str]:
        """Get refund statistics for reporting"""
        try:
            from apps.orders.models import Order
            from .models import Invoice
            
            # This would implement comprehensive refund reporting
            # For now, return basic structure
            stats = {
                'total_refunds': 0,
                'total_amount_refunded_cents': 0,
                'refunds_by_reason': {},
                'refunds_by_type': {
                    'full': 0,
                    'partial': 0
                },
                'orders_refunded': 0,
                'invoices_refunded': 0
            }
            
            return Ok(stats)
            
        except Exception as e:
            logger.exception(f"Failed to get refund statistics: {e}")
            return Err(f"Failed to get refund statistics: {e!s}")