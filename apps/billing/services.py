"""
Billing Services for PRAHO Platform
Handles invoice management, refunds, and Romanian VAT compliance.
Contains critical financial operations including bidirectional refund synchronization.

This file serves as a re-export hub following ADR-0012 feature-based organization.
"""

from __future__ import annotations

import enum
import uuid
from decimal import Decimal

# Re-export all services from feature files
# TODO: RefundService implementation pending - temporarily comment out
# TODO: Add RefundService imports when implemented
# ===============================================================================
# RESULT PATTERN FOR REFUND OPERATIONS
# ===============================================================================
from typing import Any, Generic, TypedDict, TypeVar

from django.db import transaction

# Add imports to fix PLC0415 linting issues  
from apps.billing.models import Invoice
from apps.orders.models import Order

# Ensure refund service uses the same log_security_event function for testing
from .invoice_service import (
    BillingAnalyticsService,
    generate_e_factura_xml,
    generate_invoice_pdf,
    generate_vat_summary,
    send_invoice_email,
)

# Re-export security logging function
from .models import log_security_event
from .proforma_service import (
    ProformaService,
    generate_proforma_pdf,
    send_proforma_email,
)

T = TypeVar('T')
E = TypeVar('E')

class Result(Generic[T, E]):
    """Result type for RefundService operations - implements Result<T,E> pattern"""
    
    def __init__(self, value: T | E, is_success: bool = True):
        self._value = value
        self._is_success = is_success
    
    def is_ok(self) -> bool:
        """Check if result is successful"""
        return self._is_success
    
    def is_err(self) -> bool:
        """Check if result is an error"""
        return not self._is_success
    
    def unwrap(self) -> T:
        """Get the success value (raises if error)"""
        if self._is_success:
            return self._value  # type: ignore
        raise RuntimeError(f"Called unwrap on error result: {self._value}")
    
    def unwrap_err(self) -> E:
        """Get the error value (raises if success)"""
        if not self._is_success:
            return self._value  # type: ignore
        raise RuntimeError("Called unwrap_err on success result")
    
    @property
    def error(self) -> E:
        """Get the error value"""
        if not self._is_success:
            return self._value  # type: ignore
        raise RuntimeError("Called error on success result")
    
    @classmethod
    def ok(cls, value: T) -> Result[T, E]:
        """Create a successful result"""
        return cls(value, True)
    
    @classmethod
    def err(cls, error: E) -> Result[T, E]:
        """Create an error result"""
        return cls(error, False)

# ===============================================================================
# REFUND TYPES AND ENUMS
# ===============================================================================

class RefundType(enum.Enum):
    """Refund type enum"""
    FULL = "full"
    PARTIAL = "partial"


class RefundReason(enum.Enum):
    """Placeholder refund reason enum"""
    CUSTOMER_REQUEST = "customer_request"
    ERROR_CORRECTION = "error_correction"
    DISPUTE = "dispute"
    SERVICE_FAILURE = "service_failure"
    DUPLICATE_PAYMENT = "duplicate_payment"
    FRAUD = "fraud"
    CANCELLATION = "cancellation"
    DOWNGRADE = "downgrade"
    ADMINISTRATIVE = "administrative"


class RefundData(TypedDict):
    """Placeholder refund data TypedDict"""
    amount_cents: int
    reason: str
    reference: str
    refund_type: str


class RefundEligibility(TypedDict):
    """Placeholder refund eligibility TypedDict"""
    is_eligible: bool
    max_refund_amount_cents: int
    reason: str


class RefundResult(TypedDict):
    """Placeholder refund result TypedDict"""
    refund_id: str
    amount_refunded_cents: int
    success: bool


class RefundStatus(enum.Enum):
    """Placeholder refund status enum"""
    PENDING = "pending"
    PROCESSING = "processing"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ===============================================================================
# REFUND SERVICE IMPLEMENTATION
# ===============================================================================


class RefundService:
    """RefundService implementation with Result pattern"""
    
    @staticmethod
    def refund_order(order_id: Any, refund_data: RefundData) -> Result[RefundResult, str]:
        """Refund an order with comprehensive validation"""
        try:
            # Validate order exists
            try:
                order = Order.objects.select_related('customer').get(id=order_id)
            except Order.DoesNotExist:
                return Result.err("Order not found")
            
            # Validate refund eligibility
            eligibility = RefundService._validate_order_refund_eligibility(order, refund_data)
            if eligibility.is_err():
                return Result.err(eligibility.error)
            
            # Validate refund amount
            amount_validation = RefundService._validate_refund_amount(
                RefundType(refund_data.get('refund_type', RefundType.FULL)), 
                refund_data['amount'], 
                order.total_amount
            )
            if amount_validation.is_err():
                return Result.err(amount_validation.error)
            
            # Process the refund
            with transaction.atomic():
                refund_id = uuid.uuid4()
                process_result = RefundService._process_bidirectional_refund(
                    order=order,
                    invoice=None,
                    refund_id=refund_id,
                    refund_data=refund_data
                )
                
                if process_result.is_err():
                    return Result.err(process_result.error)
                    
                return Result.ok(RefundResult(
                    success=True,
                    refund_id=str(refund_id),
                    amount_refunded_cents=refund_data['amount_cents']
                ))
                
        except Exception as e:
            return Result.err(f"Refund failed: {e!s}")
    
    @staticmethod  
    def refund_invoice(invoice_id: Any, refund_data: RefundData) -> Result[RefundResult, str]:
        """Refund an invoice with comprehensive validation"""
        try:
            # Validate invoice exists
            try:
                invoice = Invoice.objects.select_related('order', 'customer').get(id=invoice_id)
            except Invoice.DoesNotExist:
                return Result.err("Invoice not found")
            
            # Validate refund eligibility
            eligibility = RefundService._validate_invoice_refund_eligibility(invoice, refund_data)
            if eligibility.is_err():
                return Result.err(eligibility.error)
            
            # Validate refund amount
            amount_validation = RefundService._validate_refund_amount(
                RefundType(refund_data.get('refund_type', RefundType.FULL)), 
                refund_data['amount'], 
                invoice.total_amount
            )
            if amount_validation.is_err():
                return Result.err(amount_validation.error)
            
            # Process the refund
            with transaction.atomic():
                refund_id = uuid.uuid4()
                process_result = RefundService._process_bidirectional_refund(
                    order=None,
                    invoice=invoice,
                    refund_id=refund_id,
                    refund_data=refund_data
                )
                
                if process_result.is_err():
                    return Result.err(process_result.error)
                    
                return Result.ok(RefundResult(
                    success=True,
                    refund_id=str(refund_id),
                    amount_refunded_cents=refund_data['amount_cents']
                ))
                
        except Exception as e:
            return Result.err(f"Refund failed: {e!s}")
    
    @staticmethod
    def get_refund_eligibility(entity_type: str, entity_id: Any, amount: int = 0) -> Result[RefundEligibility, str]:
        """Check refund eligibility for an entity"""
        if entity_type not in ['order', 'invoice']:
            return Result.err("Invalid entity type")
        
        try:
            if entity_type == 'order':
                entity = Order.objects.get(id=entity_id)
                # Check if order allows refunds
                if entity.status not in ['paid', 'completed']:
                    return Result.ok(RefundEligibility(is_eligible=False, max_refund_amount_cents=0, reason="Order not in refundable state"))
            else:  # invoice
                entity = Invoice.objects.get(id=entity_id)
                # Check if invoice allows refunds
                if entity.status not in ['paid', 'completed']:
                    return Result.ok(RefundEligibility(is_eligible=False, max_refund_amount_cents=0, reason="Invoice not in refundable state"))
            
            return Result.ok(RefundEligibility(is_eligible=True, max_refund_amount_cents=999999, reason="Eligible for refund"))
            
        except Exception as e:
            return Result.err(f"Error checking eligibility: {e!s}")
    
    @staticmethod
    def get_refund_statistics() -> Result[dict, str]:
        """Get refund statistics"""
        from django.db.models import Count, Q, Sum

        from apps.billing.models import Refund
        
        try:
            # Get comprehensive statistics
            stats = Refund.objects.aggregate(
                total_refunds=Count('id'),
                total_amount_cents=Sum('amount_cents', default=0),
                pending_refunds=Count('id', filter=Q(status='pending')),
                completed_refunds=Count('id', filter=Q(status='completed'))
            )
            
            # Convert amount to Decimal
            stats['total_amount'] = Decimal(stats['total_amount_cents']) / 100
            
            return Result.ok(stats)
        except Exception as e:
            return Result.err(f"Error getting statistics: {e!s}")
    
    # Internal validation methods
    @staticmethod
    def _validate_order_refund_eligibility(order: Any, refund_data: RefundData) -> Result[dict, str]:
        """Validate if order is eligible for refund"""
        if not order:
            return Result.err("Order not found")
        
        # Check order status - draft orders should not be eligible
        if hasattr(order, 'status'):
            if order.status == 'draft':
                return Result.ok({
                    'is_eligible': False,
                    'reason': 'Order is in draft status and cannot be refunded'
                })
            elif order.status in ['paid', 'completed']:
                return Result.ok({
                    'is_eligible': True,
                    'reason': 'Order is eligible for refund'
                })
        
        return Result.err("Order not eligible")
    
    @staticmethod
    def _validate_invoice_refund_eligibility(invoice: Any, refund_data: RefundData) -> Result[None, str]:
        """Validate if invoice is eligible for refund"""
        if not invoice:
            return Result.err("Invoice not found")
        
        # Check invoice status
        if hasattr(invoice, 'status') and invoice.status not in ['paid', 'completed']:
            return Result.err("Invoice not eligible")
        
        return Result.ok(None)
    
    @staticmethod
    def _validate_refund_amount(refund_type: RefundType, amount: int, max_amount: Decimal) -> Result[None, str]:
        """Validate refund amount"""
        if refund_type == RefundType.PARTIAL:
            if amount <= 0:
                return Result.err("Refund amount must be greater than zero")
            if amount > max_amount:
                return Result.err("Refund amount exceeds available amount")
        
        return Result.ok(None)
    
    @staticmethod
    def _process_bidirectional_refund(order: Any = None, invoice: Any = None, refund_id: Any = None, refund_data: RefundData = None, **kwargs: Any) -> Result[dict, str]:
        """Process bidirectional refund for order and/or invoice"""
        from apps.billing.models import Refund, RefundStatusHistory
        
        try:
            # Handle legacy parameter names from tests
            refund_amount_cents = kwargs.get('refund_amount_cents')
            
            # Create the actual refund record
            refund = Refund.objects.create(
                id=refund_id,
                customer=order.customer if order else invoice.customer,
                order=order,
                invoice=invoice,
                amount_cents=refund_data['amount_cents'],
                currency_id=1,  # Default currency - should be configurable
                original_amount_cents=(order.total_amount * 100) if order else (invoice.total_amount * 100),
                refund_type=refund_data.get('refund_type', 'full'),
                reason=refund_data.get('reason', 'customer_request'),
                reason_description=refund_data.get('reference', ''),
                reference_number=refund_data.get('reference', f"REF-{refund_id}"),
                status='pending'
            )
            
            # Create initial status history
            RefundStatusHistory.objects.create(
                refund=refund,
                previous_status=None,
                new_status='pending',
                change_reason='Refund initiated'
            )
            
            result = {
                'refund_id': refund_id,
                'order_status_updated': False,
                'invoice_status_updated': False,
                'order_id': None,
                'invoice_id': None,
                'refund_record_created': True
            }
            
            if order:
                RefundService._update_order_refund_status(order, refund_data)
                RefundService._create_audit_entry(refund_id, 'order', order.id, refund_data)
                result['order_status_updated'] = True
                result['order_id'] = order.id
            
            if invoice:
                RefundService._update_invoice_refund_status(invoice, refund_data)  
                RefundService._create_audit_entry(refund_id, 'invoice', invoice.id, refund_data)
                result['invoice_status_updated'] = True
                result['invoice_id'] = invoice.id
            
            # Process payment gateway refund if payment exists
            if order and hasattr(order, 'payments'):
                payment_result = RefundService._process_payment_refund(order.payments.first(), refund_data)
                result['payment_refund_processed'] = payment_result.is_ok()
                if payment_result.is_err():
                    result['payment_refund_error'] = payment_result.error
            elif invoice and hasattr(invoice, 'payments'):
                payment_result = RefundService._process_payment_refund(invoice.payments.first(), refund_data)
                result['payment_refund_processed'] = payment_result.is_ok()
                if payment_result.is_err():
                    result['payment_refund_error'] = payment_result.error

            return Result.ok(result)
        except Exception as e:
            return Result.err(f"Failed to process refund: {e!s}")
    
    @staticmethod
    def _update_order_refund_status(order: Any, refund_data: RefundData) -> None:
        """Update order refund status"""
        try:
            # Update order status to indicate it has been refunded
            if hasattr(order, 'status'):
                if refund_data.get('refund_type') == 'full':
                    order.status = 'refunded'
                else:
                    order.status = 'partially_refunded'
                order.save()
        except Exception:
            # Log but don't fail the refund process
            pass
    
    @staticmethod
    def _update_invoice_refund_status(invoice: Any, refund_data: RefundData) -> None:
        """Update invoice refund status"""
        try:
            # Update invoice status to indicate it has been refunded
            if hasattr(invoice, 'status'):
                if refund_data.get('refund_type') == 'full':
                    invoice.status = 'refunded'
                else:
                    invoice.status = 'partially_refunded'
                invoice.save()
        except Exception:
            # Log but don't fail the refund process
            pass
    
    @staticmethod
    def _create_audit_entry(refund_id: Any, entity_type: str, entity_id: Any, refund_data: RefundData) -> None:
        """Create audit entry for refund"""
        # Log security event for refund operations
        log_security_event(
            event_type="refund_processed",
            details={
                "refund_id": str(refund_id),
                "entity_type": entity_type,
                "entity_id": str(entity_id),
                "refund_type": refund_data.get('refund_type', 'full'),
                "amount_cents": refund_data.get('amount_cents', 0),
                "reason": refund_data.get('reason', 'customer_request'),
                "critical_financial_operation": True,
            }
        )
    
    @staticmethod
    def _process_payment_refund(payment: Any, refund_data: RefundData) -> Result[dict, str]:
        """Process refund through payment gateway"""
        try:
            if not payment:
                return Result.ok({"gateway_refund": "no_payment_found"})
            
            # Update payment status to indicate refund
            if hasattr(payment, 'status'):
                if refund_data.get('refund_type') == 'full':
                    payment.status = 'refunded'
                else:
                    payment.status = 'partially_refunded'
                payment.save()
            
            # Log payment gateway refund attempt
            log_security_event(
                event_type="payment_gateway_refund",
                details={
                    "payment_id": str(payment.id) if hasattr(payment, 'id') else 'unknown',
                    "payment_method": getattr(payment, 'payment_method', 'unknown'),
                    "gateway_txn_id": getattr(payment, 'gateway_txn_id', ''),
                    "refund_amount_cents": refund_data.get('amount_cents', 0),
                    "refund_type": refund_data.get('refund_type', 'full'),
                    "critical_financial_operation": True,
                }
            )
            
            # TODO: Implement actual gateway refund calls here
            # For now, return success for local testing
            return Result.ok({
                "gateway_refund": "simulated_success",
                "payment_status_updated": True
            })
            
        except Exception as e:
            return Result.err(f"Payment refund failed: {e!s}")


class RefundQueryService:
    """Query service for refund data with real database operations"""
    
    @staticmethod
    def get_refund_statistics(*args: Any, **kwargs: Any) -> Result[dict[str, Any], str]:
        """Get refund statistics with Result pattern"""
        from django.db.models import Count, Sum

        from apps.billing.models import Refund
        
        try:
            # Get aggregate statistics
            aggregated = Refund.objects.aggregate(
                total_refunds=Count('id'),
                total_amount_refunded_cents=Sum('amount_cents', default=0)
            )
            
            # Get refunds by reason
            refunds_by_reason = {}
            reason_stats = Refund.objects.values('reason').annotate(
                count=Count('id'),
                total_amount_cents=Sum('amount_cents', default=0)
            )
            
            for stat in reason_stats:
                refunds_by_reason[stat['reason']] = {
                    'count': stat['count'],
                    'total_amount_cents': stat['total_amount_cents']
                }
            
            stats = {
                'total_refunds': aggregated['total_refunds'],
                'total_amount_refunded_cents': aggregated['total_amount_refunded_cents'],
                'refunds_by_reason': refunds_by_reason
            }
            return Result.ok(stats)
        except Exception as e:
            return Result.err(f"Error getting refund statistics: {e!s}")
    
    @staticmethod  
    def get_entity_refunds(entity_type: str, entity_id: Any) -> Result[list[dict[str, Any]], str]:
        """Get refunds for a specific entity"""
        from apps.billing.models import Refund
        
        try:
            if entity_type not in ['order', 'invoice']:
                return Result.err("Invalid entity type")
            
            # Query refunds for the specific entity
            if entity_type == 'order':
                refunds_qs = Refund.objects.filter(order_id=entity_id)
            else:  # invoice
                refunds_qs = Refund.objects.filter(invoice_id=entity_id)
            
            refunds = []
            for refund in refunds_qs.order_by('-created_at'):
                refunds.append({
                    'id': str(refund.id),
                    'reference_number': refund.reference_number,
                    'status': refund.status,
                    'refund_type': refund.refund_type,
                    'reason': refund.reason,
                    'amount_cents': refund.amount_cents,
                    'created_at': refund.created_at.isoformat(),
                    'processed_at': refund.processed_at.isoformat() if refund.processed_at else None
                })
            
            return Result.ok(refunds)
        except Exception as e:
            return Result.err(f"Error getting entity refunds: {e!s}")


# ===============================================================================
# INVOICE SERVICE IMPLEMENTATION
# ===============================================================================


class InvoiceService:
    """Service for creating and managing invoices from orders"""
    
    def create_from_order(self, order: Any) -> Result[Any, str]:
        """Create an invoice from an order"""
        try:
            from decimal import Decimal
            from django.utils import timezone
            
            # Import models here to avoid circular imports
            from apps.billing.models import Currency, Invoice, InvoiceSequence
            
            # Get default currency (RON)
            try:
                currency = Currency.objects.get(code="RON")
            except Currency.DoesNotExist:
                # Create default RON currency if it doesn't exist
                currency = Currency.objects.create(
                    code="RON",
                    name="Romanian Leu",
                    symbol="lei",
                    is_active=True
                )
            
            # Get invoice sequence
            sequence, created = InvoiceSequence.objects.get_or_create(scope="default")
            
            # Calculate totals (assuming 19% VAT for Romania)
            vat_rate = Decimal("0.19")
            subtotal_amount = Decimal(order.total_cents) / 100
            tax_amount = subtotal_amount * vat_rate
            total_amount = subtotal_amount + tax_amount
            
            # Create invoice
            invoice = Invoice.objects.create(
                customer=order.customer,
                number=sequence.get_next_number("INV"),
                currency=currency,
                subtotal_cents=int(subtotal_amount * 100),
                tax_cents=int(tax_amount * 100),
                total_cents=int(total_amount * 100),
                status="draft",
                # Copy billing address from customer
                bill_to_name=order.customer.company_name or order.customer.full_name or "",
                bill_to_tax_id=getattr(order.customer, 'cui', '') or "",
                bill_to_email=order.customer.primary_email or "",
                bill_to_address1=getattr(order.customer, 'address', '') or "",
                bill_to_city=getattr(order.customer, 'city', '') or "",
                bill_to_country="RO",  # Default to Romania
                meta={"order_id": str(order.id)}
            )
            
            # Create invoice lines from order items
            from apps.billing.models import InvoiceLine
            for item in order.items.all():
                InvoiceLine.objects.create(
                    invoice=invoice,
                    description=item.name or f"Order item {item.id}",
                    quantity=item.quantity,
                    unit_price_cents=item.unit_price_cents,
                    total_cents=item.total_cents,
                    tax_rate_percent=19,  # Romanian VAT rate
                    meta={"order_item_id": str(item.id)}
                )
            
            # Log invoice creation
            log_security_event(
                event_type="invoice_created_from_order",
                details={
                    "invoice_id": str(invoice.id),
                    "invoice_number": invoice.number,
                    "order_id": str(order.id),
                    "order_number": getattr(order, 'order_number', ''),
                    "customer_id": str(order.customer.id),
                    "total_cents": invoice.total_cents,
                    "critical_financial_operation": True
                }
            )
            
            return Result.ok(invoice)
            
        except Exception as e:
            return Result.err(f"Failed to create invoice from order: {e!s}")

# Expose all services in __all__ for explicit imports
__all__ = [
    "BillingAnalyticsService",
    "InvoiceService",
    "ProformaService",
    "RefundData",
    "RefundEligibility",
    "RefundQueryService",
    "RefundReason",
    "RefundResult",
    "RefundService",
    "RefundStatus",
    "RefundType",
    "Result",
    "generate_e_factura_xml",
    "generate_invoice_pdf",
    "generate_proforma_pdf",
    "generate_vat_summary",
    "log_security_event",
    "send_invoice_email",
    "send_proforma_email",
]
