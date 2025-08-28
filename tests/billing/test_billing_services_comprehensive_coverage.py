# ===============================================================================
# COMPREHENSIVE BILLING SERVICES TEST SUITE - COVERAGE FOCUSED
# ===============================================================================
"""
Comprehensive test suite for billing services targeting 85%+ coverage.
Focuses on RefundService, bidirectional synchronization, and all edge cases.

Priority Areas from Coverage Analysis:
- services.py: 48.69% → 85%+ (SECONDARY TARGET)
- RefundService methods - comprehensive refund testing
- Bidirectional order/invoice refund synchronization
- Payment processing integration
- Error handling and edge cases
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import Mock, patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment
from apps.billing.services import (
    RefundData,
    RefundEligibility,
    RefundQueryService,
    RefundReason,
    RefundResult,
    RefundService,
    RefundType,
)
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class RefundServiceComprehensiveCoverageTestCase(TransactionTestCase):
    """
    Comprehensive test suite for RefundService targeting 85%+ coverage.
    Uses TransactionTestCase for proper atomic transaction testing.
    """

    def setUp(self) -> None:
        """Set up test data with proper relationships."""
        # Create Currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )
        
        # Create test users
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True,
            staff_role='admin'
        )
        
        # Create test customer
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='customer@test.com',
            status='active'
        )
        
        # Create customer membership for access control
        CustomerMembership.objects.create(
            user=self.staff_user,
            customer=self.customer,
            role='owner'
        )
        
        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.currency,
            status='paid',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            bill_to_name=self.customer.name,
            bill_to_email=self.customer.primary_email,
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            meta={}
        )
        
        # Create payment for the invoice
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=11900,
            currency=self.currency,
            payment_method='bank',
            status='succeeded',
            created_by=self.staff_user
        )

    def _create_test_order(self) -> Any:
        """Create a mock order for testing."""
        mock_order = Mock()
        mock_order.id = uuid.uuid4()
        mock_order.customer = self.customer
        mock_order.status = 'completed'
        mock_order.total_cents = 15000
        mock_order.order_number = 'ORD-000001'
        mock_order.meta = {}
        mock_order.invoice = self.invoice
        mock_order.save = Mock()
        return mock_order

    def _create_refund_data(
        self, 
        refund_type: RefundType = RefundType.FULL,
        amount_cents: int = 0,
        reason: RefundReason = RefundReason.CUSTOMER_REQUEST,
        process_payment: bool = False
    ) -> RefundData:
        """Create test refund data."""
        return {
            'refund_type': refund_type,
            'amount_cents': amount_cents,
            'reason': reason,
            'notes': 'Test refund',
            'initiated_by': self.staff_user,
            'external_refund_id': None,
            'process_payment_refund': process_payment
        }

    # ===============================================================================
    # REFUND ORDER TESTS - HIGH PRIORITY MISSING COVERAGE
    # ===============================================================================

    def test_refund_order_order_not_found(self) -> None:
        """Test refund_order with non-existent order (Line 157-158)."""
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            from django.core.exceptions import ObjectDoesNotExist
            mock_select.return_value.get.side_effect = ObjectDoesNotExist()
            
            refund_data = self._create_refund_data()
            result = RefundService.refund_order(uuid.uuid4(), refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("not found", result.error)

    def test_refund_order_eligibility_check_failed(self) -> None:
        """Test refund_order with failed eligibility check (Line 164-165)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                mock_validate.return_value = Err("Not eligible")
                
                refund_data = self._create_refund_data()
                result = RefundService.refund_order(mock_order.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertEqual(result.error, "Not eligible")

    def test_refund_order_not_eligible(self) -> None:
        """Test refund_order with ineligible order (Line 168-169)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': False,
                    'reason': 'Order already refunded',
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': 15000
                }
                mock_validate.return_value = Ok(eligibility)
                
                refund_data = self._create_refund_data()
                result = RefundService.refund_order(mock_order.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertIn("not eligible for refund", result.error)

    def test_refund_order_partial_amount_exceeds_max(self) -> None:
        """Test refund_order with partial amount exceeding maximum (Line 176-177)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 5000,
                    'already_refunded_cents': 10000
                }
                mock_validate.return_value = Ok(eligibility)
                
                refund_data = self._create_refund_data(
                    refund_type=RefundType.PARTIAL,
                    amount_cents=6000  # Exceeds max of 5000
                )
                result = RefundService.refund_order(mock_order.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertIn("exceeds maximum refundable amount", result.error)

    def test_refund_order_bidirectional_process_failed(self) -> None:
        """Test refund_order with failed bidirectional processing (Line 191-192)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 15000,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                with patch.object(RefundService, '_process_bidirectional_refund') as mock_process:
                    mock_process.return_value = Err("Processing failed")
                    
                    refund_data = self._create_refund_data()
                    result = RefundService.refund_order(mock_order.id, refund_data)
                    
                    self.assertTrue(result.is_err())

    def test_refund_order_success_full_refund(self) -> None:
        """Test refund_order successful full refund (Line 173, 194-212)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 15000,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                with patch.object(RefundService, '_process_bidirectional_refund') as mock_process:
                    refund_result: RefundResult = {
                        'refund_id': uuid.uuid4(),
                        'order_id': mock_order.id,
                        'invoice_id': self.invoice.id,
                        'refund_type': RefundType.FULL,
                        'amount_refunded_cents': 15000,
                        'order_status_updated': True,
                        'invoice_status_updated': True,
                        'payment_refund_processed': False,
                        'audit_entries_created': 2
                    }
                    mock_process.return_value = Ok(refund_result)
                    
                    with patch('apps.common.validators.log_security_event') as mock_log:
                        refund_data = self._create_refund_data()
                        result = RefundService.refund_order(mock_order.id, refund_data)
                        
                        self.assertTrue(result.is_ok())
                        returned_result = result.unwrap()
                        self.assertEqual(returned_result['refund_type'], RefundType.FULL)
                        self.assertEqual(returned_result['amount_refunded_cents'], 15000)
                        mock_log.assert_called_once()

    def test_refund_order_success_partial_refund(self) -> None:
        """Test refund_order successful partial refund (Line 175)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = mock_order
            
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 15000,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                with patch.object(RefundService, '_process_bidirectional_refund') as mock_process:
                    refund_result: RefundResult = {
                        'refund_id': uuid.uuid4(),
                        'order_id': mock_order.id,
                        'invoice_id': None,
                        'refund_type': RefundType.PARTIAL,
                        'amount_refunded_cents': 5000,
                        'order_status_updated': True,
                        'invoice_status_updated': False,
                        'payment_refund_processed': False,
                        'audit_entries_created': 1
                    }
                    mock_process.return_value = Ok(refund_result)
                    
                    with patch('apps.common.validators.log_security_event') as mock_log:
                        refund_data = self._create_refund_data(
                            refund_type=RefundType.PARTIAL,
                            amount_cents=5000
                        )
                        result = RefundService.refund_order(mock_order.id, refund_data)
                        
                        self.assertTrue(result.is_ok())
                        returned_result = result.unwrap()
                        self.assertEqual(returned_result['amount_refunded_cents'], 5000)
                        
                        # Verify security event was logged
                        self.assertTrue(mock_log.called)

    def test_refund_order_unexpected_exception(self) -> None:
        """Test refund_order with unexpected exception (Line 214-216)."""
        with patch('apps.orders.models.Order.objects.select_related', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService.refund_order(uuid.uuid4(), refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to process refund", result.error)

    # ===============================================================================
    # REFUND INVOICE TESTS - HIGH PRIORITY MISSING COVERAGE
    # ===============================================================================

    def test_refund_invoice_invoice_not_found(self) -> None:
        """Test refund_invoice with non-existent invoice (Line 244-245)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            from django.core.exceptions import ObjectDoesNotExist
            mock_select.return_value.get.side_effect = ObjectDoesNotExist()
            
            refund_data = self._create_refund_data()
            result = RefundService.refund_invoice(uuid.uuid4(), refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("not found", result.error)

    def test_refund_invoice_eligibility_check_failed(self) -> None:
        """Test refund_invoice with failed eligibility check (Line 251-252)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = self.invoice
            
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                mock_validate.return_value = Err("Not eligible")
                
                refund_data = self._create_refund_data()
                result = RefundService.refund_invoice(self.invoice.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertEqual(result.error, "Not eligible")

    def test_refund_invoice_not_eligible(self) -> None:
        """Test refund_invoice with ineligible invoice (Line 255-256)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = self.invoice
            
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': False,
                    'reason': 'Invoice already refunded',
                    'max_refund_amount_cents': 0,
                    'already_refunded_cents': 11900
                }
                mock_validate.return_value = Ok(eligibility)
                
                refund_data = self._create_refund_data()
                result = RefundService.refund_invoice(self.invoice.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertIn("not eligible for refund", result.error)

    def test_refund_invoice_partial_amount_exceeds_max(self) -> None:
        """Test refund_invoice with partial amount exceeding maximum (Line 263-264)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = self.invoice
            
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 5000,
                    'already_refunded_cents': 6900
                }
                mock_validate.return_value = Ok(eligibility)
                
                refund_data = self._create_refund_data(
                    refund_type=RefundType.PARTIAL,
                    amount_cents=6000  # Exceeds max of 5000
                )
                result = RefundService.refund_invoice(self.invoice.id, refund_data)
                
                self.assertTrue(result.is_err())
                self.assertIn("exceeds maximum refundable amount", result.error)

    def test_refund_invoice_success_full_refund(self) -> None:
        """Test refund_invoice successful full refund (Line 259-260, 281-299)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = self.invoice
            
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 11900,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                with patch.object(RefundService, '_process_bidirectional_refund') as mock_process:
                    refund_result: RefundResult = {
                        'refund_id': uuid.uuid4(),
                        'order_id': None,
                        'invoice_id': self.invoice.id,
                        'refund_type': RefundType.FULL,
                        'amount_refunded_cents': 11900,
                        'order_status_updated': False,
                        'invoice_status_updated': True,
                        'payment_refund_processed': False,
                        'audit_entries_created': 1
                    }
                    mock_process.return_value = Ok(refund_result)
                    
                    with patch('apps.common.validators.log_security_event') as mock_log:
                        refund_data = self._create_refund_data()
                        result = RefundService.refund_invoice(self.invoice.id, refund_data)
                        
                        self.assertTrue(result.is_ok())
                        returned_result = result.unwrap()
                        self.assertEqual(returned_result['refund_type'], RefundType.FULL)
                        mock_log.assert_called_once()

    def test_refund_invoice_success_partial_refund(self) -> None:
        """Test refund_invoice successful partial refund (Line 262)."""
        with patch('apps.billing.models.Invoice.objects.select_related') as mock_select:
            mock_select.return_value.get.return_value = self.invoice
            
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 11900,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                with patch.object(RefundService, '_process_bidirectional_refund') as mock_process:
                    refund_result: RefundResult = {
                        'refund_id': uuid.uuid4(),
                        'order_id': None,
                        'invoice_id': self.invoice.id,
                        'refund_type': RefundType.PARTIAL,
                        'amount_refunded_cents': 5000,
                        'order_status_updated': False,
                        'invoice_status_updated': True,
                        'payment_refund_processed': False,
                        'audit_entries_created': 1
                    }
                    mock_process.return_value = Ok(refund_result)
                    
                    with patch('apps.common.validators.log_security_event') as mock_log:
                        refund_data = self._create_refund_data(
                            refund_type=RefundType.PARTIAL,
                            amount_cents=5000
                        )
                        result = RefundService.refund_invoice(self.invoice.id, refund_data)
                        
                        self.assertTrue(result.is_ok())
                        returned_result = result.unwrap()
                        self.assertEqual(returned_result['amount_refunded_cents'], 5000)
                        
                        # Verify security event was logged
                        self.assertTrue(mock_log.called)

    def test_refund_invoice_unexpected_exception(self) -> None:
        """Test refund_invoice with unexpected exception (Line 301-303)."""
        with patch('apps.billing.models.Invoice.objects.select_related', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService.refund_invoice(uuid.uuid4(), refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to process refund", result.error)

    # ===============================================================================
    # BIDIRECTIONAL REFUND PROCESSING TESTS - HIGH PRIORITY COMPLEX LOGIC
    # ===============================================================================

    def test_process_bidirectional_refund_order_no_invoice_found(self) -> None:
        """Test _process_bidirectional_refund with order but no invoice (Line 332-335)."""
        mock_order = self._create_test_order()
        mock_order.invoice = None  # No primary invoice
        
        with patch('apps.billing.models.Invoice.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = None  # No related invoices
            
            refund_data = self._create_refund_data()
            result = RefundService._process_bidirectional_refund(
                order=mock_order,
                invoice=None,
                refund_id=uuid.uuid4(),
                refund_amount_cents=5000,
                refund_data=refund_data
            )
            
            # Should still succeed even without invoice
            self.assertTrue(result.is_ok())

    def test_process_bidirectional_refund_invoice_find_orders(self) -> None:
        """Test _process_bidirectional_refund with invoice finding orders (Line 337-340)."""
        mock_order = self._create_test_order()
        
        with patch.object(self.invoice, 'orders') as mock_orders:
            mock_orders.all.return_value = [mock_order]
            mock_orders.first.return_value = mock_order
            
            with patch.object(RefundService, '_update_invoice_refund_status') as mock_update_invoice:
                mock_update_invoice.return_value = Ok(True)
                
                with patch.object(RefundService, '_update_order_refund_status') as mock_update_order:
                    mock_update_order.return_value = Ok(True)
                    
                    refund_data = self._create_refund_data()
                    result = RefundService._process_bidirectional_refund(
                        order=None,
                        invoice=self.invoice,
                        refund_id=uuid.uuid4(),
                        refund_amount_cents=5000,
                        refund_data=refund_data
                    )
                    
                    self.assertTrue(result.is_ok())
                    returned_result = result.unwrap()
                    self.assertTrue(returned_result['order_status_updated'])
                    self.assertTrue(returned_result['invoice_status_updated'])

    def test_process_bidirectional_refund_order_update_failed(self) -> None:
        """Test _process_bidirectional_refund with order update failure (Line 349-350)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_update_order_refund_status') as mock_update:
            mock_update.return_value = Err("Order update failed")
            
            refund_data = self._create_refund_data()
            result = RefundService._process_bidirectional_refund(
                order=mock_order,
                invoice=None,
                refund_id=uuid.uuid4(),
                refund_amount_cents=5000,
                refund_data=refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertEqual(result.error, "Order update failed")

    def test_process_bidirectional_refund_invoice_update_failed(self) -> None:
        """Test _process_bidirectional_refund with invoice update failure (Line 361-362)."""
        with patch.object(RefundService, '_update_invoice_refund_status') as mock_update:
            mock_update.return_value = Err("Invoice update failed")
            
            refund_data = self._create_refund_data()
            result = RefundService._process_bidirectional_refund(
                order=None,
                invoice=self.invoice,
                refund_id=uuid.uuid4(),
                refund_amount_cents=5000,
                refund_data=refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertEqual(result.error, "Invoice update failed")

    def test_process_bidirectional_refund_with_payment_processing(self) -> None:
        """Test _process_bidirectional_refund with payment refund processing (Line 367-377)."""
        with patch.object(RefundService, '_update_invoice_refund_status') as mock_update_invoice:
            mock_update_invoice.return_value = Ok(True)
            
            with patch.object(RefundService, '_process_payment_refund') as mock_payment:
                mock_payment.return_value = Ok({'success': True})
                
                refund_data = self._create_refund_data(process_payment=True)
                result = RefundService._process_bidirectional_refund(
                    order=None,
                    invoice=self.invoice,
                    refund_id=uuid.uuid4(),
                    refund_amount_cents=5000,
                    refund_data=refund_data
                )
                
                self.assertTrue(result.is_ok())
                returned_result = result.unwrap()
                self.assertTrue(returned_result['payment_refund_processed'])

    def test_process_bidirectional_refund_payment_processing_failed(self) -> None:
        """Test _process_bidirectional_refund with payment processing failure (Line 374-377)."""
        with patch.object(RefundService, '_update_invoice_refund_status') as mock_update_invoice:
            mock_update_invoice.return_value = Ok(True)
            
            with patch.object(RefundService, '_process_payment_refund') as mock_payment:
                mock_payment.return_value = Err("Payment processing failed")
                
                refund_data = self._create_refund_data(process_payment=True)
                result = RefundService._process_bidirectional_refund(
                    order=None,
                    invoice=self.invoice,
                    refund_id=uuid.uuid4(),
                    refund_amount_cents=5000,
                    refund_data=refund_data
                )
                
                # Should still succeed even if payment processing fails
                self.assertTrue(result.is_ok())
                returned_result = result.unwrap()
                self.assertFalse(returned_result['payment_refund_processed'])

    def test_process_bidirectional_refund_unexpected_exception(self) -> None:
        """Test _process_bidirectional_refund with unexpected exception (Line 394-396)."""
        with patch.object(RefundService, '_update_invoice_refund_status', side_effect=Exception("Unexpected error")):
            refund_data = self._create_refund_data()
            result = RefundService._process_bidirectional_refund(
                order=None,
                invoice=self.invoice,
                refund_id=uuid.uuid4(),
                refund_amount_cents=5000,
                refund_data=refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to process bidirectional refund", result.error)

    # ===============================================================================
    # ORDER REFUND STATUS UPDATE TESTS
    # ===============================================================================

    def test_update_order_refund_status_full_refund(self) -> None:
        """Test _update_order_refund_status with full refund (Line 415-416)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=0):
            with patch('apps.orders.services.OrderService.update_order_status') as mock_update_status:
                mock_update_status.return_value = Ok(True)
                
                refund_data = self._create_refund_data()
                result = RefundService._update_order_refund_status(
                    mock_order, 15000, refund_data
                )
                
                self.assertTrue(result.is_ok())
                # Order should be marked as 'refunded'
                mock_update_status.assert_called_once()
                status_change = mock_update_status.call_args[0][1]
                self.assertEqual(status_change['new_status'], 'refunded')

    def test_update_order_refund_status_partial_refund(self) -> None:
        """Test _update_order_refund_status with partial refund (Line 417-418)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=5000):
            with patch('apps.orders.services.OrderService.update_order_status') as mock_update_status:
                mock_update_status.return_value = Ok(True)
                
                refund_data = self._create_refund_data()
                result = RefundService._update_order_refund_status(
                    mock_order, 5000, refund_data  # Total: 10000, less than 15000
                )
                
                self.assertTrue(result.is_ok())
                # Order should be marked as 'partially_refunded'
                status_change = mock_update_status.call_args[0][1]
                self.assertEqual(status_change['new_status'], 'partially_refunded')

    def test_update_order_refund_status_service_failed(self) -> None:
        """Test _update_order_refund_status with service failure (Line 449-450)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=0):
            with patch('apps.orders.services.OrderService.update_order_status') as mock_update_status:
                mock_update_status.return_value = Err("Status update failed")
                
                refund_data = self._create_refund_data()
                result = RefundService._update_order_refund_status(
                    mock_order, 5000, refund_data
                )
                
                self.assertTrue(result.is_err())
                self.assertEqual(result.error, "Status update failed")

    def test_update_order_refund_status_unexpected_exception(self) -> None:
        """Test _update_order_refund_status with unexpected exception (Line 452-454)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService._update_order_refund_status(
                mock_order, 5000, refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to update order status", result.error)

    # ===============================================================================
    # INVOICE REFUND STATUS UPDATE TESTS
    # ===============================================================================

    def test_update_invoice_refund_status_full_refund(self) -> None:
        """Test _update_invoice_refund_status with full refund (Line 469-470)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', return_value=0):
            with patch('apps.common.validators.log_security_event') as mock_log:
                refund_data = self._create_refund_data()
                result = RefundService._update_invoice_refund_status(
                    self.invoice, 11900, refund_data
                )
                
                self.assertTrue(result.is_ok())
                self.invoice.refresh_from_db()
                self.assertEqual(self.invoice.status, 'refunded')
                mock_log.assert_called_once()

    def test_update_invoice_refund_status_partial_refund(self) -> None:
        """Test _update_invoice_refund_status with partial refund (Line 474)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', return_value=5000):
            with patch('apps.common.validators.log_security_event') as mock_log:
                refund_data = self._create_refund_data()
                result = RefundService._update_invoice_refund_status(
                    self.invoice, 5000, refund_data  # Total: 10000, less than 11900
                )
                
                self.assertTrue(result.is_ok())
                self.invoice.refresh_from_db()
                self.assertEqual(self.invoice.status, 'issued')  # Partial refunds keep as 'issued'
                mock_log.assert_called_once()

    def test_update_invoice_refund_status_unexpected_exception(self) -> None:
        """Test _update_invoice_refund_status with unexpected exception (Line 510-512)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService._update_invoice_refund_status(
                self.invoice, 5000, refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to update invoice status", result.error)

    # ===============================================================================
    # PAYMENT REFUND PROCESSING TESTS
    # ===============================================================================

    def test_process_payment_refund_no_payments_found(self) -> None:
        """Test _process_payment_refund with no payments to refund (Line 548-549)."""
        # Remove the payment we created in setUp
        self.payment.delete()
        
        refund_data = self._create_refund_data()
        result = RefundService._process_payment_refund(
            order=None,
            invoice=self.invoice,
            refund_amount_cents=5000,
            refund_data=refund_data
        )
        
        self.assertTrue(result.is_err())
        self.assertEqual(result.error, "No successful payments found to refund")

    def test_process_payment_refund_full_payment_refund(self) -> None:
        """Test _process_payment_refund with full payment refund (Line 564-565)."""
        refund_data = self._create_refund_data()
        result = RefundService._process_payment_refund(
            order=None,
            invoice=self.invoice,
            refund_amount_cents=11900,  # Full payment amount
            refund_data=refund_data
        )
        
        self.assertTrue(result.is_ok())
        returned_result = result.unwrap()
        self.assertEqual(returned_result['total_refunded_cents'], 11900)
        self.assertEqual(returned_result['payments_refunded'], 1)
        
        # Check payment status updated
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, 'refunded')

    def test_process_payment_refund_partial_payment_refund(self) -> None:
        """Test _process_payment_refund with partial payment refund (Line 566-567)."""
        refund_data = self._create_refund_data()
        result = RefundService._process_payment_refund(
            order=None,
            invoice=self.invoice,
            refund_amount_cents=5000,  # Partial amount
            refund_data=refund_data
        )
        
        self.assertTrue(result.is_ok())
        returned_result = result.unwrap()
        self.assertEqual(returned_result['total_refunded_cents'], 5000)
        
        # Check payment status updated
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, 'partially_refunded')

    def test_process_payment_refund_with_order_invoice(self) -> None:
        """Test _process_payment_refund with order having invoice (Line 540-546)."""
        mock_order = self._create_test_order()
        
        refund_data = self._create_refund_data()
        result = RefundService._process_payment_refund(
            order=mock_order,
            invoice=None,
            refund_amount_cents=5000,
            refund_data=refund_data
        )
        
        self.assertTrue(result.is_ok())

    def test_process_payment_refund_unexpected_exception(self) -> None:
        """Test _process_payment_refund with unexpected exception (Line 585-587)."""
        with patch('apps.billing.models.Payment.objects.filter', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService._process_payment_refund(
                order=None,
                invoice=self.invoice,
                refund_amount_cents=5000,
                refund_data=refund_data
            )
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to process payment refund", result.error)

    # ===============================================================================
    # REFUND ELIGIBILITY VALIDATION TESTS
    # ===============================================================================

    def test_validate_order_refund_eligibility_invalid_status(self) -> None:
        """Test _validate_order_refund_eligibility with invalid status (Line 597-603)."""
        mock_order = self._create_test_order()
        mock_order.status = 'draft'
        
        refund_data = self._create_refund_data()
        result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
        
        self.assertTrue(result.is_ok())
        eligibility = result.unwrap()
        self.assertFalse(eligibility['is_eligible'])
        self.assertIn("Cannot refund order in 'draft' status", eligibility['reason'])

    def test_validate_order_refund_eligibility_already_refunded(self) -> None:
        """Test _validate_order_refund_eligibility with fully refunded order (Line 609-615)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=15000):
            refund_data = self._create_refund_data()
            result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertFalse(eligibility['is_eligible'])
            self.assertEqual(eligibility['reason'], "Order has already been fully refunded")

    def test_validate_order_refund_eligibility_partial_zero_amount(self) -> None:
        """Test _validate_order_refund_eligibility with zero partial amount (Line 619-625)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=0):
            refund_data = self._create_refund_data(
                refund_type=RefundType.PARTIAL,
                amount_cents=0
            )
            result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertFalse(eligibility['is_eligible'])
            self.assertEqual(eligibility['reason'], "Refund amount must be greater than 0")

    def test_validate_order_refund_eligibility_partial_exceeds_max(self) -> None:
        """Test _validate_order_refund_eligibility with amount exceeding max (Line 627-633)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=5000):
            refund_data = self._create_refund_data(
                refund_type=RefundType.PARTIAL,
                amount_cents=12000  # Exceeds remaining 10000
            )
            result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertFalse(eligibility['is_eligible'])
            self.assertIn("exceeds available amount", eligibility['reason'])

    def test_validate_order_refund_eligibility_success(self) -> None:
        """Test _validate_order_refund_eligibility with eligible order (Line 635-640)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', return_value=5000):
            refund_data = self._create_refund_data()
            result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertTrue(eligibility['is_eligible'])
            self.assertEqual(eligibility['max_refund_amount_cents'], 10000)
            self.assertEqual(eligibility['already_refunded_cents'], 5000)

    def test_validate_order_refund_eligibility_unexpected_exception(self) -> None:
        """Test _validate_order_refund_eligibility with unexpected exception (Line 642-644)."""
        mock_order = self._create_test_order()
        
        with patch.object(RefundService, '_get_order_refunded_amount', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService._validate_order_refund_eligibility(mock_order, refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to validate eligibility", result.error)

    def test_validate_invoice_refund_eligibility_invalid_status(self) -> None:
        """Test _validate_invoice_refund_eligibility with invalid status (Line 654-660)."""
        self.invoice.status = 'draft'
        self.invoice.save()
        
        refund_data = self._create_refund_data()
        result = RefundService._validate_invoice_refund_eligibility(self.invoice, refund_data)
        
        self.assertTrue(result.is_ok())
        eligibility = result.unwrap()
        self.assertFalse(eligibility['is_eligible'])
        self.assertIn("Cannot refund invoice in 'draft' status", eligibility['reason'])

    def test_validate_invoice_refund_eligibility_already_refunded(self) -> None:
        """Test _validate_invoice_refund_eligibility with fully refunded invoice (Line 666-672)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', return_value=11900):
            refund_data = self._create_refund_data()
            result = RefundService._validate_invoice_refund_eligibility(self.invoice, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertFalse(eligibility['is_eligible'])
            self.assertEqual(eligibility['reason'], "Invoice has already been fully refunded")

    def test_validate_invoice_refund_eligibility_success(self) -> None:
        """Test _validate_invoice_refund_eligibility with eligible invoice (Line 692-697)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', return_value=0):
            refund_data = self._create_refund_data()
            result = RefundService._validate_invoice_refund_eligibility(self.invoice, refund_data)
            
            self.assertTrue(result.is_ok())
            eligibility = result.unwrap()
            self.assertTrue(eligibility['is_eligible'])
            self.assertEqual(eligibility['max_refund_amount_cents'], 11900)

    def test_validate_invoice_refund_eligibility_unexpected_exception(self) -> None:
        """Test _validate_invoice_refund_eligibility with unexpected exception (Line 699-701)."""
        with patch.object(RefundService, '_get_invoice_refunded_amount', side_effect=Exception("DB Error")):
            refund_data = self._create_refund_data()
            result = RefundService._validate_invoice_refund_eligibility(self.invoice, refund_data)
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to validate eligibility", result.error)

    # ===============================================================================
    # REFUND AMOUNT CALCULATION TESTS
    # ===============================================================================

    def test_get_order_refunded_amount_no_refunds(self) -> None:
        """Test _get_order_refunded_amount with no refunds in metadata (Line 708-709)."""
        mock_order = self._create_test_order()
        mock_order.meta = {}
        
        amount = RefundService._get_order_refunded_amount(mock_order)
        
        self.assertEqual(amount, 0)

    def test_get_order_refunded_amount_with_refunds(self) -> None:
        """Test _get_order_refunded_amount with refunds in metadata (Line 707-708)."""
        mock_order = self._create_test_order()
        mock_order.meta = {
            'refunds': [
                {'amount_cents': 5000},
                {'amount_cents': 3000}
            ]
        }
        
        amount = RefundService._get_order_refunded_amount(mock_order)
        
        self.assertEqual(amount, 8000)

    def test_get_invoice_refunded_amount_no_refunds(self) -> None:
        """Test _get_invoice_refunded_amount with no refunds in metadata (Line 716-717)."""
        self.invoice.meta = {}
        self.invoice.save()
        
        amount = RefundService._get_invoice_refunded_amount(self.invoice)
        
        self.assertEqual(amount, 0)

    def test_get_invoice_refunded_amount_with_refunds(self) -> None:
        """Test _get_invoice_refunded_amount with refunds in metadata (Line 715-716)."""
        self.invoice.meta = {
            'refunds': [
                {'amount_cents': 2000},
                {'amount_cents': 1500}
            ]
        }
        self.invoice.save()
        
        amount = RefundService._get_invoice_refunded_amount(self.invoice)
        
        self.assertEqual(amount, 3500)

    # ===============================================================================
    # GET REFUND ELIGIBILITY TESTS
    # ===============================================================================

    def test_get_refund_eligibility_invalid_entity_type(self) -> None:
        """Test get_refund_eligibility with invalid entity type (Line 757-758)."""
        result = RefundService.get_refund_eligibility(
            'invalid_type', uuid.uuid4(), 5000
        )
        
        self.assertTrue(result.is_err())
        self.assertIn("Invalid entity_type", result.error)

    def test_get_refund_eligibility_order_success(self) -> None:
        """Test get_refund_eligibility for order (Line 747-750)."""
        mock_order = self._create_test_order()
        
        with patch('apps.orders.models.Order.objects.get', return_value=mock_order):
            with patch.object(RefundService, '_validate_order_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 10000,
                    'already_refunded_cents': 5000
                }
                mock_validate.return_value = Ok(eligibility)
                
                result = RefundService.get_refund_eligibility('order', mock_order.id, 5000)
                
                self.assertTrue(result.is_ok())
                returned_eligibility = result.unwrap()
                self.assertTrue(returned_eligibility['is_eligible'])

    def test_get_refund_eligibility_invoice_success(self) -> None:
        """Test get_refund_eligibility for invoice (Line 752-755)."""
        with patch('apps.billing.models.Invoice.objects.get', return_value=self.invoice):
            with patch.object(RefundService, '_validate_invoice_refund_eligibility') as mock_validate:
                eligibility: RefundEligibility = {
                    'is_eligible': True,
                    'reason': 'Eligible',
                    'max_refund_amount_cents': 11900,
                    'already_refunded_cents': 0
                }
                mock_validate.return_value = Ok(eligibility)
                
                result = RefundService.get_refund_eligibility('invoice', self.invoice.id, 5000)
                
                self.assertTrue(result.is_ok())
                returned_eligibility = result.unwrap()
                self.assertTrue(returned_eligibility['is_eligible'])

    def test_get_refund_eligibility_unexpected_exception(self) -> None:
        """Test get_refund_eligibility with unexpected exception (Line 760-762)."""
        with patch('apps.billing.models.Invoice.objects.get', side_effect=Exception("DB Error")):
            result = RefundService.get_refund_eligibility('invoice', uuid.uuid4(), 5000)
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to check eligibility", result.error)


class RefundQueryServiceComprehensiveCoverageTestCase(TestCase):
    """Test RefundQueryService for comprehensive coverage."""

    def setUp(self) -> None:
        """Set up test data."""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            name='Test Company',
            customer_type='company',
            primary_email='test@example.com',
            status='active'
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.currency,
            status='paid',
            total_cents=10000,
            meta={}
        )

    def test_get_entity_refunds_order_with_refunds(self) -> None:
        """Test get_entity_refunds for order with refund history (Line 780-781)."""
        mock_order = Mock()
        mock_order.meta = {
            'refunds': [
                {'refund_id': '123', 'amount_cents': 5000},
                {'refund_id': '456', 'amount_cents': 3000}
            ]
        }
        
        with patch('apps.orders.models.Order.objects.get', return_value=mock_order):
            result = RefundQueryService.get_entity_refunds('order', uuid.uuid4())
            
            self.assertTrue(result.is_ok())
            refunds = result.unwrap()
            self.assertEqual(len(refunds), 2)

    def test_get_entity_refunds_order_no_refunds(self) -> None:
        """Test get_entity_refunds for order without refunds (Line 775, 789)."""
        mock_order = Mock()
        mock_order.meta = {}
        
        with patch('apps.orders.models.Order.objects.get', return_value=mock_order):
            result = RefundQueryService.get_entity_refunds('order', uuid.uuid4())
            
            self.assertTrue(result.is_ok())
            refunds = result.unwrap()
            self.assertEqual(len(refunds), 0)

    def test_get_entity_refunds_invoice_with_refunds(self) -> None:
        """Test get_entity_refunds for invoice with refund history (Line 786-787)."""
        self.invoice.meta = {
            'refunds': [
                {'refund_id': '789', 'amount_cents': 2000}
            ]
        }
        self.invoice.save()
        
        with patch('apps.billing.models.Invoice.objects.get', return_value=self.invoice):
            result = RefundQueryService.get_entity_refunds('invoice', self.invoice.id)
            
            self.assertTrue(result.is_ok())
            refunds = result.unwrap()
            self.assertEqual(len(refunds), 1)
            self.assertEqual(refunds[0]['amount_cents'], 2000)

    def test_get_entity_refunds_unexpected_exception(self) -> None:
        """Test get_entity_refunds with unexpected exception (Line 791-793)."""
        with patch('apps.orders.models.Order.objects.get', side_effect=Exception("DB Error")):
            result = RefundQueryService.get_entity_refunds('order', uuid.uuid4())
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to get refund history", result.error)

    def test_get_refund_statistics_success(self) -> None:
        """Test get_refund_statistics successful execution (Line 808-819)."""
        result = RefundQueryService.get_refund_statistics(
            customer_id=self.customer.id,
            date_from='2024-01-01',
            date_to='2024-12-31'
        )
        
        self.assertTrue(result.is_ok())
        stats = result.unwrap()
        
        # Check default structure
        self.assertIn('total_refunds', stats)
        self.assertIn('total_amount_refunded_cents', stats)
        self.assertIn('refunds_by_reason', stats)
        self.assertIn('refunds_by_type', stats)
        self.assertIn('orders_refunded', stats)
        self.assertIn('invoices_refunded', stats)

    def test_get_refund_statistics_unexpected_exception(self) -> None:
        """Test get_refund_statistics with unexpected exception (Line 822-824)."""
        with patch('apps.orders.models.Order', side_effect=Exception("DB Error")):
            result = RefundQueryService.get_refund_statistics()
            
            self.assertTrue(result.is_err())
            self.assertIn("Failed to get refund statistics", result.error)
