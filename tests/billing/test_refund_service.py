"""
Comprehensive tests for RefundService
Tests the critical financial refund system with bidirectional synchronization.
"""

import uuid
from decimal import Decimal
from typing import Any

import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import transaction

from apps.billing.services import (
    RefundService,
    RefundQueryService,
    RefundData,
    RefundType,
    RefundReason,
    RefundStatus
)
from apps.common.types import Ok, Err

User = get_user_model()

class RefundServiceTestCase(TestCase):
    """Test cases for the RefundService"""

    def setUp(self):
        """Set up test data"""
        # Create test user
        self.user = User.objects.create_user(
            email='admin@example.com',
            password='admin123'
        )
        
        # Create test customer
        from apps.customers.models import Customer, CustomerTaxProfile
        self.customer = Customer.objects.create(
            name='Test Company',
            customer_type='company',
            company_name='Test Company',
            status='active'
        )
        
        # Create customer tax profile
        self.customer_tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='12345678',
            vat_number='RO12345678'
        )
        
        # Create test currency
        from apps.billing.models import Currency
        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'symbol': 'lei', 'decimals': 2}
        )
        
        # Create test order
        from apps.orders.models import Order
        self.order = Order.objects.create(
            order_number='ORD-2024-0001',
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,        # 19.00 RON (19% VAT)
            total_cents=11900,     # 119.00 RON
            status='completed',
            customer_email='test@company.com',
            customer_name=self.customer.company_name
        )
        
        # Create test invoice
        from apps.billing.models import Invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-0001',
            status='paid',
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900
        )
        
        # Link order to invoice
        self.order.invoice = self.invoice
        self.order.save()
        
        # Create test payment
        from apps.billing.models import Payment
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            status='succeeded',
            amount_cents=11900,
            currency=self.currency,
            gateway_txn_id='test_txn_123'
        )

    def test_order_full_refund_success(self):
        """Test successful full refund of an order"""
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,  # Ignored for full refunds
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Customer requested full refund',
            'initiated_by': self.user,
            'external_refund_id': 'stripe_refund_123',
            'process_payment_refund': True
        }
        
        result = RefundService.refund_order(self.order.id, refund_data)
        
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        
        # Verify result structure
        self.assertEqual(refund_result['order_id'], self.order.id)
        self.assertEqual(refund_result['invoice_id'], self.invoice.id)
        self.assertEqual(refund_result['refund_type'], RefundType.FULL)
        self.assertEqual(refund_result['amount_refunded_cents'], 11900)
        self.assertTrue(refund_result['order_status_updated'])
        self.assertTrue(refund_result['invoice_status_updated'])
        self.assertTrue(refund_result['payment_refund_processed'])
        self.assertEqual(refund_result['audit_entries_created'], 2)
        
        # Verify order status updated
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'refunded')
        
        # Verify invoice status updated
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, 'refunded')
        self.assertIn('refunds', self.invoice.meta)
        self.assertEqual(len(self.invoice.meta['refunds']), 1)
        
        # Verify payment status updated
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, 'refunded')

    def test_order_partial_refund_success(self):
        """Test successful partial refund of an order"""
        refund_amount = 5000  # 50.00 RON partial refund
        
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': refund_amount,
            'reason': RefundReason.SERVICE_FAILURE,
            'notes': 'Partial service failure compensation',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(self.order.id, refund_data)
        
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        
        # Verify result
        self.assertEqual(refund_result['refund_type'], RefundType.PARTIAL)
        self.assertEqual(refund_result['amount_refunded_cents'], refund_amount)
        self.assertFalse(refund_result['payment_refund_processed'])
        
        # Verify order status updated to partially refunded
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'partially_refunded')

    def test_invoice_full_refund_success(self):
        """Test successful full refund of an invoice"""
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.DUPLICATE_PAYMENT,
            'notes': 'Duplicate payment detected',
            'initiated_by': self.user,
            'external_refund_id': 'paypal_refund_456',
            'process_payment_refund': True
        }
        
        result = RefundService.refund_invoice(self.invoice.id, refund_data)
        
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        
        # Verify bidirectional update
        self.assertEqual(refund_result['order_id'], self.order.id)
        self.assertEqual(refund_result['invoice_id'], self.invoice.id)
        self.assertTrue(refund_result['order_status_updated'])
        self.assertTrue(refund_result['invoice_status_updated'])
        
        # Verify both entities updated
        self.order.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual(self.order.status, 'refunded')
        self.assertEqual(self.invoice.status, 'refunded')

    def test_refund_nonexistent_order(self):
        """Test refunding nonexistent order returns error"""
        fake_id = uuid.uuid4()
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(fake_id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn('not found', result.error)

    def test_refund_draft_order_rejected(self):
        """Test refunding draft order is rejected"""
        # Create draft order
        from apps.orders.models import Order
        draft_order = Order.objects.create(
            order_number='ORD-2024-0002',
            customer=self.customer,
            currency=self.currency,
            total_cents=10000,
            status='draft'
        )
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(draft_order.id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn('not eligible for refund', result.error)

    def test_double_refund_prevention(self):
        """Test that double refunds are prevented"""
        # First refund
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'First refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result1 = RefundService.refund_order(self.order.id, refund_data)
        self.assertTrue(result1.is_ok())
        
        # Second refund attempt should fail
        refund_data['notes'] = 'Second refund attempt'
        result2 = RefundService.refund_order(self.order.id, refund_data)
        
        self.assertTrue(result2.is_err())
        # The actual error message indicates status transition issue
        self.assertTrue('refunded' in result2.error.lower() or 'already' in result2.error.lower())

    def test_partial_refund_amount_validation(self):
        """Test partial refund amount validation"""
        # Attempt refund larger than order total
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 20000,  # More than order total of 11900
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Invalid amount',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(self.order.id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn('exceeds available amount', result.error)

    def test_zero_amount_partial_refund_rejected(self):
        """Test zero amount partial refund is rejected"""
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Zero refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(self.order.id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn('must be greater than 0', result.error)

    def test_sequential_partial_refunds(self):
        """Test multiple sequential partial refunds"""
        # First partial refund
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 4000,
            'reason': RefundReason.SERVICE_FAILURE,
            'notes': 'First partial refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result1 = RefundService.refund_order(self.order.id, refund_data)
        self.assertTrue(result1.is_ok())
        
        # Verify order is partially refunded
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'partially_refunded')
        
        # Second partial refund (completing the refund)
        refund_data['amount_cents'] = 7900  # Remaining amount
        refund_data['notes'] = 'Second partial refund'
        
        result2 = RefundService.refund_order(self.order.id, refund_data)
        self.assertTrue(result2.is_ok())
        
        # Verify order is now fully refunded
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'refunded')

    def test_refund_eligibility_check(self):
        """Test refund eligibility checking without processing"""
        # Check full refund eligibility
        result = RefundService.get_refund_eligibility('order', self.order.id)
        
        self.assertTrue(result.is_ok())
        eligibility = result.unwrap()
        
        self.assertTrue(eligibility['is_eligible'])
        self.assertEqual(eligibility['max_refund_amount_cents'], 11900)
        self.assertEqual(eligibility['already_refunded_cents'], 0)
        
        # Check partial refund eligibility with amount
        result = RefundService.get_refund_eligibility('order', self.order.id, 5000)
        
        self.assertTrue(result.is_ok())
        eligibility = result.unwrap()
        self.assertTrue(eligibility['is_eligible'])

    def test_refund_eligibility_invalid_entity_type(self):
        """Test refund eligibility with invalid entity type"""
        result = RefundService.get_refund_eligibility('invalid', self.order.id)
        
        self.assertTrue(result.is_err())
        self.assertIn('Invalid entity_type', result.error)

    def test_atomic_transaction_rollback(self):
        """Test that failed refunds rollback completely"""
        # Create a scenario that should fail - partial refund with invalid amount
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 99999999,  # Way more than order total
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Should fail due to excessive amount',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        # Store original order status
        original_status = self.order.status
        
        result = RefundService.refund_order(self.order.id, refund_data)
        
        # Should fail due to excessive refund amount
        self.assertTrue(result.is_err())
        
        # Verify order status wasn't changed due to rollback
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, original_status)

    def test_refund_query_service(self):
        """Test RefundQueryService functionality"""
        # Process a refund first
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 5000,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        RefundService.refund_order(self.order.id, refund_data)
        
        # Query refund history
        result = RefundQueryService.get_entity_refunds('order', self.order.id)
        self.assertTrue(result.is_ok())
        
        refunds = result.unwrap()
        self.assertEqual(len(refunds), 1)
        self.assertEqual(refunds[0]['amount_cents'], 5000)
        self.assertEqual(refunds[0]['reason'], 'customer_request')

    def test_refund_statistics(self):
        """Test refund statistics generation"""
        result = RefundQueryService.get_refund_statistics(customer_id=self.customer.id)
        
        self.assertTrue(result.is_ok())
        stats = result.unwrap()
        
        # Verify stats structure
        self.assertIn('total_refunds', stats)
        self.assertIn('total_amount_refunded_cents', stats)
        self.assertIn('refunds_by_reason', stats)
        self.assertIn('refunds_by_type', stats)

class RefundEdgeCasesTestCase(TestCase):
    """Test edge cases and complex scenarios"""

    def setUp(self):
        """Set up complex test scenarios"""
        # Create test data similar to main test case
        self.user = User.objects.create_user(
            email='admin@example.com',
            password='admin123'
        )
        
        from apps.customers.models import Customer, CustomerTaxProfile
        self.customer = Customer.objects.create(
            name='Test Company',
            customer_type='company',
            company_name='Test Company',
            status='active'
        )
        
        # Create customer tax profile
        self.customer_tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='12345678',
            vat_number='RO12345678'
        )
        
        from apps.billing.models import Currency
        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'symbol': 'lei', 'decimals': 2}
        )

    def test_order_without_invoice_refund(self):
        """Test refunding order that has no associated invoice"""
        from apps.orders.models import Order
        
        order = Order.objects.create(
            order_number='ORD-2024-0003',
            customer=self.customer,
            currency=self.currency,
            total_cents=10000,
            status='completed',
            customer_email='test@company.com',
            customer_name=self.customer.company_name
        )
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Order without invoice',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_order(order.id, refund_data)
        
        # Should still succeed
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        
        self.assertEqual(refund_result['order_id'], order.id)
        self.assertIsNone(refund_result['invoice_id'])
        self.assertTrue(refund_result['order_status_updated'])
        self.assertFalse(refund_result['invoice_status_updated'])

    def test_invoice_without_order_refund(self):
        """Test refunding invoice that has no associated orders"""
        from apps.billing.models import Invoice
        
        invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-0003',
            status='paid',
            currency=self.currency,
            total_cents=10000
        )
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.DUPLICATE_PAYMENT,
            'notes': 'Invoice without order',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        result = RefundService.refund_invoice(invoice.id, refund_data)
        
        # Should still succeed
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        
        self.assertIsNone(refund_result['order_id'])
        self.assertEqual(refund_result['invoice_id'], invoice.id)
        self.assertFalse(refund_result['order_status_updated'])
        self.assertTrue(refund_result['invoice_status_updated'])

    def test_payment_refund_without_payments(self):
        """Test refund processing when no payments exist"""
        from apps.orders.models import Order
        from apps.billing.models import Invoice
        
        order = Order.objects.create(
            order_number='ORD-2024-0004',
            customer=self.customer,
            currency=self.currency,
            total_cents=10000,
            status='completed'
        )
        
        invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-2024-0004',
            status='issued',  # Not paid yet
            currency=self.currency,
            total_cents=10000
        )
        
        order.invoice = invoice
        order.save()
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'No payments to refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': True  # Request payment refund
        }
        
        result = RefundService.refund_order(order.id, refund_data)
        
        # Should succeed but payment refund should fail
        self.assertTrue(result.is_ok())
        refund_result = result.unwrap()
        self.assertFalse(refund_result['payment_refund_processed'])


@pytest.mark.django_db
class TestRefundServiceWithFixtures:
    """Pytest-style tests with fixtures for more complex scenarios"""
    
    @pytest.fixture
    def setup_refund_test_data(self):
        """Fixture to set up comprehensive test data"""
        user = User.objects.create_user(
            email='admin@example.com',
            password='admin123'
        )
        
        from apps.customers.models import Customer
        customer = Customer.objects.create(
            company_name='Test Company',
            email='test@company.com',
            fiscal_code='12345678',
            vat_number='RO12345678'
        )
        
        from apps.billing.models import Currency
        currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'symbol': 'lei', 'decimals': 2}
        )
        
        return {
            'user': user,
            'customer': customer,
            'currency': currency
        }
    
    def test_concurrent_refund_processing(self, setup_refund_test_data):
        """Test concurrent refund attempts are handled properly"""
        data = setup_refund_test_data
        
        from apps.orders.models import Order
        order = Order.objects.create(
            order_number='ORD-2024-0005',
            customer=data['customer'],
            currency=data['currency'],
            total_cents=10000,
            status='completed'
        )
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Concurrent test',
            'initiated_by': data['user'],
            'external_refund_id': None,
            'process_payment_refund': False
        }
        
        # This would test concurrent execution in a real scenario
        # For now, just verify the basic functionality works
        result = RefundService.refund_order(order.id, refund_data)
        assert result.is_ok()
        
        # Second attempt should fail
        result2 = RefundService.refund_order(order.id, refund_data)
        assert result2.is_err()
        assert 'already been fully refunded' in result2.error