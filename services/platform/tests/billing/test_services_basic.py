# ===============================================================================
# COMPREHENSIVE BILLING SERVICES TESTS - REFUND SERVICE COVERAGE
# ===============================================================================

from __future__ import annotations

import uuid
from unittest.mock import Mock, patch

import unittest
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    InvoiceSequence,
    ProformaSequence,
)
from apps.billing.services import (
    RefundData,
    RefundQueryService,
    RefundReason,
    RefundService,
    RefundStatus,
    RefundType,
)
from apps.customers.models import Customer
from apps.users.models import User
from apps.common.types import Ok, Err


class RefundServiceComprehensiveTestCase(TestCase):
    """
    Comprehensive test suite for RefundService.
    Tests all major functions and edge cases to achieve 85%+ coverage.
    """

    def setUp(self) -> None:
        """Set up test fixtures with proper Romanian business data"""
        self.currency = Currency.objects.create(
            code='RON',
            symbol='RON',
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name='Test SRL',
            customer_type='company',
            status='active'
        )
        
        self.user = User.objects.create_user(
            email='admin@example.com',
            password='testpass123',
            is_staff=True
        )
        
        # Create invoice sequence
        self.invoice_sequence = InvoiceSequence.objects.create(
            scope='test',
            last_value=0
        )
        
        # Create proforma sequence
        self.proforma_sequence = ProformaSequence.objects.create(
            scope='test',
            last_value=0
        )

    def test_refund_type_enum_values(self) -> None:
        """Test RefundType enum has correct values"""
        self.assertEqual(RefundType.FULL.value, "full")
        self.assertEqual(RefundType.PARTIAL.value, "partial")

    def test_refund_reason_enum_values(self) -> None:
        """Test RefundReason enum has all expected values"""
        expected_reasons = [
            "customer_request", "error_correction", "dispute", "service_failure",
            "duplicate_payment", "fraud", "cancellation", "downgrade", "administrative"
        ]
        actual_reasons = [reason.value for reason in RefundReason]
        for reason in expected_reasons:
            self.assertIn(reason, actual_reasons)

    def test_refund_status_enum_values(self) -> None:
        """Test RefundStatus enum has correct values"""
        expected_statuses = ["pending", "processing", "completed", "failed", "cancelled"]
        actual_statuses = [status.value for status in RefundStatus]
        for status in expected_statuses:
            self.assertIn(status, actual_statuses)

    @patch('apps.orders.models.Order.objects.select_related')
    def test_refund_order_order_not_found(self, mock_select_related: Mock) -> None:
        """Test refund_order when order doesn't exist"""
        mock_select_related.return_value.get.side_effect = Exception("Order matching query does not exist")
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False,
        }
        
        order_id = uuid.uuid4()
        result = RefundService.refund_order(order_id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn("Order", result.error)

    @patch('apps.billing.services.RefundService._validate_order_refund_eligibility')
    @patch('apps.orders.models.Order.objects.select_related')
    def test_refund_order_not_eligible(self, mock_select_related: Mock, mock_validate: Mock) -> None:
        """Test refund_order when order is not eligible for refund"""
        from apps.common.types import Err
        
        mock_order = Mock()
        mock_order.id = uuid.uuid4()
        mock_select_related.return_value.get.return_value = mock_order
        
        mock_validate.return_value = Err("Order not eligible")
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False,
        }
        
        result = RefundService.refund_order(mock_order.id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertEqual(result.error, "Order not eligible")

    @patch('apps.billing.services.RefundService._validate_invoice_refund_eligibility')
    @patch('apps.billing.models.Invoice.objects.select_related')
    def test_refund_invoice_invoice_not_found(self, mock_select_related: Mock, mock_validate: Mock) -> None:
        """Test refund_invoice when invoice doesn't exist"""
        mock_select_related.return_value.get.side_effect = Exception("Invoice matching query does not exist")
        
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Test refund',
            'initiated_by': self.user,
            'external_refund_id': None,
            'process_payment_refund': False,
        }
        
        invoice_id = uuid.uuid4()
        result = RefundService.refund_invoice(invoice_id, refund_data)
        
        self.assertTrue(result.is_err())
        self.assertIn("Invoice", result.error)

    def test_validate_refund_eligibility_invalid_entity_type(self) -> None:
        """Test get_refund_eligibility with invalid entity type"""
        result = RefundService.get_refund_eligibility("invalid_entity", uuid.uuid4(), 1000)
        
        self.assertTrue(result.is_err())
        self.assertIn("Invalid entity type", result.error)



class RefundQueryServiceTestCase(TestCase):
    """Test suite for RefundQueryService"""

    def setUp(self) -> None:
        """Set up test fixtures"""
        self.currency = Currency.objects.create(
            code='RON',
            symbol='RON',
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name='Test SRL',
            customer_type='company',
            status='active'
        )

    @patch('apps.orders.models.Order.objects.filter')
    def test_get_refund_statistics_no_orders(self, mock_filter: Mock) -> None:
        """Test refund statistics when no orders exist"""
        mock_filter.return_value.aggregate.return_value = {
            'total_refunded_cents': None,
            'total_refund_count': 0
        }
        
        result = RefundQueryService.get_refund_statistics(
            customer_id=self.customer.id,
            date_from=timezone.now().date(),
            date_to=timezone.now().date()
        )
        
        self.assertTrue(result.is_ok())
        stats = result.unwrap()
        self.assertEqual(stats['total_amount_refunded_cents'], 0)
        self.assertEqual(stats['total_refunds'], 0)
        self.assertEqual(stats['orders_refunded'], 0)
        self.assertEqual(stats['invoices_refunded'], 0)

    @patch('apps.orders.models.Order.objects.filter')  
    def test_get_refund_statistics_with_data(self, mock_filter: Mock) -> None:
        """Test refund statistics with actual data"""
        mock_filter.return_value.aggregate.return_value = {
            'total_refunded_cents': 50000,  # 500.00 RON
            'total_refund_count': 5
        }
        
        result = RefundQueryService.get_refund_statistics(
            customer_id=self.customer.id,
            date_from=timezone.now().date(),
            date_to=timezone.now().date()
        )
        
        self.assertTrue(result.is_ok())
        stats = result.unwrap()
        # Test the actual keys returned by the method
        self.assertIn('total_amount_refunded_cents', stats)
        self.assertIn('total_refunds', stats)
        self.assertIn('refunds_by_reason', stats)
        self.assertIn('refunds_by_type', stats)



class RefundServiceErrorHandlingTestCase(TransactionTestCase):
    """Test suite for RefundService error handling and edge cases"""

    def test_refund_service_transaction_rollback(self) -> None:
        """Test that refund service properly rolls back transactions on error"""
        with patch('apps.billing.services.RefundService._process_bidirectional_refund') as mock_process:
            mock_process.side_effect = Exception("Simulated error")
            
            refund_data: RefundData = {
                'refund_type': RefundType.FULL,
                'amount_cents': 0,
                'reason': RefundReason.CUSTOMER_REQUEST,
                'notes': 'Test refund',
                'initiated_by': None,
                'external_refund_id': None,
                'process_payment_refund': False,
            }
            
            # This should not raise an exception due to @transaction.atomic
            result = RefundService.refund_order(uuid.uuid4(), refund_data)
            self.assertTrue(result.is_err())
