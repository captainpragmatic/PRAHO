"""
Comprehensive test coverage for business transaction audit services.
Tests the BillingAuditService and OrdersAuditService implementations.
"""

import uuid
from decimal import Decimal
from unittest.mock import Mock, patch

import pytest
import unittest
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
# Conditional imports - some services may not exist yet
try:
    from apps.audit.services import AuditContext, BillingAuditService, OrdersAuditService, BusinessEventData
except ImportError:
    AuditContext = BillingAuditService = OrdersAuditService = BusinessEventData = None

from apps.billing.models import Currency, Invoice, Payment, ProformaInvoice
# Handle missing orders app
try:
    from apps.orders.models import Order, OrderItem
except ImportError:
    Order = OrderItem = None


class TestBillingAuditService(TestCase):
    """Test suite for BillingAuditService"""

    def setUp(self):
        """Set up test fixtures"""
        # Create test currency
        self.currency = Currency.objects.create(code='RON', symbol='RON', decimals=2)
        
        # Create test customer
        from apps.customers.models import Customer, CustomerTaxProfile
        self.customer = Customer.objects.create(
            company_name='Test Company SRL',
            customer_type='business',
            status='active'
        )
        
        # Create tax profile with Romanian business details
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True
        )
        
        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.currency,
            status='draft',
            total_cents=100000,  # 1000 RON
            tax_cents=19000,     # 190 RON VAT
            subtotal_cents=81000,
            bill_to_name='Test Company SRL',
            bill_to_tax_id='RO12345678',
            bill_to_country='RO'
        )
        
        # Create test payment
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=100000,
            status='pending',
            payment_method='stripe',
            gateway_txn_id='txn_123456789'
        )
        
        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-000001',
            currency=self.currency,
            total_cents=100000,
            tax_cents=19000,
            subtotal_cents=81000,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Test Company SRL'
        )

    def test_log_invoice_event_creates_audit_entry(self):
        """Test that invoice events create proper audit entries with rich metadata"""
        # Act
        audit_event = BillingAuditService.log_invoice_event(
            BusinessEventData(
                event_type='invoice_created',
                business_object=self.invoice,
                user=None,
                context=AuditContext(
                    actor_type='system',
                    ip_address='127.0.0.1',
                    metadata={'source': 'test'}
                ),
                description='Test invoice creation'
            )
        )

        # Assert
        self.assertIsNotNone(audit_event)
        self.assertEqual(audit_event.action, 'invoice_created')
        self.assertEqual(audit_event.content_object, self.invoice)
        self.assertEqual(audit_event.category, 'business_operation')
        self.assertEqual(audit_event.severity, 'low')
        self.assertFalse(audit_event.is_sensitive)
        
        # Check rich metadata
        metadata = audit_event.metadata
        self.assertEqual(metadata['invoice_number'], self.invoice.number)
        self.assertEqual(metadata['invoice_status'], self.invoice.status)
        self.assertEqual(metadata['customer_id'], str(self.invoice.customer.id))
        self.assertEqual(metadata['currency'], self.invoice.currency.code)
        self.assertEqual(metadata['total_amount'], str(self.invoice.total))
        self.assertEqual(metadata['vat_amount'], str(self.invoice.tax_amount))
        self.assertIn('romanian_compliance', metadata)
        self.assertEqual(metadata['source'], 'test')

    def test_log_payment_event_with_transaction_context(self):
        """Test payment events capture transaction-specific metadata"""
        # Act
        audit_event = BillingAuditService.log_payment_event(
            BusinessEventData(
                event_type='payment_succeeded',
                business_object=self.payment,
                context=AuditContext(
                    actor_type='system',
                    metadata={'gateway_response_code': '200'}
                ),
                description='Payment successfully processed'
            )
        )

        # Assert
        assert audit_event.action == 'payment_succeeded'
        assert audit_event.severity == 'medium'
        
        metadata = audit_event.metadata
        assert metadata['payment_method'] == self.payment.payment_method
        assert metadata['amount'] == str(self.payment.amount)
        assert metadata['currency'] == self.payment.currency.code
        assert metadata['gateway_txn_id'] == self.payment.gateway_txn_id
        assert metadata['financial_impact'] is True
        assert metadata['gateway_response_code'] == '200'

    def test_log_proforma_event_captures_validity_info(self):
        """Test proforma events include expiration and validity metadata"""
        # Act
        audit_event = BillingAuditService.log_proforma_event(
            BusinessEventData(
                event_type='proforma_created',
                business_object=self.proforma,
                context=AuditContext(actor_type='user'),
                description='Proforma created for customer'
            )
        )

        # Assert
        assert audit_event.action == 'proforma_created'
        metadata = audit_event.metadata
        assert metadata['proforma_number'] == self.proforma.number
        assert metadata['valid_until'] == self.proforma.valid_until.isoformat()
        assert metadata['is_expired'] == self.proforma.is_expired
        assert metadata['total_amount'] == str(self.proforma.total)

    def test_invoice_event_with_status_changes(self):
        """Test invoice events properly track status changes"""
        # Setup
        old_values = {'status': 'draft', 'total_cents': 90000}
        new_values = {'status': 'issued', 'total_cents': 100000}

        # Act
        from apps.audit.services import BusinessEventData
        event_data = BusinessEventData(
            event_type='invoice_status_changed',
            business_object=self.invoice,
            old_values=old_values,
            new_values=new_values
        )
        audit_event = BillingAuditService.log_invoice_event(event_data)

        # Assert
        assert audit_event.old_values == old_values
        assert audit_event.new_values == new_values
        assert audit_event.action == 'invoice_status_changed'

    def test_payment_event_categorization(self):
        """Test payment events are properly categorized and marked sensitive"""
        # Act
        audit_event = BillingAuditService.log_payment_event(
            BusinessEventData(
                event_type='payment_failed',
                business_object=self.payment
            )
        )

        # Assert
        assert audit_event.category == 'business_operation'
        assert audit_event.severity == 'high'  # payment_failed explicitly listed in high_actions
        assert audit_event.is_sensitive is True  # payment_ prefix is sensitive
        assert audit_event.requires_review is False  # payment_failed not in review list


@pytest.mark.django_db 
class TestOrdersAuditService:
    """Test suite for OrdersAuditService"""

    @pytest.fixture
    def currency(self):
        """Create test currency"""
        return Currency.objects.create(code='EUR', symbol='€', decimals=2)

    @pytest.fixture
    def customer(self):
        """Create test customer"""
        from apps.customers.models import Customer
        return Customer.objects.create(
            company_name='Test Customer Ltd',
            customer_type='business',
            status='active'
        )

    @pytest.fixture
    def order(self, customer, currency):
        """Create test order"""
        return Order.objects.create(
            customer=customer,
            order_number='ORD-20241201-000001',
            currency=currency,
            status='draft',
            total_cents=50000,  # 500 EUR
            subtotal_cents=42017,  # 420.17 EUR
            tax_cents=7983,     # 79.83 EUR VAT
            customer_email='customer@test.com',
            customer_name='John Doe',
            customer_company='Test Customer Ltd',
            source_ip='192.168.1.100',
            utm_source='google',
            utm_medium='organic'
        )

    @pytest.fixture
    def product(self):
        """Create test product"""
        from apps.products.models import Product
        return Product.objects.create(
            name='Shared Hosting Plan',
            product_type='hosting',
            status='active'
        )

    @pytest.fixture
    def order_item(self, order, product):
        """Create test order item"""
        return OrderItem.objects.create(
            order=order,
            product=product,
            product_name='Shared Hosting Plan',
            product_type='hosting',
            billing_period='monthly',
            quantity=1,
            unit_price_cents=4200,  # 42 EUR
            tax_rate=Decimal('0.19'),
            provisioning_status='pending'
        )

    def test_log_order_event_with_comprehensive_metadata(self, order):
        """Test order events capture comprehensive business context"""
        # Act
        audit_event = OrdersAuditService.log_order_event(
            event_type='order_created',
            order=order,
            context=AuditContext(
                actor_type='user',
                ip_address=order.source_ip
            ),
            description='Customer placed new order'
        )

        # Assert
        assert audit_event.action == 'order_created'
        assert audit_event.category == 'business_operation'
        assert audit_event.severity == 'medium'
        
        metadata = audit_event.metadata
        assert metadata['order_number'] == order.order_number
        assert metadata['order_status'] == order.status
        assert metadata['customer_email'] == order.customer_email
        assert metadata['customer_company'] == order.customer_company
        assert metadata['total_amount'] == str(order.total)
        assert metadata['currency'] == order.currency.code
        assert metadata['is_draft'] == order.is_draft
        assert metadata['is_paid'] == order.is_paid
        
        # Source tracking metadata
        source_tracking = metadata['source_tracking']
        assert source_tracking['source_ip'] == order.source_ip
        assert source_tracking['utm_source'] == order.utm_source
        assert source_tracking['utm_medium'] == order.utm_medium

    def test_log_order_item_event_with_product_context(self, order_item):
        """Test order item events include product and pricing details"""
        # Act
        audit_event = OrdersAuditService.log_order_item_event(
            event_type='order_item_added',
            order_item=order_item,
            context=AuditContext(actor_type='system')
        )

        # Assert
        assert audit_event.action == 'order_item_added'
        metadata = audit_event.metadata
        assert metadata['order_number'] == order_item.order.order_number
        assert metadata['product_name'] == order_item.product_name
        assert metadata['product_type'] == order_item.product_type
        assert metadata['quantity'] == order_item.quantity
        assert metadata['unit_price'] == str(order_item.unit_price)
        assert metadata['tax_rate'] == str(order_item.tax_rate)
        assert metadata['provisioning_status'] == order_item.provisioning_status

    def test_log_provisioning_event_with_service_context(self, order_item):
        """Test provisioning events link order items with services"""
        # Setup - create a mock service
        mock_service = Mock()
        mock_service.id = uuid.uuid4()
        mock_service.service_type = 'hosting'

        # Act
        audit_event = OrdersAuditService.log_provisioning_event(
            event_type='provisioning_completed',
            order_item=order_item,
            service=mock_service,
            context=AuditContext(actor_type='system'),
            description='Service provisioned successfully'
        )

        # Assert
        assert audit_event.action == 'provisioning_completed'
        assert audit_event.content_object == mock_service
        metadata = audit_event.metadata
        assert metadata['order_number'] == order_item.order.order_number
        assert metadata['product_name'] == order_item.product_name
        assert metadata['service_id'] == str(mock_service.id)
        assert metadata['service_type'] == mock_service.service_type

    def test_order_status_change_tracking(self, order):
        """Test order status changes are properly tracked with old/new values"""
        # Setup
        old_values = {'status': 'draft', 'total_cents': 45000}
        new_values = {'status': 'pending', 'total_cents': 50000}

        # Act
        audit_event = OrdersAuditService.log_order_event(
            event_type='order_status_changed',
            order=order,
            old_values=old_values,
            new_values=new_values
        )

        # Assert
        assert audit_event.old_values == old_values
        assert audit_event.new_values == new_values

    def test_order_event_includes_items_count(self, order, order_item):
        """Test order events include count of items for context"""
        # Act - order now has 1 item
        audit_event = OrdersAuditService.log_order_event(
            event_type='order_updated',
            order=order
        )

        # Assert
        metadata = audit_event.metadata
        assert metadata['items_count'] == 1

    def test_order_item_quantity_change_tracking(self, order_item):
        """Test order item quantity changes are tracked"""
        # Setup
        old_values = {'quantity': 1, 'unit_price_cents': 4200}
        new_values = {'quantity': 2, 'unit_price_cents': 4200}

        # Act
        audit_event = OrdersAuditService.log_order_item_event(
            event_type='order_quantity_changed',
            order_item=order_item,
            old_values=old_values,
            new_values=new_values
        )

        # Assert
        assert audit_event.action == 'order_quantity_changed'
        assert audit_event.old_values == old_values
        assert audit_event.new_values == new_values


@pytest.mark.django_db
class TestAuditEventCategorization:
    """Test audit event categorization and severity assignment"""

    def test_billing_events_categorization(self):
        """Test billing events are properly categorized"""
        # Test various billing event types
        billing_events = [
            'invoice_created', 'invoice_paid', 'invoice_voided',
            'payment_succeeded', 'payment_failed', 'payment_refunded',
            'proforma_created', 'proforma_converted',
            'credit_added', 'credit_used'
        ]

        for event_type in billing_events:
            # Create mock objects for testing
            mock_invoice = Mock()
            mock_invoice.number = 'TEST-001'
            mock_invoice.status = 'draft'
            mock_invoice.customer = Mock()
            mock_invoice.customer.id = 1
            mock_invoice.customer.company_name = 'Test Co'
            mock_invoice.currency = Mock()
            mock_invoice.currency.code = 'EUR'
            mock_invoice.total = Decimal('100.00')
            mock_invoice.tax_amount = Decimal('19.00')
            mock_invoice.total_cents = 10000
            mock_invoice.tax_cents = 1900
            mock_invoice.due_at = None
            mock_invoice.issued_at = None
            mock_invoice.is_overdue = Mock(return_value=False)
            mock_invoice.efactura_id = ''
            mock_invoice.efactura_sent = False
            mock_invoice.efactura_sent_date = None
            mock_invoice.bill_to_name = 'Test Co'

            if event_type.startswith('invoice_'):
                audit_event = BillingAuditService.log_invoice_event(
                    event_type=event_type,
                    invoice=mock_invoice
                )
            elif event_type.startswith('payment_'):
                mock_payment = Mock()
                mock_payment.id = 1
                mock_payment.customer = mock_invoice.customer
                mock_payment.currency = mock_invoice.currency
                mock_payment.amount = Decimal('100.00')
                mock_payment.amount_cents = 10000
                mock_payment.status = 'succeeded'
                mock_payment.payment_method = 'stripe'
                mock_payment.gateway_txn_id = 'txn_123'
                mock_payment.reference_number = 'ref_123'
                mock_payment.received_at = timezone.now()
                mock_payment.invoice = mock_invoice
                
                audit_event = BillingAuditService.log_payment_event(
                    event_type=event_type,
                    payment=mock_payment
                )
            else:
                continue

            assert audit_event.category == 'business_operation'
            assert audit_event.is_sensitive is True

    def test_orders_events_categorization(self):
        """Test order events are properly categorized"""
        order_events = [
            'order_created', 'order_status_changed', 'order_completed',
            'provisioning_started', 'provisioning_completed', 'provisioning_failed'
        ]

        for event_type in order_events:
            # Create mock objects
            mock_order = Mock()
            mock_order.order_number = 'ORD-001'
            mock_order.status = 'draft'
            mock_order.customer = Mock()
            mock_order.customer.id = 1
            mock_order.customer_email = 'test@test.com'
            mock_order.customer_name = 'Test User'
            mock_order.customer_company = 'Test Co'
            mock_order.customer_vat_id = ''
            mock_order.currency = Mock()
            mock_order.currency.code = 'EUR'
            mock_order.total = Decimal('100.00')
            mock_order.total_cents = 10000
            mock_order.subtotal_cents = 8403
            mock_order.tax_cents = 1597
            mock_order.discount_cents = 0
            mock_order.payment_method = 'card'
            mock_order.transaction_id = ''
            mock_order.is_draft = True
            mock_order.is_paid = False
            mock_order.can_be_cancelled = True
            mock_order.created_at = timezone.now()
            mock_order.completed_at = None
            mock_order.expires_at = None
            mock_order.invoice = None
            mock_order.source_ip = '127.0.0.1'
            mock_order.user_agent = 'Test Agent'
            mock_order.referrer = ''
            mock_order.utm_source = ''
            mock_order.utm_medium = ''
            mock_order.utm_campaign = ''
            mock_order.items = Mock()
            mock_order.items.count = Mock(return_value=1)

            if event_type.startswith('order_'):
                audit_event = OrdersAuditService.log_order_event(
                    event_type=event_type,
                    order=mock_order
                )
            elif event_type.startswith('provisioning_'):
                mock_item = Mock()
                mock_item.order = mock_order
                mock_item.id = uuid.uuid4()
                mock_item.product_name = 'Test Product'
                mock_item.product_type = 'hosting'
                mock_item.domain_name = ''
                mock_item.provisioning_status = 'pending'
                mock_item.provisioning_notes = ''
                mock_item.config = {}
                
                audit_event = OrdersAuditService.log_provisioning_event(
                    event_type=event_type,
                    order_item=mock_item
                )
            else:
                continue

            assert audit_event.category == 'business_operation'

    def test_high_severity_events(self):
        """Test events that should be marked as high severity"""
        high_severity_events = [
            'payment_fraud_detected', 'payment_chargeback_received',
            'invoice_voided', 'provisioning_failed'
        ]

        # Note: This is a conceptual test - in practice we'd need proper mock setup
        # for each event type. The key assertion is that severity is properly assigned.
        for event_type in high_severity_events:
            # Test that the severity determination function works
            from apps.audit.services import AuditService
            severity = AuditService._get_action_severity(event_type)
            assert severity == 'high'


@pytest.mark.django_db
class TestAuditEventPerformance:
    """Test audit logging performance and efficiency"""

    def test_audit_logging_minimal_queries(self, django_assert_max_num_queries):
        """Test that audit logging uses minimal database queries"""
        from apps.customers.models import Customer
        from apps.billing.models import Currency, Invoice

        # Setup
        currency = Currency.objects.create(code='USD', symbol='$', decimals=2)
        customer = Customer.objects.create(
            company_name='Performance Test Co',
            customer_type='business',
            status='active'
        )
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number='PERF-001',
            status='draft',
            total_cents=10000
        )

        # Test - should use minimal queries for audit logging
        with django_assert_max_num_queries(5):  # ContentType lookup, User lookup, AuditEvent create
            BillingAuditService.log_invoice_event(
                event_type='invoice_created',
                invoice=invoice,
                description='Performance test'
            )

    def test_metadata_serialization_performance(self):
        """Test that metadata serialization handles complex objects efficiently"""
        from apps.audit.services import serialize_metadata
        
        # Setup complex metadata with various object types
        complex_metadata = {
            'uuid_field': uuid.uuid4(),
            'datetime_field': timezone.now(),
            'decimal_field': Decimal('123.456'),
            'string_field': 'test',
            'nested_dict': {
                'inner_uuid': uuid.uuid4(),
                'inner_datetime': timezone.now()
            },
            'list_field': [1, 2, 3, 'test'],
            'boolean_field': True,
            'none_field': None
        }

        # Act
        serialized = serialize_metadata(complex_metadata)

        # Assert - all values should be JSON-serializable
        assert isinstance(serialized, dict)
        assert isinstance(serialized['uuid_field'], str)
        assert isinstance(serialized['datetime_field'], str)
        assert isinstance(serialized['decimal_field'], str)
        assert serialized['string_field'] == 'test'
        assert isinstance(serialized['nested_dict']['inner_uuid'], str)
        assert serialized['boolean_field'] is True
        assert serialized['none_field'] is None



if __name__ == '__main__':
    pytest.main([__file__])