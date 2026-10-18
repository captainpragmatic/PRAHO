"""
Comprehensive test coverage for business transaction audit services.
Tests the BillingAuditService and OrdersAuditService implementations.
"""

import uuid
from decimal import Decimal

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
        self.currency, _ = Currency.objects.get_or_create(code='RON', defaults={'symbol': 'RON', 'decimals': 2})

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
        currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        return currency

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
            is_active=True
        )

    @pytest.fixture
    def order_item(self, order, product):
        """Create test order item"""
        return OrderItem.objects.create(
            order=order,
            product=product,
            product_name='Shared Hosting Plan',
            product_type='hosting',
            quantity=1,
            unit_price_cents=4200,  # 42 EUR
            tax_rate=Decimal('0.19'),
            provisioning_status='pending'
        )

    def test_log_order_event_with_comprehensive_metadata(self, order):
        """Test order events capture comprehensive business context"""
        # Act
        audit_event = OrdersAuditService.log_order_event(
            BusinessEventData(
                event_type='order_created',
                business_object=order,
                context=AuditContext(
                    actor_type='user',
                    ip_address=order.source_ip
                ),
                description='Customer placed new order'
            )
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
            BusinessEventData(
                event_type='order_item_added',
                business_object=order_item,
                context=AuditContext(actor_type='system')
            )
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

    def test_log_provisioning_event_links_order_item_context(self, order_item):
        """Test provisioning events carry the order item's order and product context"""
        # Act
        audit_event = OrdersAuditService.log_provisioning_event(
            BusinessEventData(
                event_type='provisioning_completed',
                business_object=order_item,
                context=AuditContext(actor_type='system'),
                description='Service provisioned successfully'
            )
        )

        # Assert - an order item with no service yet is the audited object
        assert audit_event.action == 'provisioning_completed'
        assert audit_event.content_object == order_item
        metadata = audit_event.metadata
        assert metadata['order_number'] == order_item.order.order_number
        assert metadata['order_item_id'] == str(order_item.id)
        assert metadata['product_name'] == order_item.product_name
        assert metadata['service_id'] is None

    def test_order_status_change_tracking(self, order):
        """Test order status changes are properly tracked with old/new values"""
        # Setup
        old_values = {'status': 'draft', 'total_cents': 45000}
        new_values = {'status': 'pending', 'total_cents': 50000}

        # Act
        audit_event = OrdersAuditService.log_order_event(
            BusinessEventData(
                event_type='order_status_changed',
                business_object=order,
                old_values=old_values,
                new_values=new_values
            )
        )

        # Assert
        assert audit_event.old_values == old_values
        assert audit_event.new_values == new_values

    def test_order_event_includes_items_count(self, order, order_item):
        """Test order events include count of items for context"""
        # Act - order now has 1 item
        audit_event = OrdersAuditService.log_order_event(
            BusinessEventData(event_type='order_updated', business_object=order)
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
            BusinessEventData(
                event_type='order_quantity_changed',
                business_object=order_item,
                old_values=old_values,
                new_values=new_values
            )
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
        from apps.customers.models import Customer

        currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        customer = Customer.objects.create(company_name='Test Co', customer_type='business', status='active')
        invoice = Invoice.objects.create(
            customer=customer, currency=currency, number='CAT-001', status='draft',
            total_cents=10000, tax_cents=1900, subtotal_cents=8100, bill_to_name='Test Co',
        )
        payment = Payment.objects.create(
            customer=customer, invoice=invoice, currency=currency, amount_cents=10000,
            status='pending', payment_method='stripe', gateway_txn_id='txn_123',
        )
        invoice_events = ['invoice_created', 'invoice_paid', 'invoice_voided']
        payment_events = ['payment_succeeded', 'payment_failed', 'payment_refunded']

        for event_type in invoice_events:
            audit_event = BillingAuditService.log_invoice_event(
                BusinessEventData(event_type=event_type, business_object=invoice)
            )
            assert audit_event.category == 'business_operation', event_type
            assert audit_event.content_object == invoice, event_type

        for event_type in payment_events:
            audit_event = BillingAuditService.log_payment_event(
                BusinessEventData(event_type=event_type, business_object=payment)
            )
            assert audit_event.category == 'business_operation', event_type
            assert audit_event.is_sensitive is True, event_type  # payment_ prefix is sensitive

    def test_orders_events_categorization(self):
        """Test order events are properly categorized"""
        from apps.customers.models import Customer
        from apps.products.models import Product

        currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        customer = Customer.objects.create(company_name='Test Co', customer_type='business', status='active')
        order = Order.objects.create(
            customer=customer, order_number='ORD-CAT-001', currency=currency, status='draft',
            total_cents=10000, subtotal_cents=8403, tax_cents=1597,
            customer_email='test@test.com', customer_name='Test User', customer_company='Test Co',
        )
        product = Product.objects.create(name='Hosting', product_type='hosting', is_active=True)
        order_item = OrderItem.objects.create(
            order=order, product=product, product_name='Hosting', product_type='hosting',
            quantity=1, unit_price_cents=4200, tax_rate=Decimal('0.19'), provisioning_status='pending',
        )

        for event_type in ['order_created', 'order_status_changed', 'order_completed']:
            audit_event = OrdersAuditService.log_order_event(
                BusinessEventData(event_type=event_type, business_object=order)
            )
            assert audit_event.category == 'business_operation', event_type

        for event_type in ['provisioning_started', 'provisioning_completed', 'provisioning_failed']:
            audit_event = OrdersAuditService.log_provisioning_event(
                BusinessEventData(event_type=event_type, business_object=order_item)
            )
            assert audit_event.category == 'business_operation', event_type

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
        currency, _ = Currency.objects.get_or_create(code='USD', defaults={'symbol': '$', 'decimals': 2})
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
                BusinessEventData(
                    event_type='invoice_created',
                    business_object=invoice,
                    description='Performance test'
                )
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
