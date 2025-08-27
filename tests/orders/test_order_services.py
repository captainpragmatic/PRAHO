"""
Test suite for order services in PRAHO Platform
Tests business logic, Romanian VAT compliance, and service layer functionality.
"""

import uuid
from decimal import Decimal

from django.test import TestCase
from django.contrib.auth import get_user_model

from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.orders.services import (
    OrderCreateData,
    OrderService,
    OrderCalculationService,
    OrderNumberingService,
    OrderQueryService,
    StatusChangeData,
)

User = get_user_model()


class OrderCalculationServiceTestCase(TestCase):
    """Test cases for order calculation services"""

    def test_romanian_vat_calculation(self):
        """Test 19% Romanian VAT calculation"""
        # Test various amounts
        test_cases = [
            (10000, 1900),    # 100.00 RON → 19.00 RON VAT
            (50000, 9500),    # 500.00 RON → 95.00 RON VAT
            (100000, 19000),  # 1000.00 RON → 190.00 RON VAT
            (1, 0),           # 0.01 RON → 0.00 RON VAT (rounded down)
        ]
        
        for amount_cents, expected_vat_cents in test_cases:
            with self.subTest(amount=amount_cents):
                vat_cents = OrderCalculationService.calculate_vat(amount_cents)
                self.assertEqual(vat_cents, expected_vat_cents)

    def test_order_totals_calculation(self):
        """Test complete order totals calculation"""
        items = [
            {
                'quantity': 2,
                'unit_price_cents': 5000,  # 50.00 RON each
            },
            {
                'quantity': 1,
                'unit_price_cents': 10000,  # 100.00 RON
            }
        ]
        
        totals = OrderCalculationService.calculate_order_totals(items)
        
        expected_subtotal = 20000  # 200.00 RON
        expected_vat = 3800        # 38.00 RON (19% VAT)
        expected_total = 23800     # 238.00 RON
        
        self.assertEqual(totals['subtotal_cents'], expected_subtotal)
        self.assertEqual(totals['tax_cents'], expected_vat)
        self.assertEqual(totals['total_cents'], expected_total)

    def test_zero_amount_calculation(self):
        """Test calculation with zero amounts"""
        totals = OrderCalculationService.calculate_order_totals([])
        
        self.assertEqual(totals['subtotal_cents'], 0)
        self.assertEqual(totals['tax_cents'], 0)
        self.assertEqual(totals['total_cents'], 0)


class OrderNumberingServiceTestCase(TestCase):
    """Test cases for order numbering service"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )

    def test_first_order_number_generation(self):
        """Test generation of first order number for customer"""
        order_number = OrderNumberingService.generate_order_number(self.customer)
        
        # Should follow format: ORD-YYYY-CUSTOMER_ID_PREFIX-XXXX
        self.assertTrue(order_number.startswith("ORD-2024-"))
        self.assertTrue(order_number.endswith("-0001"))
        self.assertIn(str(self.customer.pk).replace('-', '')[:8].upper(), order_number)

    def test_sequential_order_numbers(self):
        """Test sequential order number generation"""
        # Create first order
        order1 = Order.objects.create(
            customer=self.customer,
            order_number=OrderNumberingService.generate_order_number(self.customer),
            currency="RON"
        )
        
        # Generate second order number
        order_number2 = OrderNumberingService.generate_order_number(self.customer)
        
        # Should be sequential
        prefix = order1.order_number[:-4]  # Remove -XXXX part
        expected_number2 = f"{prefix}-0002"
        self.assertEqual(order_number2, expected_number2)

    def test_order_number_uniqueness_per_customer(self):
        """Test that order numbers are unique per customer"""
        customer2 = Customer.objects.create(
            company_name="Another Company SRL",
            email="another@company.ro",
            phone="+40987654321",
            is_active=True
        )
        
        number1 = OrderNumberingService.generate_order_number(self.customer)
        number2 = OrderNumberingService.generate_order_number(customer2)
        
        # Numbers should be different due to different customer prefixes
        self.assertNotEqual(number1, number2)
        self.assertTrue(number1.endswith("-0001"))
        self.assertTrue(number2.endswith("-0001"))


class OrderServiceTestCase(TestCase):
    """Test cases for main order service"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="admin@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )

    def test_successful_order_creation(self):
        """Test successful order creation with all components"""
        billing_address = {
            'company_name': "Test Company SRL",
            'contact_name': "Ion Popescu",
            'email': "ion@company.ro",
            'phone': "+40123456789",
            'address_line1': "Str. Aviatorilor nr. 1",
            'address_line2': "",
            'city': "Bucuresti",
            'county': "Bucuresti",
            'postal_code': "010563",
            'country': "Romania",
            'fiscal_code': "RO12345678",
            'registration_number': "J40/1234/2024",
            'vat_number': "RO12345678"
        }
        
        items = [
            {
                'product_id': None,
                'service_id': None,
                'quantity': 1,
                'unit_price_cents': 10000,  # 100.00 RON
                'description': "Web Hosting Plan",
                'meta': {'plan': 'standard'}
            }
        ]
        
        order_data = OrderCreateData(
            customer=self.customer,
            items=items,
            billing_address=billing_address,
            currency="RON",
            notes="Test order creation"
        )
        
        result = OrderService.create_order(order_data, self.user)
        
        # Verify success
        self.assertTrue(result.is_ok())
        order = result.unwrap()
        
        # Verify order details
        self.assertEqual(order.customer, self.customer)
        self.assertEqual(order.currency, "RON")
        self.assertEqual(order.subtotal_cents, 10000)
        self.assertEqual(order.tax_cents, 1900)  # 19% VAT
        self.assertEqual(order.total_cents, 11900)
        
        # Verify billing address
        self.assertEqual(order.billing_company_name, "Test Company SRL")
        self.assertEqual(order.billing_fiscal_code, "RO12345678")
        
        # Verify order items created
        self.assertEqual(order.items.count(), 1)
        item = order.items.first()
        self.assertEqual(item.quantity, 1)
        self.assertEqual(item.unit_price_cents, 10000)
        self.assertEqual(item.description, "Web Hosting Plan")
        
        # Verify status history created
        self.assertEqual(order.status_history.count(), 1)
        history = order.status_history.first()
        self.assertIsNone(history.old_status)
        self.assertEqual(history.new_status, "draft")
        self.assertEqual(history.changed_by, self.user)

    def test_order_status_update_success(self):
        """Test successful order status update"""
        # Create order
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-TEST-0001",
            currency="RON",
            status="draft"
        )
        
        # Update status
        status_data = StatusChangeData(
            new_status="pending",
            notes="Order submitted for processing",
            changed_by=self.user
        )
        
        result = OrderService.update_order_status(order, status_data)
        
        # Verify success
        self.assertTrue(result.is_ok())
        updated_order = result.unwrap()
        self.assertEqual(updated_order.status, "pending")
        
        # Verify status history
        self.assertEqual(order.status_history.count(), 1)
        history = order.status_history.first()
        self.assertEqual(history.old_status, "draft")
        self.assertEqual(history.new_status, "pending")
        self.assertEqual(history.notes, "Order submitted for processing")
        self.assertEqual(history.changed_by, self.user)

    def test_invalid_status_transition(self):
        """Test invalid status transition rejection"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-INVALID-0001",
            currency="RON",
            status="completed"  # Terminal status
        )
        
        status_data = StatusChangeData(
            new_status="draft",  # Invalid transition from completed
            notes="Trying invalid transition",
            changed_by=self.user
        )
        
        result = OrderService.update_order_status(order, status_data)
        
        # Verify failure
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()
        self.assertIn("Invalid status transition", error_message)
        
        # Verify order status unchanged
        order.refresh_from_db()
        self.assertEqual(order.status, "completed")

    def test_valid_status_transitions(self):
        """Test all valid status transitions"""
        valid_transitions = [
            ("draft", "pending"),
            ("draft", "cancelled"),
            ("pending", "confirmed"),
            ("pending", "cancelled"),
            ("pending", "failed"),
            ("confirmed", "processing"),
            ("confirmed", "cancelled"),
            ("processing", "completed"),
            ("processing", "failed"),
            ("processing", "cancelled"),
            ("failed", "pending"),
            ("failed", "cancelled"),
        ]
        
        for old_status, new_status in valid_transitions:
            with self.subTest(transition=f"{old_status} → {new_status}"):
                order = Order.objects.create(
                    customer=self.customer,
                    order_number=f"ORD-2024-{old_status.upper()}-{new_status.upper()}",
                    currency="RON",
                    status=old_status
                )
                
                status_data = StatusChangeData(
                    new_status=new_status,
                    notes=f"Transition from {old_status} to {new_status}",
                    changed_by=self.user
                )
                
                result = OrderService.update_order_status(order, status_data)
                self.assertTrue(result.is_ok(), f"Failed transition {old_status} → {new_status}")


class OrderQueryServiceTestCase(TestCase):
    """Test cases for order query service"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        # Create test orders
        self.order1 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-QUERY-0001",
            currency="RON",
            status="draft",
            billing_company_name="Test Company SRL"
        )
        
        self.order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-QUERY-0002",
            currency="RON",
            status="completed",
            billing_company_name="Test Company SRL"
        )

    def test_get_orders_for_customer(self):
        """Test retrieving orders for specific customer"""
        result = OrderQueryService.get_orders_for_customer(self.customer)
        
        self.assertTrue(result.is_ok())
        orders = result.unwrap()
        self.assertEqual(len(orders), 2)
        
        # Verify order is newest first
        self.assertEqual(orders[0], self.order2)
        self.assertEqual(orders[1], self.order1)

    def test_get_orders_with_status_filter(self):
        """Test retrieving orders with status filtering"""
        filters = {'status': 'completed'}
        result = OrderQueryService.get_orders_for_customer(self.customer, filters)
        
        self.assertTrue(result.is_ok())
        orders = result.unwrap()
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].status, "completed")

    def test_get_orders_with_search_filter(self):
        """Test retrieving orders with search filtering"""
        filters = {'search': 'QUERY-0001'}
        result = OrderQueryService.get_orders_for_customer(self.customer, filters)
        
        self.assertTrue(result.is_ok())
        orders = result.unwrap()
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].order_number, "ORD-2024-QUERY-0001")

    def test_get_order_with_items(self):
        """Test retrieving order with related items"""
        # Add item to order
        OrderItem.objects.create(
            order=self.order1,
            quantity=1,
            unit_price_cents=5000,
            line_total_cents=5000,
            description="Test Item"
        )
        
        result = OrderQueryService.get_order_with_items(self.order1.id, self.customer)
        
        self.assertTrue(result.is_ok())
        order = result.unwrap()
        self.assertEqual(order.id, self.order1.id)
        
        # Verify prefetched items
        items = list(order.items.all())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].description, "Test Item")

    def test_get_nonexistent_order(self):
        """Test retrieving non-existent order"""
        fake_uuid = uuid.uuid4()
        result = OrderQueryService.get_order_with_items(fake_uuid, self.customer)
        
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()
        self.assertEqual(error_message, "Order not found")

    def test_get_order_wrong_customer(self):
        """Test retrieving order with wrong customer"""
        other_customer = Customer.objects.create(
            company_name="Other Company SRL",
            email="other@company.ro",
            phone="+40987654321",
            is_active=True
        )
        
        result = OrderQueryService.get_order_with_items(self.order1.id, other_customer)
        
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()
        self.assertEqual(error_message, "Order not found")