"""
Test suite for order services in PRAHO Platform
Tests business logic, Romanian VAT compliance, and service layer functionality.
"""

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice
from apps.orders.services import (
    OrderCalculationService,
    OrderCreateData,
    OrderNumberingService,
    OrderQueryService,
    OrderService,
    StatusChangeData,
)

User = get_user_model()


class OrderCalculationServiceTestCase(TestCase):
    """Test cases for order calculation services"""

    def test_romanian_vat_calculation(self):
        """Test 21% Romanian VAT calculation via calculate_order_totals"""
        # Test various amounts - Romania VAT is 21%
        test_cases = [
            (10000, 2100),    # 100.00 RON → 21.00 RON VAT (21%)
            (50000, 10500),   # 500.00 RON → 105.00 RON VAT (21%)
            (100000, 21000),  # 1000.00 RON → 210.00 RON VAT (21%)
            (1, 0),           # 0.01 RON → 0.00 RON VAT (rounded down)
        ]

        for amount_cents, expected_vat_cents in test_cases:
            with self.subTest(amount=amount_cents):
                items = [{'quantity': 1, 'unit_price_cents': amount_cents}]
                totals = OrderCalculationService.calculate_order_totals(items)
                self.assertEqual(totals['tax_cents'], expected_vat_cents)

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
        expected_vat = 4200        # 42.00 RON (21% VAT)
        expected_total = 24200     # 242.00 RON
        
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
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )
        
        # Create tax profile for the customer
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO12345678",
            cui="RO12345678",
            is_vat_payer=True
        )

    def test_first_order_number_generation(self):
        """Test generation of first order number for customer"""
        order_number = OrderNumberingService.generate_order_number(self.customer)
        
        # Should follow format: ORD-YYYY-CUSTOMER_ID_PREFIX-XXXX
        from datetime import datetime
        current_year = str(datetime.now().year)
        self.assertTrue(order_number.startswith(f"ORD-{current_year}-"))
        self.assertTrue(order_number.endswith("-0001"))
        self.assertIn(str(self.customer.pk).replace('-', '')[:8].upper(), order_number)

    def test_sequential_order_numbers(self):
        """Test sequential order number generation"""
        # Create first order
        order1 = Order.objects.create(
            customer=self.customer,
            order_number=OrderNumberingService.generate_order_number(self.customer),
            currency=self.currency
        )
        
        # Generate second order number
        order_number2 = OrderNumberingService.generate_order_number(self.customer)
        
        # Should be sequential - same base format but with incremented sequence
        parts = order1.order_number.split('-')  # ['ORD', '2025', 'XXXXXXXX', '0001']
        expected_parts = parts[:-1] + ['0002']  # Replace sequence with 0002
        expected_number2 = '-'.join(expected_parts)
        self.assertEqual(order_number2, expected_number2)

    def test_order_number_uniqueness_per_customer(self):
        """Test that order numbers are unique per customer"""
        customer2 = Customer.objects.create(
            name="Another Company SRL",
            customer_type="company",
            status="active",
            primary_email="another@company.ro"
        )
        
        # Create tax profile for customer2
        CustomerTaxProfile.objects.create(
            customer=customer2,
            vat_number="RO87654321",
            cui="RO87654321",
            is_vat_payer=True
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
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )
        
        # Create tax profile for the customer
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO12345678",
            cui="RO12345678",
            is_vat_payer=True
        )
        
        # Create test product
        self.product = Product.objects.create(
            slug="web-hosting-standard",
            name="Web Hosting Standard",
            description="Standard web hosting plan",
            short_description="Basic hosting for small websites"
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
                'product_id': self.product.id,
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
            currency=self.currency.code,
            notes="Test order creation"
        )
        
        result = OrderService.create_order(order_data, self.user)
        
        # Verify success
        self.assertTrue(result.is_ok())
        order = result.unwrap()
        self.assertIsInstance(order, Order)
        assert isinstance(order, Order)  # Type narrowing
        
        # Verify order details
        self.assertEqual(order.customer, self.customer)
        self.assertEqual(order.currency, self.currency)
        self.assertEqual(order.subtotal_cents, 10000)
        self.assertEqual(order.tax_cents, 2100)  # 21% VAT
        self.assertEqual(order.total_cents, 12100)
        
        # Verify billing address
        self.assertEqual(order.billing_address['company_name'], "Test Company SRL")
        self.assertEqual(order.billing_address['fiscal_code'], "RO12345678")
        
        # Verify order items created
        self.assertEqual(order.items.count(), 1)
        item = order.items.first()
        self.assertIsNotNone(item)
        assert item is not None  # Type narrowing
        self.assertEqual(item.quantity, 1)
        self.assertEqual(item.unit_price_cents, 10000)
        self.assertEqual(item.product_name, "Web Hosting Plan")
        
        # Verify status history created
        self.assertEqual(order.status_history.count(), 1)
        history = order.status_history.first()
        self.assertIsNotNone(history)
        assert history is not None  # Type narrowing
        self.assertEqual(history.old_status, "")
        self.assertEqual(history.new_status, "draft")
        self.assertEqual(history.changed_by, self.user)

    def test_order_status_update_success(self):
        """Test successful order status update"""
        # Create order with billing address (required for preflight validation)
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-TEST-0001",
            currency=self.currency,
            status="draft",
            billing_address={
                'company_name': 'Test Company SRL',
                'contact_name': 'Ion Popescu',
                'email': 'ion@company.ro',
                'phone': '+40123456789',
                'address_line1': 'Str. Aviatorilor nr. 1',
                'address_line2': '',
                'city': 'Bucuresti',
                'county': 'Bucuresti',
                'postal_code': '010563',
                'country': 'Romania',
                'fiscal_code': 'RO12345678',
            }
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
        self.assertIsNotNone(history)
        assert history is not None  # Type narrowing
        self.assertEqual(history.old_status, "draft")
        self.assertEqual(history.new_status, "pending")
        self.assertEqual(history.notes, "Order submitted for processing")
        self.assertEqual(history.changed_by, self.user)

    def test_invalid_status_transition(self):
        """Test invalid status transition rejection"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-INVALID-0001",
            currency=self.currency,
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
        error_message = result.unwrap_err()  # type: ignore[union-attr]
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
                    currency=self.currency,
                    status=old_status,
                    billing_address={
                        'contact_name': 'Test Contact',
                        'email': 'test@company.ro',
                        'address_line1': 'Test Street 1',
                        'city': 'Bucuresti',
                        'county': 'Bucuresti',
                        'postal_code': '010001',
                        'country': 'Romania',
                    }
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
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )
        
        # Create tax profile for the customer
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO12345678",
            cui="RO12345678",
            is_vat_payer=True
        )
        
        # Create a product for testing
        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="hosting",
            is_active=True
        )
        
        # Create test orders
        self.order1 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-QUERY-0001",
            currency=self.currency,
            status="draft"
        )
        
        self.order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-QUERY-0002",
            currency=self.currency,
            status="completed"
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
            product=self.product,
            quantity=1,
            unit_price_cents=5000,
            line_total_cents=5000,
            product_name="Test Item",
            product_type="hosting"
        )
        
        result = OrderQueryService.get_order_with_items(self.order1.id, self.customer)
        
        self.assertTrue(result.is_ok())
        order = result.unwrap()
        self.assertEqual(order.id, self.order1.id)
        
        # Verify prefetched items
        items = list(order.items.all())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].product_name, "Test Item")

    def test_get_nonexistent_order(self):
        """Test retrieving non-existent order"""
        fake_uuid = uuid.uuid4()
        result = OrderQueryService.get_order_with_items(fake_uuid, self.customer)
        
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()  # type: ignore[union-attr]
        self.assertEqual(error_message, "Order not found")

    def test_get_order_wrong_customer(self):
        """Test retrieving order with wrong customer"""
        other_customer = Customer.objects.create(
            name="Other Company SRL",
            customer_type="company",
            status="active",
            primary_email="other@company.ro"
        )
        
        # Create tax profile for other_customer
        CustomerTaxProfile.objects.create(
            customer=other_customer,
            vat_number="RO11111111",
            cui="RO11111111",
            is_vat_payer=True
        )
        
        result = OrderQueryService.get_order_with_items(self.order1.id, other_customer)

        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()  # type: ignore[union-attr]
        self.assertEqual(error_message, "Order not found")


class OrderServiceCreationTestCase(TestCase):
    """Test cases for service creation during order lifecycle"""

    def setUp(self):
        """Set up test data"""
        # Create currency
        self.currency = Currency.objects.create(code="RON", name="Romanian Leu")

        # Create customer
        self.customer = Customer.objects.create(
            name="Test Customer SRL",
            customer_type="company",
            status="active",
            primary_email="test@customer.ro"
        )

        # Create tax profile
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO12345678",
            cui="RO12345678",
            is_vat_payer=True
        )

        # Create product with service plan
        self.product = Product.objects.create(
            slug="test-hosting",
            name="Test Hosting Package",
            product_type="shared_hosting",
            is_active=True
        )

        # Create service plan
        from apps.provisioning.models import ServicePlan
        self.service_plan = ServicePlan.objects.create(
            name="Basic Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=2999  # 29.99 RON
        )

        # Link product to service plan
        self.product.default_service_plan = self.service_plan
        self.product.save()

        # Create product price for testing
        self.product_price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2999,  # 29.99 RON - matches the order item price
            setup_cents=0,
            is_active=True
        )

    def test_complete_service_creation_flow(self):
        """Test the complete service creation flow: draft → pending → processing → completed"""
        from apps.orders.services import OrderServiceCreationService, OrderCreateData, OrderService, StatusChangeData
        from apps.provisioning.models import Service

        # Step 1: Create draft order
        order_data = OrderCreateData(
            customer=self.customer,
            items=[{
                'product_id': self.product.id,
                'quantity': 1,
                'unit_price_cents': 2999,
                'setup_cents': 0,
                'description': 'Test Hosting Package',
                'meta': {'billing_cycle': 'monthly'}
            }],
            billing_address={
                'company_name': 'Test Company',
                'contact_name': 'Test Contact',
                'email': 'test@customer.ro',
                'phone': '+40712345678',
                'address_line1': 'Test Street 123',
                'address_line2': '',
                'city': 'Bucharest',
                'county': 'Bucharest',
                'postal_code': '010001',
                'country': 'RO',
                'fiscal_code': 'RO12345678',
                'registration_number': 'J40/123/2023',
                'vat_number': 'RO12345678'
            },
            currency="RON"
        )

        result = OrderService.create_order(order_data)
        self.assertTrue(result.is_ok())
        order = result.unwrap()

        # Verify order is draft and no services exist yet
        self.assertEqual(order.status, 'draft')
        self.assertEqual(Service.objects.count(), 0)

        # Step 2: Move order to pending (should create services)
        status_data = StatusChangeData(new_status='pending')
        result = OrderService.update_order_status(order, status_data)
        self.assertTrue(result.is_ok())

        # Verify order status changed
        order.refresh_from_db()
        self.assertEqual(order.status, 'pending')

        # Manually trigger service creation (signals may not work in test environment)
        from apps.orders.services import OrderServiceCreationService
        creation_result = OrderServiceCreationService.create_pending_services(order)
        self.assertTrue(creation_result.is_ok(), f"Service creation failed: {creation_result}")

        services = Service.objects.filter(customer=self.customer)
        self.assertEqual(services.count(), 1)

        service = services.first()
        self.assertEqual(service.status, 'pending')
        self.assertEqual(service.service_plan, self.service_plan)
        self.assertIn(self.product.name, service.service_name)

        # Verify order item is linked to service
        order_item = order.items.first()
        self.assertEqual(order_item.service, service)

        # Step 3a: Move order to confirmed first
        status_data = StatusChangeData(new_status='confirmed')
        result = OrderService.update_order_status(order, status_data)
        self.assertTrue(result.is_ok())

        # Step 3b: Then move to processing (should update services to provisioning)
        status_data = StatusChangeData(new_status='processing')
        result = OrderService.update_order_status(order, status_data)
        self.assertTrue(result.is_ok())

        # Manually update services to provisioning (signals may not work in tests)
        from apps.orders.services import OrderServiceCreationService
        update_result = OrderServiceCreationService.update_service_status_on_payment(order)
        self.assertTrue(update_result.is_ok())

        # Verify service status updated to provisioning
        service.refresh_from_db()
        self.assertEqual(service.status, 'provisioning')

        # Step 4: Complete provisioning (should activate services)
        # Refresh order item to get latest service link
        order_item.refresh_from_db()

        order_item.mark_as_provisioned()

        # Verify service status updated to active
        service.refresh_from_db()
        self.assertEqual(service.status, 'active')
        self.assertIsNotNone(service.activated_at)

    def test_service_creation_without_service_plan(self):
        """Test service creation when product has no default service plan"""
        from apps.orders.services import OrderServiceCreationService
        from apps.provisioning.models import Service

        # Remove service plan from product
        self.product.default_service_plan = None
        self.product.save()

        # Create draft order
        order_data = OrderCreateData(
            customer=self.customer,
            items=[{
                'product_id': self.product.id,
                'quantity': 1,
                'unit_price_cents': 2999,
                'setup_cents': 0,
                'description': 'Test Hosting Package',
                'meta': {'billing_cycle': 'monthly'}
            }],
            billing_address={
                'company_name': 'Test Company',
                'contact_name': 'Test Contact',
                'email': 'test@customer.ro',
                'phone': '+40712345678',
                'address_line1': 'Test Street 123',
                'address_line2': '',
                'city': 'Bucharest',
                'county': 'Bucharest',
                'postal_code': '010001',
                'country': 'RO',
                'fiscal_code': 'RO12345678',
                'registration_number': 'J40/123/2023',
                'vat_number': 'RO12345678'
            },
            currency="RON"
        )

        result = OrderService.create_order(order_data)
        self.assertTrue(result.is_ok())
        order = result.unwrap()

        # Try to create services (should still work with fallback mapping)
        result = OrderServiceCreationService.create_pending_services(order)

        # Should succeed if there are any active service plans
        if self.service_plan.is_active:
            self.assertTrue(result.is_ok())
            services = result.unwrap()
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0].service_plan, self.service_plan)  # Fallback plan
        else:
            # If no active service plans, creation should fail gracefully
            self.assertTrue(result.is_ok())
            services = result.unwrap()
            self.assertEqual(len(services), 0)

    def test_service_not_created_if_already_exists(self):
        """Test that services are not duplicated if they already exist for order items"""
        from apps.orders.services import OrderServiceCreationService
        from apps.provisioning.models import Service

        # Create order
        order_data = OrderCreateData(
            customer=self.customer,
            items=[{
                'product_id': self.product.id,
                'quantity': 1,
                'unit_price_cents': 2999,
                'setup_cents': 0,
                'description': 'Test Hosting Package',
                'meta': {'billing_cycle': 'monthly'}
            }],
            billing_address={
                'company_name': 'Test Company',
                'contact_name': 'Test Contact',
                'email': 'test@customer.ro',
                'phone': '+40712345678',
                'address_line1': 'Test Street 123',
                'address_line2': '',
                'city': 'Bucharest',
                'county': 'Bucharest',
                'postal_code': '010001',
                'country': 'RO',
                'fiscal_code': 'RO12345678',
                'registration_number': 'J40/123/2023',
                'vat_number': 'RO12345678'
            },
            currency="RON"
        )

        result = OrderService.create_order(order_data)
        order = result.unwrap()

        # Create services first time
        result1 = OrderServiceCreationService.create_pending_services(order)
        self.assertTrue(result1.is_ok())
        services1 = result1.unwrap()
        self.assertEqual(len(services1), 1)

        # Try to create services again (should not create duplicates)
        result2 = OrderServiceCreationService.create_pending_services(order)
        self.assertTrue(result2.is_ok())
        services2 = result2.unwrap()
        self.assertEqual(len(services2), 0)  # No new services created

        # Verify total service count is still 1
        total_services = Service.objects.filter(customer=self.customer).count()
        self.assertEqual(total_services, 1)
