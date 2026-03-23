"""
Test suite for order services in PRAHO Platform
Tests business logic, Romanian VAT compliance, and service layer functionality.
"""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.orders.services import (
    OrderCalculationService,
    OrderCreateData,
    OrderNumberingService,
    OrderQueryService,
    OrderService,
    StatusChangeData,
)
from apps.products.models import Product, ProductPrice
from tests.helpers.fsm_helpers import force_status

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
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
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
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
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
        # FSM: submit() (draft→awaiting_payment) requires at least one item on the order
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type="hosting",
            quantity=1,
            unit_price_cents=5000,
        )
        # Preflight validation requires a current price for the order currency
        ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=5000,
            setup_cents=0,
            is_active=True,
        )

        # Update status
        status_data = StatusChangeData(
            new_status="awaiting_payment",
            notes="Order submitted for processing",
            changed_by=self.user
        )

        result = OrderService.update_order_status(order, status_data)

        # Verify success
        self.assertTrue(result.is_ok(), f"Expected success, got error: {result.unwrap_err() if result.is_err() else 'N/A'}")
        updated_order = result.unwrap()
        self.assertEqual(updated_order.status, "awaiting_payment")

        # Verify status history
        self.assertEqual(order.status_history.count(), 1)
        history = order.status_history.first()
        self.assertIsNotNone(history)
        assert history is not None  # Type narrowing
        self.assertEqual(history.old_status, "draft")
        self.assertEqual(history.new_status, "awaiting_payment")
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

        # Verify failure — (completed, draft) is not in the TRANSITION_MAP
        self.assertTrue(result.is_err())
        error_message = result.unwrap_err()  # type: ignore[union-attr]
        self.assertTrue(
            "No transition from" in error_message
            or "Invalid status transition" in error_message,
            f"Expected a transition error, got: {error_message}",
        )

        # Verify order status unchanged
        order.refresh_from_db()
        self.assertEqual(order.status, "completed")

    def test_valid_status_transitions(self):
        """Test all valid status transitions"""
        valid_transitions = [
            ("draft", "awaiting_payment"),
            ("draft", "cancelled"),
            ("awaiting_payment", "paid"),
            ("awaiting_payment", "cancelled"),
            ("awaiting_payment", "failed"),
            ("paid", "provisioning"),
            ("paid", "cancelled"),
            ("paid", "in_review"),
            ("in_review", "provisioning"),
            ("in_review", "cancelled"),
            ("provisioning", "completed"),
            ("provisioning", "failed"),
            ("provisioning", "cancelled"),
            # NOTE: ("failed", "awaiting_payment") uses FSM retry() method which is not
            # exposed via update_order_status service — omitted here intentionally
            ("failed", "cancelled"),
        ]

        for old_status, new_status in valid_transitions:
            with self.subTest(transition=f"{old_status} → {new_status}"):
                order = Order.objects.create(
                    customer=self.customer,
                    order_number=f"ORD-2024-{old_status[:4].upper()}-{new_status[:4].upper()}",
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

                # FSM: draft → awaiting_payment requires items + a current price (preflight validation)
                if old_status == "draft" and new_status == "awaiting_payment":
                    item_product = Product.objects.create(
                        slug=f"transition-product-{old_status}-{new_status}",
                        name="Transition Test Product",
                        product_type="hosting",
                        is_active=True,
                    )
                    OrderItem.objects.create(
                        order=order,
                        product=item_product,
                        product_name=item_product.name,
                        product_type=item_product.product_type,
                        quantity=1,
                        unit_price_cents=1000,
                    )
                    ProductPrice.objects.create(
                        product=item_product,
                        currency=self.currency,
                        monthly_price_cents=1000,
                        setup_cents=0,
                        is_active=True,
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
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
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
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu"})

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
        from apps.orders.services import (  # noqa: PLC0415
            OrderCreateData,
            OrderService,
            OrderServiceCreationService,
            StatusChangeData,
        )
        from apps.provisioning.models import Service  # noqa: PLC0415

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

        # Step 2: Move order to awaiting_payment (should create services)
        status_data = StatusChangeData(new_status='awaiting_payment')
        result = OrderService.update_order_status(order, status_data)
        self.assertTrue(result.is_ok())

        # Verify order status changed
        order.refresh_from_db()
        self.assertEqual(order.status, 'awaiting_payment')

        # Manually trigger service creation (signals may not work in test environment)
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

        # Step 3a: Move order to paid first
        status_data = StatusChangeData(new_status='paid')
        result = OrderService.update_order_status(order, status_data)
        self.assertTrue(result.is_ok())

        # Step 3b: Then move to provisioning (should update services to provisioning)
        status_data = StatusChangeData(new_status='provisioning')
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

        # FSM: provisioning_status must be in_progress before complete_provisioning() can fire
        force_status(order_item, "in_progress", field_name="provisioning_status")
        order_item.mark_as_provisioned()

        # Verify service status updated to active
        service.refresh_from_db()
        self.assertEqual(service.status, 'active')
        self.assertIsNotNone(service.activated_at)

    def test_service_creation_without_service_plan(self):
        """Test service creation when product has no default service plan"""
        from apps.orders.services import OrderServiceCreationService

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


<<<<<<< HEAD
class AuditTrailOnConfirmOrderTestCase(TestCase):
    """C6: confirm_order must call AuditService.log_simple_event('order_payment_confirmed')."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Audit Trail Test SRL", customer_type="company",
            status="active", primary_email="audit-trail@test.ro",
        )

    def _create_order(self, total_cents: int = 12100) -> Order:
        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total_cents - 2100, tax_cents=2100, total_cents=total_cents,
            billing_address={},
        )
        return order

    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    def test_confirm_order_logs_payment_confirmed_audit_event(self, mock_threshold):
        """C6 GREEN: confirm_order must create an AuditEvent with content_object=order.

        The audit record must be linked to the Order instance (not content_object=None
        which log_security_event hardcodes). We assert against real AuditEvent records
        so that if the implementation falls back to content_object=None, the test fails.
        """
        from django.contrib.contenttypes.models import ContentType  # noqa: PLC0415

        from apps.audit.models import AuditEvent  # noqa: PLC0415
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        mock_threshold.return_value = 1000000  # High threshold so order goes to provisioning

        order = self._create_order(total_cents=12100)
        force_status(order, "awaiting_payment")
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
        )

        result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
        self.assertTrue(result.is_ok())

        # Assert a real AuditEvent was created with:
        # 1. The correct event_type
        # 2. content_object pointing to the Order (not None / fallback User)
        order_content_type = ContentType.objects.get_for_model(order)
        audit_event = AuditEvent.objects.filter(
            action="order_payment_confirmed",
            content_type=order_content_type,
            object_id=str(order.id),
        ).first()
        self.assertIsNotNone(
            audit_event,
            "AuditEvent with action='order_payment_confirmed' linked to Order was not created. "
            "The audit record must use AuditService.log_simple_event(content_object=order) — "
            "not log_security_event() which hardcodes content_object=None."
        )
        # Verify invoice_id is in the metadata
        self.assertIn("invoice_id", audit_event.metadata,
                      "order_payment_confirmed audit event must include invoice_id in metadata")
        self.assertEqual(audit_event.metadata["invoice_id"], str(invoice.id))


# ===============================================================================
# B-3: confirm_order audit history gap
# The first status history record (awaiting_payment→paid) MUST be written
# immediately after mark_paid(), before the second FSM transition fires.
# If it is written after flag_for_review()/start_provisioning(), the order
# object's .status is already the third state, so the record would silently
# describe the wrong transition.
# ===============================================================================


class ConfirmOrderAuditHistoryOrderTestCase(TestCase):
    """B-3: Both OrderStatusHistory records must be created in transition order."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="History Order Test SRL",
            customer_type="company",
            status="active",
            primary_email="history-order@test.ro",
        )

    def _create_awaiting_payment_order(self, total_cents: int = 12100) -> "Order":
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total_cents - 2100,
            tax_cents=2100,
            total_cents=total_cents,
            billing_address={},
        )
        force_status(order, "awaiting_payment")
        return order

    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    def test_confirm_order_below_threshold_creates_two_history_records_in_order(
        self, mock_threshold: object
    ) -> None:
        """Below review threshold: must emit awaiting_payment→paid then paid→provisioning."""
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.models import OrderStatusHistory  # noqa: PLC0415
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        mock_threshold.return_value = 1_000_000_00  # Far above test order total

        order = self._create_awaiting_payment_order(total_cents=12100)
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
        self.assertTrue(result.is_ok(), f"confirm_order failed: {result}")

        records = list(
            OrderStatusHistory.objects.filter(order=order)
            .order_by("created_at")
            .values_list("old_status", "new_status")
        )

        # Must have exactly two records from the double-transition
        self.assertEqual(
            len(records),
            2,
            f"Expected 2 OrderStatusHistory records, got {len(records)}: {records}",
        )
        # First: awaiting_payment → paid
        self.assertEqual(
            records[0],
            ("awaiting_payment", "paid"),
            f"First history record must be awaiting_payment→paid, got {records[0]}",
        )
        # Second: paid → provisioning
        self.assertEqual(
            records[1],
            ("paid", "provisioning"),
            f"Second history record must be paid→provisioning, got {records[1]}",
        )

    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    def test_confirm_order_above_threshold_creates_two_history_records_in_order(
        self, mock_threshold: object
    ) -> None:
        """Above review threshold: must emit awaiting_payment→paid then paid→in_review."""
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.models import OrderStatusHistory  # noqa: PLC0415
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        mock_threshold.return_value = 100  # Below test order total → triggers review gate

        order = self._create_awaiting_payment_order(total_cents=12100)
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
        self.assertTrue(result.is_ok(), f"confirm_order failed: {result}")

        records = list(
            OrderStatusHistory.objects.filter(order=order)
            .order_by("created_at")
            .values_list("old_status", "new_status")
        )

        self.assertEqual(
            len(records),
            2,
            f"Expected 2 OrderStatusHistory records, got {len(records)}: {records}",
        )
        self.assertEqual(
            records[0],
            ("awaiting_payment", "paid"),
            f"First history record must be awaiting_payment→paid, got {records[0]}",
        )
        self.assertEqual(
            records[1],
            ("paid", "in_review"),
            f"Second history record must be paid→in_review, got {records[1]}",
        )

    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    def test_first_history_record_is_written_before_second_transition(
        self, mock_threshold: object
    ) -> None:
        """B-3 ordering guard: awaiting_payment→paid record must be persisted BEFORE
        start_provisioning() is called.

        Strategy: patch Order.start_provisioning to raise after mark_paid() succeeds.
        If the history is written BEFORE start_provisioning(), the first record survives
        (the outer atomic block rolls back, but we use a savepoint probe).
        If the history is written AFTER start_provisioning() (the current bug), nothing
        is written even for the first transition.

        We verify the fix by ensuring the history_record OLD→NEW strings correctly
        reflect the state at the time of writing (awaiting_payment→paid),
        NOT the post-transition state (paid→provisioning).
        """
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.models import OrderStatusHistory  # noqa: PLC0415
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        # Below review threshold so start_provisioning() is called
        mock_threshold.return_value = 1_000_000_00

        order = self._create_awaiting_payment_order(total_cents=12100)
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
        self.assertTrue(result.is_ok(), f"confirm_order failed: {result}")

        # The first history record must describe awaiting_payment→paid,
        # not the post-transition state (which would be paid→provisioning).
        # If the records were reversed or the old_status were wrong, this assertion fails.
        first_record = (
            OrderStatusHistory.objects.filter(order=order).order_by("created_at").first()
        )
        self.assertIsNotNone(first_record, "No OrderStatusHistory records created")
        assert first_record is not None  # type narrowing
        self.assertEqual(
            first_record.old_status,
            "awaiting_payment",
            "First history record old_status must be 'awaiting_payment' — "
            "if the history is written after the second FSM transition, old_status "
            "will reflect the post-transition state instead.",
        )
        self.assertEqual(
            first_record.new_status,
            "paid",
            "First history record new_status must be 'paid'.",
        )


# ===============================================================================
# TASK 5.8: Proforma reuse on retry (failed → awaiting_payment)
# ===============================================================================


class ProformaReuseOnRetryTest(TestCase):
    """Task 5.8: When an order goes from 'failed' back to 'awaiting_payment',
    update_order_status must reuse the existing proforma rather than creating a
    new one (H4 fix in services.py).

    This guards against orphan proformas: if a payment attempt fails and the
    customer retries, a fresh proforma would have a different number and the
    customer would receive two proformas for the same order.
    """

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Proforma Reuse SRL",
            customer_type="company",
            status="active",
            primary_email="proforma-reuse@test.ro",
        )
        self.product = Product.objects.create(
            name="Reuse Plan",
            slug="reuse-plan",
            product_type="shared_hosting",
            is_active=True,
        )
        from apps.billing.proforma_models import ProformaSequence  # noqa: PLC0415
        ProformaSequence.objects.get_or_create(scope="default")

    def _create_draft_order(self):
        from decimal import Decimal  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={"company_name": "Reuse SRL", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order

    def test_proforma_is_reused_on_retry_from_failed(self):
        """Task 5.8: Proforma linked on first awaiting_payment is reused on retry.

        Lifecycle:
        1. Order force_status → awaiting_payment (simulate successful first submission).
        2. ProformaService.create_from_order() creates the proforma (same as update_order_status).
        3. Order force_status → failed.
        4. update_order_status(failed → awaiting_payment) — must reuse existing proforma.

        Using force_status for the initial awaiting_payment bypasses preflight
        validation which requires full billing address + product price. The core
        behavior under test is the reuse guard in step 4 (H4 fix in services.py).
        """
        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_draft_order()

        # Step 1: Simulate first awaiting_payment (bypass preflight via force_status)
        force_status(order, "awaiting_payment")

        # Step 2: Simulate proforma creation that update_order_status would do
        proforma_result = ProformaService.create_from_order(order)
        self.assertTrue(proforma_result.is_ok(), f"ProformaService.create_from_order failed: {proforma_result}")
        order.refresh_from_db()

        first_proforma = order.proforma
        self.assertIsNotNone(first_proforma, "Proforma must be created on first awaiting_payment")
        first_proforma_id = first_proforma.id

        # Step 3: awaiting_payment → failed (payment attempt failed)
        result_fail = OrderService.update_order_status(
            order, StatusChangeData(new_status="failed", notes="payment failed")
        )
        self.assertTrue(result_fail.is_ok(), f"Failed transition failed: {result_fail}")
        order.refresh_from_db()
        self.assertEqual(order.status, "failed")

        # Verify proforma FK is still present after failure
        self.assertEqual(
            order.proforma_id,
            first_proforma_id,
            "Proforma FK must be preserved through failed state",
        )

        # Step 4: failed → awaiting_payment again (retry — must reuse proforma)
        result_retry = OrderService.update_order_status(
            order, StatusChangeData(new_status="awaiting_payment", notes="retry after failure")
        )
        self.assertTrue(result_retry.is_ok(), f"Retry transition failed: {result_retry}")
        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")

        # CRITICAL ASSERTION: same proforma, no new one created
        self.assertEqual(
            order.proforma_id,
            first_proforma_id,
            f"Proforma must be REUSED on retry — expected id={first_proforma_id}, "
            f"got id={order.proforma_id}. A second proforma was created instead of reusing.",
        )

        # Verify the proforma itself still exists and has the correct ID
        reused_proforma = ProformaInvoice.objects.get(id=first_proforma_id)
        self.assertEqual(
            reused_proforma.id,
            first_proforma_id,
            "The original proforma must still exist and be linked after retry",
        )


class OrderCreateMissingProductIdRegressionTests(TestCase):
    """Regression tests for issue #127 — items without product_id must fail the order."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu"})
        self.customer = Customer.objects.create(
            name="Test Customer SRL",
            customer_type="company",
            status="active",
            primary_email="regression127@customer.ro",
        )
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO99999999",
            cui="RO99999999",
            is_vat_payer=True,
        )

    def _make_order_data(self, product_id: int | None) -> OrderCreateData:
        return OrderCreateData(
            customer=self.customer,
            currency="RON",
            items=[
                {
                    "product_id": product_id,
                    "description": "Test item",
                    "quantity": 1,
                    "unit_price_cents": 1000,
                }
            ],
            billing_address={
                "company_name": "Test SRL",
                "country": "RO",
            },
            notes="",
            meta={},
            idempotency_key=str(uuid.uuid4()),
        )

    def test_order_fails_when_item_missing_product_id(self) -> None:
        """create_order must return Err (not silently skip) when any item has no product_id."""
        result = OrderService.create_order(self._make_order_data(None))
        self.assertTrue(result.is_err(), "Expected Err when product_id is None")
        self.assertIn("product_id", result.unwrap_err())

    def test_order_succeeds_when_all_items_have_product_id(self) -> None:
        """Sanity check: a valid product_id still creates the order successfully."""
        product = Product.objects.create(
            slug="regression-127-product",
            name="Regression 127 Product",
            product_type="shared_hosting",
            is_active=True,
        )
        result = OrderService.create_order(self._make_order_data(product.id))
        self.assertTrue(result.is_ok(), f"Expected Ok, got: {result}")
