"""
Test suite for order views in PRAHO Platform
Tests authentication, authorization, multi-tenant access, and view functionality.
"""

import uuid

from django.contrib.messages import get_messages
from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.products.models import Product
from apps.users.models import CustomerMembership, User


class OrderViewsAuthenticationTestCase(TestCase):
    """Test authentication requirements for order views"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
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

    def test_order_list_requires_authentication(self):
        """Test that order list requires authentication"""
        url = reverse('orders:order_list')
        response = self.client.get(url)

        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login/', response.url)

    def test_order_detail_requires_authentication(self):
        """Test that order detail requires authentication"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-AUTH-0001",
            currency=self.currency
        )

        url = reverse('orders:order_detail', args=[order.id])
        response = self.client.get(url)

        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login/', response.url)

    # NOTE: test_staff_only_views_require_staff was removed because
    # StaffOnlyPlatformMiddleware now blocks customer users at middleware level
    # (returns 302 redirect before view can return 403)


class OrderListViewTestCase(TestCase):
    """Test cases for order list view"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()

        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )

        # Create staff user
        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin"
        )

        # Create customer user
        self.customer_user = User.objects.create_user(
            email="customer@company.ro",
            password="testpass123"
        )

        # Create customer
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )

        # Add customer user to customer
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role="admin"
        )

        # Create test orders
        self.order1 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-LIST-0001",
            currency=self.currency,
            status="draft"
        )

        self.order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-LIST-0002",
            currency=self.currency,
            status="completed"
        )

    def test_staff_user_sees_all_orders(self):
        """Test that staff users can see all orders"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Order Management")
        self.assertContains(response, "ORD-2024-LIST-0001")
        self.assertContains(response, "ORD-2024-LIST-0002")

        # Check context
        self.assertTrue(response.context['is_staff'])
        self.assertEqual(len(response.context['orders']), 2)

    # NOTE: test_customer_user_sees_only_their_orders was removed because
    # customers access orders via portal, not platform (StaffOnlyPlatformMiddleware)

    def test_order_list_search_functionality(self):
        """Test search functionality in order list"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_list')
        response = self.client.get(url, {'search': 'LIST-0001'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ORD-2024-LIST-0001")
        self.assertNotContains(response, "ORD-2024-LIST-0002")

    def test_order_list_status_filtering(self):
        """Test status filtering in order list"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_list')
        response = self.client.get(url, {'status': 'completed'})

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "ORD-2024-LIST-0001")  # draft
        self.assertContains(response, "ORD-2024-LIST-0002")     # completed

    def test_order_list_pagination(self):
        """Test pagination in order list"""
        # Create many orders to test pagination
        for i in range(20):
            Order.objects.create(
                customer=self.customer,
                order_number=f"ORD-2024-PAGE-{i:04d}",
                currency=self.currency,
                status="draft"
            )

        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        # Should have pagination with 15 orders per page
        self.assertEqual(len(response.context['orders']), 15)

    def test_order_list_empty_state(self):
        """Test empty state when no orders exist"""
        # Delete test orders
        Order.objects.all().delete()

        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No orders yet")


class OrderDetailViewTestCase(TestCase):
    """Test cases for order detail view"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()

        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )

        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin"
        )

        self.customer_user = User.objects.create_user(
            email="customer@company.ro",
            password="testpass123"
        )

        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )

        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role="admin"
        )

        # Create tax profile for fiscal code testing
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui="RO12345678",
            is_vat_payer=True
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-DETAIL-0001",
            currency=self.currency,
            status="pending",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            notes="Test order for detail view"
        )

        # Create a real product for testing
        self.product = Product.objects.create(
            slug="web-hosting-plan",
            name="Web Hosting Plan",
            product_type="hosting",
            is_active=True
        )

        # Add order item (using minimal required fields for testing)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Web Hosting Plan",
            product_type="hosting",
            quantity=1,
            unit_price_cents=10000,
            provisioning_status="pending"
        )

        # Add status history
        OrderStatusHistory.objects.create(
            order=self.order,
            old_status="",  # Empty string for initial status
            new_status="draft",
            notes="Order created",
            changed_by=self.staff_user
        )

    def test_order_detail_staff_view(self):
        """Test order detail view for staff users"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_detail', args=[self.order.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ORD-2024-DETAIL-0001")
        self.assertContains(response, "Test Company SRL")
        self.assertContains(response, "Web Hosting Plan")
        self.assertContains(response, "121,00 RON")  # Total with VAT
        self.assertContains(response, "RO12345678")  # Fiscal code
        self.assertContains(response, "Test order for detail view")  # Notes

        # Check staff-specific features
        self.assertTrue(response.context['is_staff'])
        self.assertTrue(response.context['can_edit'])  # Pending status can be edited
        self.assertContains(response, "Change Status")
        self.assertContains(response, "Edit")

    # NOTE: test_order_detail_customer_view was removed because
    # customers access orders via portal, not platform (StaffOnlyPlatformMiddleware)

    # NOTE: test_order_detail_access_control was removed because
    # multi-tenant access control for customers is tested in portal tests

    def test_order_detail_nonexistent_order(self):
        """Test order detail with non-existent order ID"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        fake_uuid = uuid.uuid4()
        url = reverse('orders:order_detail', args=[fake_uuid])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_order_detail_completed_order_restrictions(self):
        """Test that completed orders show appropriate restrictions"""
        self.order.status = "completed"
        self.order.save()

        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_detail', args=[self.order.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

        # Should not be editable
        self.assertFalse(response.context['can_edit'])
        self.assertNotContains(response, "Edit")
        self.assertNotContains(response, "Change Status")


class OrderStatusChangeViewTestCase(TestCase):
    """Test cases for order status change functionality"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()

        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )

        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin"
        )

        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STATUS-0001",
            currency=self.currency,
            status="draft",
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

    def test_successful_status_change(self):
        """Test successful order status change"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_change_status', args=[self.order.id])
        response = self.client.post(url, {
            'status': 'pending',
            'notes': 'Order submitted for processing'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(response.status_code, 200)

        # Check JSON response
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['new_status'], 'pending')

        # Verify order status changed
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'pending')

        # Verify status history created
        self.assertEqual(self.order.status_history.count(), 1)
        history = self.order.status_history.first()
        self.assertIsNotNone(history)
        assert history is not None  # Type narrowing
        self.assertEqual(history.old_status, 'draft')
        self.assertEqual(history.new_status, 'pending')
        self.assertEqual(history.notes, 'Order submitted for processing')

    def test_invalid_status_transition(self):
        """Test invalid status transition rejection"""
        self.order.status = "completed"
        self.order.save()

        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_change_status', args=[self.order.id])
        response = self.client.post(url, {
            'status': 'draft',  # Invalid transition
            'notes': 'Trying to revert completed order'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(response.status_code, 400)

        # Check error response
        data = response.json()
        self.assertFalse(data['success'])
        self.assertIn('Invalid status transition', data['message'])

        # Verify order status unchanged
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'completed')

    # NOTE: test_status_change_requires_staff was removed because
    # StaffOnlyPlatformMiddleware now blocks customer users at middleware level
    # (returns 302 redirect before view can return 403)

    def test_status_change_missing_parameters(self):
        """Test status change with missing required parameters"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_change_status', args=[self.order.id])
        response = self.client.post(url, {
            # Missing 'status' parameter
            'notes': 'Notes without status'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['message'], 'Status is required')


class OrderCancelViewTestCase(TestCase):
    """Test cases for order cancellation functionality"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()

        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2
        )

        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin"
        )

        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@company.ro"
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-CANCEL-0001",
            currency=self.currency,
            status="pending"
        )

    def test_successful_order_cancellation(self):
        """Test successful order cancellation"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_cancel', args=[self.order.id])
        response = self.client.post(url, {
            'cancellation_reason': 'Customer requested cancellation'
        })

        # Should redirect to order detail
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.endswith(f'/orders/{self.order.id}/'))

        # Verify order cancelled
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'cancelled')

        # Verify status history
        history = self.order.status_history.first()
        self.assertIsNotNone(history)
        assert history is not None  # Type narrowing
        self.assertEqual(history.new_status, 'cancelled')
        self.assertEqual(history.notes, 'Customer requested cancellation')

        # Check success message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any("Order has been cancelled" in str(msg) for msg in messages))

    def test_cancel_completed_order_rejected(self):
        """Test that completed orders cannot be cancelled"""
        self.order.status = "completed"
        self.order.save()

        self.client.login(email="staff@pragmatichost.com", password="testpass123")

        url = reverse('orders:order_cancel', args=[self.order.id])
        response = self.client.post(url)

        # Should redirect with error
        self.assertEqual(response.status_code, 302)

        # Verify order status unchanged
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'completed')

        # Check error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any("cannot be cancelled" in str(msg) for msg in messages))
