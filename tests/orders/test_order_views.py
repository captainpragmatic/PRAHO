"""
Test suite for order views in PRAHO Platform
Tests authentication, authorization, multi-tenant access, and view functionality.
"""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages

from apps.customers.models import Customer, CustomerMembership
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.users.models import User

User = get_user_model()


class OrderViewsAuthenticationTestCase(TestCase):
    """Test authentication requirements for order views"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )

    def test_order_list_requires_authentication(self):
        """Test that order list requires authentication"""
        url = reverse('orders:order_list')
        response = self.client.get(url)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)

    def test_order_detail_requires_authentication(self):
        """Test that order detail requires authentication"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-AUTH-0001",
            currency="RON"
        )
        
        url = reverse('orders:order_detail', args=[order.id])
        response = self.client.get(url)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login/', response.url)

    def test_staff_only_views_require_staff(self):
        """Test that staff-only views require staff privileges"""
        # Create regular user
        user = User.objects.create_user(
            email="user@example.com",
            password="testpass123"
        )
        
        self.client.login(email="user@example.com", password="testpass123")
        
        # Test create view requires staff
        url = reverse('orders:order_create')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        
        # Should redirect to dashboard with error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any("Staff privileges required" in str(msg) for msg in messages))


class OrderListViewTestCase(TestCase):
    """Test cases for order list view"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create staff user
        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )
        
        # Create customer user
        self.customer_user = User.objects.create_user(
            email="customer@company.ro",
            password="testpass123"
        )
        
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
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
            currency="RON",
            status="draft",
            billing_company_name="Test Company SRL"
        )
        
        self.order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-LIST-0002",
            currency="RON",
            status="completed",
            billing_company_name="Test Company SRL"
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

    def test_customer_user_sees_only_their_orders(self):
        """Test that customer users only see their orders"""
        self.client.login(email="customer@company.ro", password="testpass123")
        
        url = reverse('orders:order_list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ORD-2024-LIST-0001")
        self.assertContains(response, "ORD-2024-LIST-0002")
        
        # Should not show staff features
        self.assertFalse(response.context['is_staff'])

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
                currency="RON",
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
        
        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )
        
        self.customer_user = User.objects.create_user(
            email="customer@company.ro",
            password="testpass123"
        )
        
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        CustomerMembership.objects.create(
            user=self.customer_user,
            customer=self.customer,
            role="admin"
        )
        
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-DETAIL-0001",
            currency="RON",
            status="pending",
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            billing_company_name="Test Company SRL",
            billing_contact_name="Ion Popescu",
            billing_email="ion@company.ro",
            billing_fiscal_code="RO12345678",
            notes="Test order for detail view"
        )
        
        # Add order item
        self.order_item = OrderItem.objects.create(
            order=self.order,
            quantity=1,
            unit_price_cents=10000,
            line_total_cents=10000,
            description="Web Hosting Plan",
            provisioning_status="pending"
        )
        
        # Add status history
        OrderStatusHistory.objects.create(
            order=self.order,
            old_status=None,
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
        self.assertContains(response, "119,00 RON")  # Total with VAT
        self.assertContains(response, "RO12345678")  # Fiscal code
        self.assertContains(response, "Test order for detail view")  # Notes
        
        # Check staff-specific features
        self.assertTrue(response.context['is_staff'])
        self.assertTrue(response.context['can_edit'])  # Pending status can be edited
        self.assertContains(response, "Change Status")
        self.assertContains(response, "Edit")

    def test_order_detail_customer_view(self):
        """Test order detail view for customer users"""
        self.client.login(email="customer@company.ro", password="testpass123")
        
        url = reverse('orders:order_detail', args=[self.order.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ORD-2024-DETAIL-0001")
        
        # Should not show staff-only features
        self.assertFalse(response.context['is_staff'])
        self.assertNotContains(response, "Change Status")
        self.assertNotContains(response, "Edit")

    def test_order_detail_access_control(self):
        """Test multi-tenant access control for order detail"""
        # Create another customer and user
        other_customer = Customer.objects.create(
            company_name="Other Company SRL",
            email="other@company.ro",
            phone="+40987654321",
            is_active=True
        )
        
        other_user = User.objects.create_user(
            email="other@company.ro",
            password="testpass123"
        )
        
        CustomerMembership.objects.create(
            user=other_user,
            customer=other_customer,
            role="admin"
        )
        
        # Try to access order from different customer
        self.client.login(email="other@company.ro", password="testpass123")
        
        url = reverse('orders:order_detail', args=[self.order.id])
        response = self.client.get(url)
        
        # Should redirect with error
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any("permission to access this order" in str(msg) for msg in messages))

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
        
        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )
        
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STATUS-0001",
            currency="RON",
            status="draft"
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
        
        self.assertEqual(response.status_code, 200)
        
        # Check error response
        data = response.json()
        self.assertFalse(data['success'])
        self.assertIn('Invalid status transition', data['error'])
        
        # Verify order status unchanged
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'completed')

    def test_status_change_requires_staff(self):
        """Test that status change requires staff privileges"""
        customer_user = User.objects.create_user(
            email="customer@company.ro",
            password="testpass123"
        )
        
        CustomerMembership.objects.create(
            user=customer_user,
            customer=self.customer,
            role="admin"
        )
        
        self.client.login(email="customer@company.ro", password="testpass123")
        
        url = reverse('orders:order_change_status', args=[self.order.id])
        response = self.client.post(url, {
            'status': 'pending',
            'notes': 'Customer trying to change status'
        })
        
        # Should redirect due to staff_required decorator
        self.assertEqual(response.status_code, 302)

    def test_status_change_missing_parameters(self):
        """Test status change with missing required parameters"""
        self.client.login(email="staff@pragmatichost.com", password="testpass123")
        
        url = reverse('orders:order_change_status', args=[self.order.id])
        response = self.client.post(url, {
            # Missing 'status' parameter
            'notes': 'Notes without status'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'Status is required')


class OrderCancelViewTestCase(TestCase):
    """Test cases for order cancellation functionality"""

    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.staff_user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )
        
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-CANCEL-0001",
            currency="RON",
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
        self.assertTrue(response.url.endswith(f'/app/orders/{self.order.id}/'))
        
        # Verify order cancelled
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, 'cancelled')
        
        # Verify status history
        history = self.order.status_history.first()
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