"""
Simple access control tests for PRAHO Platform security audit fixes.
Tests critical security fixes for customers vs staff access.
"""

from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase

from apps.common.decorators import (
    billing_staff_required,
    can_create_internal_notes,
    can_edit_proforma,
    can_manage_financial_data,
    can_view_internal_notes,
    staff_required,
    staff_required_strict,
)

User = get_user_model()


class SimpleAccessControlTestCase(TestCase):
    """Test basic access control for security fixes"""

    def setUp(self):
        """Set up test data"""
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='staff@praho.ro',
            password='staffpass123',
            first_name='Staff',
            last_name='Member',
            is_staff=True,
            staff_role='admin'
        )
        
        # Create customer user  
        self.customer_user = User.objects.create_user(
            email='customer@example.com',
            password='customerpass123',
            first_name='Customer',
            last_name='User'
        )
        
        self.client = Client()

    def test_billing_staff_decorator_blocks_customers(self):
        """Test that billing staff decorator blocks customer users"""
        # Login as customer
        self.client.login(email='customer@example.com', password='customerpass123')
        
        # Create a URL that would use billing_staff_required decorator
        # This tests the decorator itself by making a direct request
        
        @billing_staff_required
        def test_view(request):
            return HttpResponse('success')
        
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.customer_user
        
        # Add message storage to the request
        request.session = {}
        request._messages = FallbackStorage(request)
        
        response = test_view(request)
        self.assertEqual(response.status_code, 302)  # Redirect
        self.assertIn('/app/', response.url)

    def test_staff_required_decorator_blocks_customers(self):
        """Test that staff_required decorator blocks customer users"""
        
        @staff_required_strict
        def test_view(request):
            return HttpResponse('success')
        
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.customer_user
        
        # Add message storage to the request
        request.session = {}
        request._messages = FallbackStorage(request)
        
        response = test_view(request)
        self.assertEqual(response.status_code, 403)  # Forbidden

    def test_staff_required_decorator_allows_staff(self):
        """Test that staff_required decorator allows staff users"""
        
        @staff_required
        def test_view(request):
            return HttpResponse('success')
        
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.staff_user
        
        response = test_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'success')

    def test_billing_staff_required_allows_staff(self):
        """Test that billing_staff_required decorator allows staff users"""
        
        @billing_staff_required
        def test_view(request):
            return HttpResponse('success')
        
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.staff_user
        
        response = test_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'success')

    def test_can_edit_proforma_function(self):
        """Test the can_edit_proforma permission function"""
        
        # Mock proforma object
        class MockProforma:
            is_expired = False
        
        proforma = MockProforma()
        
        # Staff should be able to edit non-expired proformas
        self.assertTrue(can_edit_proforma(self.staff_user, proforma))
        
        # Customers should not be able to edit proformas
        self.assertFalse(can_edit_proforma(self.customer_user, proforma))
        
        # Expired proformas should not be editable by anyone
        proforma.is_expired = True
        self.assertFalse(can_edit_proforma(self.staff_user, proforma))
        self.assertFalse(can_edit_proforma(self.customer_user, proforma))

    def test_can_create_internal_notes_function(self):
        """Test the can_create_internal_notes permission function"""
        
        # Staff should be able to create internal notes
        self.assertTrue(can_create_internal_notes(self.staff_user))
        
        # Customers should not be able to create internal notes
        self.assertFalse(can_create_internal_notes(self.customer_user))

    def test_can_view_internal_notes_function(self):
        """Test the can_view_internal_notes permission function"""
        
        # Staff should be able to view internal notes
        self.assertTrue(can_view_internal_notes(self.staff_user))
        
        # Customers should not be able to view internal notes  
        self.assertFalse(can_view_internal_notes(self.customer_user))

    def test_can_manage_financial_data_function(self):
        """Test the can_manage_financial_data permission function"""
        
        # Admin staff should be able to manage financial data
        self.assertTrue(can_manage_financial_data(self.staff_user))
        
        # Customers should not be able to manage financial data
        self.assertFalse(can_manage_financial_data(self.customer_user))

    def test_user_role_properties(self):
        """Test user role properties work correctly"""
        # Test staff user properties
        self.assertTrue(self.staff_user.is_staff)
        self.assertTrue(self.staff_user.is_staff_user)
        self.assertEqual(self.staff_user.staff_role, 'admin')
        
        # Test customer user properties
        self.assertFalse(self.customer_user.is_staff)
        self.assertFalse(self.customer_user.is_staff_user)
        self.assertEqual(self.customer_user.staff_role, '')
        
    def tearDown(self):
        """Clean up test data"""
        # Clean up is handled by Django's TestCase automatically
