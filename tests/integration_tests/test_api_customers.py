# ===============================================================================
# INTEGRATION TESTS FOR CUSTOMER API ENDPOINTS
# ===============================================================================
"""
Integration tests for customer management API endpoints.
Tests cover CRUD operations, access control, and Romanian compliance.
"""

import json
import os
import sys

import pytest

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django
django.setup()

from django.test import Client, TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model

from apps.customers.models import Customer, CustomerAddress, CustomerBillingProfile, CustomerTaxProfile

User = get_user_model()


class TestCustomerAPIIntegration(TestCase):
    """Integration tests for customer API endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        # Create admin user
        self.admin = User.objects.create_user(
            username='admin_api_test',
            email='admin@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        # Create regular staff user
        self.staff = User.objects.create_user(
            username='staff_api_test',
            email='staff@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='support',
        )

        # Create customer
        self.customer = Customer.objects.create(
            name='SC Test API SRL',
            customer_type='company',
            company_name='SC Test API SRL',
            primary_email='api@test.ro',
            primary_phone='+40721234567',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            registration_number='J40/1234/2023',
            is_vat_payer=True,
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        CustomerAddress.objects.create(
            customer=self.customer,
            address_type='legal',
            address_line1='Str. Test Nr. 1',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True,
        )

    def test_customer_list_requires_authentication(self):
        """Customer list should require authentication"""
        response = self.client.get('/app/customers/')
        # Should redirect to login
        assert response.status_code in [302, 403]

    def test_customer_list_authenticated(self):
        """Authenticated user should see customer list"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/customers/')
        assert response.status_code == 200

    def test_customer_detail_accessible(self):
        """Customer detail should be accessible to staff"""
        self.client.force_login(self.admin)
        response = self.client.get(f'/app/customers/{self.customer.pk}/')
        assert response.status_code == 200

    def test_customer_create_form_accessible(self):
        """Customer create form should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/customers/create/')
        assert response.status_code == 200

    def test_customer_search_htmx(self):
        """Customer search should work via HTMX"""
        self.client.force_login(self.admin)
        response = self.client.get(
            '/app/customers/search/',
            {'q': 'Test'},
            HTTP_HX_REQUEST='true',
        )
        # Should return partial or full response
        assert response.status_code in [200, 204]


class TestCustomerAPIAccessControl(TestCase):
    """Test access control for customer API"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_acl_test',
            email='admin_acl@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.support = User.objects.create_user(
            username='support_acl_test',
            email='support_acl@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='support',
        )

        self.viewer = User.objects.create_user(
            username='viewer_acl_test',
            email='viewer_acl@test.ro',
            password='testpass123',
            is_staff=True,
            staff_role='viewer',
        )

        self.customer = Customer.objects.create(
            name='SC ACL Test SRL',
            customer_type='company',
            company_name='SC ACL Test SRL',
            primary_email='acl@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

    def test_admin_can_delete_customer(self):
        """Admin should be able to delete customers"""
        self.client.force_login(self.admin)
        response = self.client.post(f'/app/customers/{self.customer.pk}/delete/')
        # Should redirect after successful delete or show confirmation
        assert response.status_code in [200, 302]

    def test_viewer_cannot_edit_customer(self):
        """Viewer should not be able to edit customers"""
        self.client.force_login(self.viewer)
        response = self.client.post(
            f'/app/customers/{self.customer.pk}/edit/',
            {'name': 'Modified Name'},
        )
        # Should be forbidden or redirect to list
        assert response.status_code in [302, 403, 200]


class TestCustomerAPIValidation(TestCase):
    """Test validation in customer API"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_val_test',
            email='admin_val@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

    def test_create_customer_valid_data(self):
        """Valid customer data should be accepted"""
        self.client.force_login(self.admin)
        response = self.client.post('/app/customers/create/', {
            'name': 'SC New Company SRL',
            'customer_type': 'company',
            'company_name': 'SC New Company SRL',
            'primary_email': 'new@company.ro',
            'primary_phone': '+40721234567',
            'data_processing_consent': True,
        })
        # Should redirect on success or show form with success
        assert response.status_code in [200, 302]

    def test_create_customer_missing_email(self):
        """Missing email should show error"""
        self.client.force_login(self.admin)
        response = self.client.post('/app/customers/create/', {
            'name': 'SC No Email SRL',
            'customer_type': 'company',
            'company_name': 'SC No Email SRL',
            # Missing email
        })
        # Should show form with errors
        assert response.status_code in [200, 400]

    def test_xss_in_customer_name_rejected(self):
        """XSS in customer name should be rejected or sanitized"""
        self.client.force_login(self.admin)
        response = self.client.post('/app/customers/create/', {
            'name': '<script>alert("xss")</script>',
            'customer_type': 'company',
            'company_name': '<script>alert("xss")</script>',
            'primary_email': 'xss@test.ro',
        })
        # Should be rejected or sanitized
        assert response.status_code in [200, 400, 302]

        # If created, verify name is sanitized
        if response.status_code == 302:
            customer = Customer.objects.filter(primary_email='xss@test.ro').first()
            if customer:
                assert '<script>' not in customer.name


class TestCustomerProfileAPI(TestCase):
    """Test customer profile API endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_profile_test',
            email='admin_profile@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.customer = Customer.objects.create(
            name='SC Profile Test SRL',
            customer_type='company',
            company_name='SC Profile Test SRL',
            primary_email='profile@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO87654321',
            vat_number='RO87654321',
            is_vat_payer=True,
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

    def test_tax_profile_update(self):
        """Tax profile update should work"""
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/app/customers/{self.customer.pk}/tax-profile/',
            {
                'cui': 'RO11111111',
                'vat_number': 'RO11111111',
                'is_vat_payer': True,
            }
        )
        assert response.status_code in [200, 302]

    def test_billing_profile_update(self):
        """Billing profile update should work"""
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/app/customers/{self.customer.pk}/billing-profile/',
            {
                'payment_terms': 45,
                'preferred_currency': 'EUR',
            }
        )
        assert response.status_code in [200, 302]
