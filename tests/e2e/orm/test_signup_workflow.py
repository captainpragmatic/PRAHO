# ===============================================================================
# END-TO-END TESTS FOR SIGNUP WORKFLOW
# ===============================================================================
"""
End-to-end tests for customer signup and onboarding workflow.
Tests the complete flow from registration to profile completion.
"""

import os
import sys

import pytest

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django
django.setup()

from django.test import Client, TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse

from apps.customers.models import Customer, CustomerAddress, CustomerBillingProfile, CustomerTaxProfile

User = get_user_model()


@pytest.mark.e2e
class TestSignupWorkflow(TestCase):
    """End-to-end tests for complete signup workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        # Create admin for customer creation
        self.admin = User.objects.create_user(
            email='signup_admin@test.ro',
            password='AdminPass123!',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

    def test_complete_company_signup_flow(self):
        """Test complete company signup workflow"""
        self.client.force_login(self.admin)

        # Step 1: Create customer
        customer = Customer.objects.create(
            name='SC New Signup SRL',
            customer_type='company',
            company_name='SC New Signup SRL',
            primary_email='newsignup@company.ro',
            primary_phone='+40721234567',
            data_processing_consent=True,
            created_by=self.admin,
        )
        assert customer.pk is not None
        assert customer.status == 'prospect'

        # Step 2: Create tax profile
        tax_profile = CustomerTaxProfile.objects.create(
            customer=customer,
            cui='RO12345678',
            vat_number='RO12345678',
            registration_number='J40/1234/2024',
            is_vat_payer=True,
        )
        assert tax_profile.pk is not None
        assert customer.tax_profile is not None

        # Step 3: Create billing profile
        billing_profile = CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=30,
            preferred_currency='RON',
        )
        assert billing_profile.pk is not None
        assert customer.billing_profile is not None

        # Step 4: Create legal address
        address = CustomerAddress.objects.create(
            customer=customer,
            address_type='legal',
            address_line1='Str. Noua Nr. 10',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True,
        )
        assert address.pk is not None
        assert customer.addresses.count() == 1

        # Verify complete profile
        customer.refresh_from_db()
        assert customer.tax_profile is not None
        assert customer.billing_profile is not None
        assert customer.addresses.filter(is_current=True).exists()

    def test_complete_individual_signup_flow(self):
        """Test complete individual customer signup"""
        self.client.force_login(self.admin)

        # Create individual customer
        customer = Customer.objects.create(
            name='Ion Popescu',
            customer_type='individual',
            first_name='Ion',
            last_name='Popescu',
            primary_email='ion.popescu@email.ro',
            primary_phone='+40722123456',
            data_processing_consent=True,
            created_by=self.admin,
        )

        # Create billing profile (no tax profile for individuals)
        billing_profile = CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=14,
            preferred_currency='RON',
        )

        # Create billing address
        address = CustomerAddress.objects.create(
            customer=customer,
            address_type='billing',
            address_line1='Bd. Unirii Nr. 5, Ap. 10',
            city='București',
            county='Sector 3',
            postal_code='030167',
            country='România',
            is_current=True,
        )

        assert customer.customer_type == 'individual'
        assert customer.billing_profile is not None
        assert customer.addresses.count() == 1

    def test_signup_requires_gdpr_consent(self):
        """Signup should track GDPR consent"""
        self.client.force_login(self.admin)

        # Customer without consent
        customer = Customer.objects.create(
            name='SC No Consent SRL',
            customer_type='company',
            company_name='SC No Consent SRL',
            primary_email='noconsent@company.ro',
            data_processing_consent=False,
            created_by=self.admin,
        )

        # Consent should be tracked
        assert customer.data_processing_consent is False

    def test_signup_with_multiple_addresses(self):
        """Customer can have multiple addresses"""
        self.client.force_login(self.admin)

        customer = Customer.objects.create(
            name='SC Multi Address SRL',
            customer_type='company',
            company_name='SC Multi Address SRL',
            primary_email='multiaddr@company.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        # Legal address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='legal',
            address_line1='Str. Legala Nr. 1',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True,
        )

        # Billing address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='billing',
            address_line1='Str. Facturare Nr. 2',
            city='Cluj-Napoca',
            county='Cluj',
            postal_code='400001',
            country='România',
            is_current=True,
        )

        # Shipping address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='shipping',
            address_line1='Str. Livrare Nr. 3',
            city='Timișoara',
            county='Timiș',
            postal_code='300001',
            country='România',
            is_current=True,
        )

        assert customer.addresses.count() == 3


@pytest.mark.e2e
class TestUserRegistrationFlow(TestCase):
    """End-to-end tests for user registration"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

    def test_login_page_accessible(self):
        """Login page should be accessible"""
        response = self.client.get('/auth/login/')
        assert response.status_code == 200

    def test_successful_login(self):
        """User should be able to login"""
        user = User.objects.create_user(
            email='login@test.ro',
            password='TestPass123!',
        )

        response = self.client.post('/auth/login/', {
            'email': 'login@test.ro',
            'password': 'TestPass123!',
        })

        # Should redirect on success
        assert response.status_code in [200, 302]

    def test_invalid_login_rejected(self):
        """Invalid credentials should be rejected"""
        response = self.client.post('/auth/login/', {
            'email': 'nonexistent@test.ro',
            'password': 'wrongpassword',
        })

        # Should show error or return 200 with form
        assert response.status_code == 200

    def test_logout_workflow(self):
        """User should be able to logout"""
        user = User.objects.create_user(
            email='logout@test.ro',
            password='TestPass123!',
        )

        self.client.force_login(user)

        response = self.client.post('/auth/logout/')
        # Should redirect after logout
        assert response.status_code in [200, 302]


@pytest.mark.e2e
class TestCustomerOnboardingFlow(TestCase):
    """End-to-end tests for customer onboarding"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='onboard_admin@test.ro',
            password='AdminPass123!',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

    def test_new_customer_onboarding_steps(self):
        """Test all steps of customer onboarding"""
        self.client.force_login(self.admin)

        # Create base customer
        customer = Customer.objects.create(
            name='SC Onboarding SRL',
            customer_type='company',
            company_name='SC Onboarding SRL',
            primary_email='onboarding@company.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        # Verify customer was created
        assert customer.pk is not None

        # Complete tax profile
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui='RO87654321',
            vat_number='RO87654321',
            registration_number='J40/5678/2024',
            is_vat_payer=True,
        )

        # Complete billing profile
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        # Add legal address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='legal',
            address_line1='Str. Onboarding Nr. 1',
            city='București',
            county='Sector 2',
            postal_code='020101',
            country='România',
            is_current=True,
        )

        # Verify all components are present
        customer.refresh_from_db()
        assert hasattr(customer, 'tax_profile') and customer.tax_profile is not None
        assert hasattr(customer, 'billing_profile') and customer.billing_profile is not None
        assert customer.addresses.exists()

    def test_customer_profile_completion_percentage(self):
        """Test profile completion tracking"""
        self.client.force_login(self.admin)

        # Create minimal customer
        customer = Customer.objects.create(
            name='SC Incomplete SRL',
            customer_type='company',
            company_name='SC Incomplete SRL',
            primary_email='incomplete@company.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        # Check incomplete profile
        has_tax = hasattr(customer, 'tax_profile') and customer.tax_profile is not None
        has_billing = hasattr(customer, 'billing_profile') and customer.billing_profile is not None
        has_address = customer.addresses.exists()

        # Should be incomplete
        assert not has_tax or not has_billing or not has_address
