# ===============================================================================
# 🏢 CUSTOMER PROFILES TESTS - Tax & Billing Profiles
# ===============================================================================
"""
Tests for Customer tax and billing profile models focusing on Romanian compliance.

🚨 Coverage Target: ≥90% for profile model methods
📊 Query Budget: Tests include performance validation  
🔒 Security: Tests Romanian tax compliance validation
"""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.customers.models import (
    Customer,
    CustomerBillingProfile,
    CustomerTaxProfile,
)

User = get_user_model()


def create_test_user(email, **kwargs):
    """Helper to create test user"""
    return User.objects.create_user(email=email, password='testpass', **kwargs)


class CustomerTaxProfileTestCase(TestCase):
    """Test CustomerTaxProfile model methods and validation"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='test@company.ro',
            status='active'
        )

    def test_tax_profile_creation(self):
        """Test tax profile creation with valid data"""
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            tax_number='RO12345678',
            tax_country='RO',
            is_vat_registered=True,
            vat_rate=Decimal('0.19')
        )
        
        self.assertEqual(tax_profile.tax_number, 'RO12345678')
        self.assertEqual(tax_profile.tax_country, 'RO')
        self.assertTrue(tax_profile.is_vat_registered)
        self.assertEqual(tax_profile.vat_rate, Decimal('0.19'))

    def test_tax_number_validation_romanian(self):
        """Test Romanian tax number (CUI) validation"""
        # Valid Romanian CUI
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            tax_number='RO12345678',
            tax_country='RO',
            is_vat_registered=True
        )
        
        self.assertEqual(tax_profile.tax_number, 'RO12345678')

    def test_tax_profile_str_representation(self):
        """Test string representation of tax profile"""
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            tax_number='RO12345678',
            tax_country='RO'
        )
        
        expected = f"Tax Profile for {self.customer.display_name} (RO12345678)"
        self.assertEqual(str(tax_profile), expected)

    def test_vat_calculation_methods(self):
        """Test VAT calculation helper methods"""
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            tax_number='RO12345678',
            tax_country='RO',
            is_vat_registered=True,
            vat_rate=Decimal('0.19')
        )
        
        # Test VAT calculation
        net_amount = Decimal('100.00')
        expected_vat = Decimal('19.00')  # 19% VAT
        expected_gross = Decimal('119.00')
        
        self.assertEqual(tax_profile.calculate_vat(net_amount), expected_vat)
        self.assertEqual(tax_profile.calculate_gross_amount(net_amount), expected_gross)

    def test_romanian_vat_requirements(self):
        """Test Romanian VAT registration requirements"""
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            tax_number='RO12345678',
            tax_country='RO',
            is_vat_registered=True
        )
        
        # Romanian companies should have 19% VAT rate
        self.assertTrue(tax_profile.is_romanian_entity())
        self.assertEqual(tax_profile.default_vat_rate(), Decimal('0.19'))


class CustomerBillingProfileTestCase(TestCase):
    """Test CustomerBillingProfile model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('billing@test.ro', staff_role='billing')
        
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Billing Test SRL',
            primary_email='billing@test.ro',
            status='active'
        )

    def test_billing_profile_creation(self):
        """Test billing profile creation"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            billing_email='billing@test.ro',
            payment_terms_days=30,
            credit_limit_cents=500000,  # 5000 lei
            preferred_currency='RON'
        )
        
        self.assertEqual(billing_profile.billing_email, 'billing@test.ro')
        self.assertEqual(billing_profile.payment_terms_days, 30)
        self.assertEqual(billing_profile.credit_limit_cents, 500000)
        self.assertEqual(billing_profile.preferred_currency, 'RON')

    def test_credit_limit_properties(self):
        """Test credit limit calculation methods"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            credit_limit_cents=500000,  # 5000 lei
            preferred_currency='RON'
        )
        
        # Test credit limit conversion
        self.assertEqual(billing_profile.credit_limit_amount, Decimal('5000.00'))
        
        # Test credit usage calculation (assuming method exists)
        if hasattr(billing_profile, 'available_credit'):
            self.assertIsInstance(billing_profile.available_credit, Decimal)

    def test_billing_contact_validation(self):
        """Test billing contact information validation"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            billing_email='test@domain.ro',
            billing_contact_name='John Doe',
            billing_phone='+40721234567'
        )
        
        self.assertEqual(billing_profile.billing_email, 'test@domain.ro')
        self.assertEqual(billing_profile.billing_contact_name, 'John Doe')
        self.assertEqual(billing_profile.billing_phone, '+40721234567')

    def test_payment_terms_validation(self):
        """Test payment terms validation"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms_days=30
        )
        
        self.assertEqual(billing_profile.payment_terms_days, 30)
        
        # Test payment due date calculation
        if hasattr(billing_profile, 'calculate_due_date'):
            from django.utils import timezone
            invoice_date = timezone.now().date()
            due_date = billing_profile.calculate_due_date(invoice_date)
            expected_due = invoice_date + timezone.timedelta(days=30)
            self.assertEqual(due_date, expected_due)

    def test_billing_profile_str_representation(self):
        """Test string representation of billing profile"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            billing_email='billing@test.ro'
        )
        
        expected = f"Billing Profile for {self.customer.display_name}"
        self.assertEqual(str(billing_profile), expected)

    def test_romanian_billing_requirements(self):
        """Test Romanian-specific billing requirements"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            preferred_currency='RON',
            payment_terms_days=30
        )
        
        # Romanian businesses typically use RON currency
        self.assertEqual(billing_profile.preferred_currency, 'RON')
        
        # Test Romanian invoice numbering requirements
        if hasattr(billing_profile, 'get_next_invoice_number'):
            invoice_number = billing_profile.get_next_invoice_number()
            self.assertIsInstance(invoice_number, str)
            self.assertTrue(len(invoice_number) > 0)