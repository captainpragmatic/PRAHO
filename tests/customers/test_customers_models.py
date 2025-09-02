# ===============================================================================
# 🏢 CUSTOMER MODELS TESTS - Core Customer Model
# ===============================================================================
"""
Tests for core Customer model focusing on business logic and validation.
This covers the main Customer model - profiles, addresses, etc. are in separate files.

🚨 Coverage Target: ≥90% for customer model methods
📊 Query Budget: Tests include performance validation
🔒 Security: Tests Romanian compliance validation
"""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerPaymentMethod,
    CustomerTaxProfile,
)

User = get_user_model()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def create_test_user(email: str, **kwargs) -> User:
    """Helper to create test users"""
    defaults = {
        'first_name': 'Test',
        'last_name': 'User',
        'password': 'testpass123'
    }
    defaults.update(kwargs)
    return User.objects.create_user(email=email, **defaults)


def create_test_customer(name: str, admin_user: User, **kwargs) -> Customer:
    """Helper to create test customers"""
    defaults = {
        'customer_type': 'company',
        'company_name': name,
        'primary_email': f'contact@{name.lower().replace(" ", "")}.ro',
        'primary_phone': '+40721123456',
        'data_processing_consent': True,
        'created_by': admin_user
    }
    defaults.update(kwargs)
    return Customer.objects.create(**defaults)


# ===============================================================================
# CUSTOMER MODEL TESTS
# ===============================================================================

class CustomerModelTestCase(TestCase):
    """Test Customer model methods and properties"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Test Company SRL', self.admin_user)

    def test_customer_string_representation(self):
        """Test Customer __str__ method"""
        self.assertEqual(str(self.customer), 'Test Company SRL')

    def test_customer_display_name_company(self):
        """Test get_display_name for company type"""
        self.customer.customer_type = 'company'
        self.customer.company_name = 'Tech Solutions SRL'
        self.customer.name = 'John Doe'
        
        self.assertEqual(self.customer.get_display_name(), 'Tech Solutions SRL')

    def test_customer_display_name_individual(self):
        """Test get_display_name for individual type"""
        self.customer.customer_type = 'individual'
        self.customer.company_name = ''
        self.customer.name = 'Maria Popescu'
        
        self.assertEqual(self.customer.get_display_name(), 'Maria Popescu')

    def test_soft_delete_properties(self):
        """Test soft delete functionality"""
        # Initially not deleted
        self.assertFalse(self.customer.is_deleted)
        
        # Soft delete
        self.customer.soft_delete(user=self.admin_user)
        
        # Should be marked as deleted
        self.assertTrue(self.customer.is_deleted)
        self.assertIsNotNone(self.customer.deleted_at)
        self.assertEqual(self.customer.deleted_by, self.admin_user)

    def test_customer_restore(self):
        """Test customer restore functionality"""
        # Soft delete then restore
        self.customer.soft_delete(user=self.admin_user)
        self.customer.restore()
        
        # Should be restored
        self.assertFalse(self.customer.is_deleted)
        self.assertIsNone(self.customer.deleted_at)
        self.assertIsNone(self.customer.deleted_by)


# ===============================================================================
# CUSTOMER TAX PROFILE TESTS
# ===============================================================================

class CustomerTaxProfileTestCase(TestCase):
    """Test CustomerTaxProfile model and Romanian compliance"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Tax Test Company', self.admin_user)

    def test_customer_tax_profile_creation(self):
        """Test creating tax profile with Romanian data"""
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            registration_number='J40/1234/2023',
            is_vat_payer=True,
            vat_number='RO12345678',
            vat_rate=Decimal('19.00')
        )
        
        self.assertEqual(tax_profile.cui, 'RO12345678')
        self.assertTrue(tax_profile.is_vat_payer)
        self.assertEqual(tax_profile.vat_rate, Decimal('19.00'))

    def test_customer_get_tax_profile(self):
        """Test customer.get_tax_profile() method"""
        # No tax profile initially
        self.assertIsNone(self.customer.get_tax_profile())
        
        # Create tax profile
        tax_profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO87654321',
            is_vat_payer=True
        )
        
        # Should return the tax profile
        retrieved_profile = self.customer.get_tax_profile()
        self.assertEqual(retrieved_profile, tax_profile)
        self.assertEqual(retrieved_profile.cui, 'RO87654321')


# ===============================================================================
# CUSTOMER BILLING PROFILE TESTS
# ===============================================================================

class CustomerBillingProfileTestCase(TestCase):
    """Test CustomerBillingProfile model and financial calculations"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Billing Test Company', self.admin_user)

    def test_customer_billing_profile_creation(self):
        """Test creating billing profile"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            credit_limit=Decimal('10000.00'),
            preferred_currency='RON',
            invoice_delivery_method='email'
        )
        
        self.assertEqual(billing_profile.payment_terms, 30)
        self.assertEqual(billing_profile.credit_limit, Decimal('10000.00'))
        self.assertEqual(billing_profile.preferred_currency, 'RON')

    def test_customer_get_billing_profile(self):
        """Test customer.get_billing_profile() method"""
        # No billing profile initially
        self.assertIsNone(self.customer.get_billing_profile())
        
        # Create billing profile
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=14,
            credit_limit=Decimal('5000.00')
        )
        
        # Should return the billing profile
        retrieved_profile = self.customer.get_billing_profile()
        self.assertEqual(retrieved_profile, billing_profile)
        self.assertEqual(retrieved_profile.payment_terms, 14)

    def test_account_balance_calculation(self):
        """Test get_account_balance() method"""
        billing_profile = CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            credit_limit=Decimal('10000.00')
        )
        
        # Should return 0.00 when no invoices
        balance = billing_profile.get_account_balance()
        self.assertEqual(balance, Decimal('0.00'))


# ===============================================================================
# CUSTOMER ADDRESS TESTS
# ===============================================================================

class CustomerAddressTestCase(TestCase):
    """Test CustomerAddress model and Romanian address handling"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Address Test Company', self.admin_user)

    def test_customer_address_creation(self):
        """Test creating Romanian address"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='primary',
            address_line1='Strada Exemplu 123',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True
        )
        
        self.assertEqual(address.city, 'București')
        self.assertEqual(address.county, 'Sector 1')
        self.assertTrue(address.is_current)

    def test_address_string_representation(self):
        """Test CustomerAddress __str__ method"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Test Street 1',
            city='Cluj-Napoca',
            county='Cluj',
            postal_code='400000',
            is_current=True
        )
        
        expected = f"{self.customer.name} - Adresa facturare"
        self.assertEqual(str(address), expected)

    def test_get_full_address(self):
        """Test get_full_address() method"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='primary',
            address_line1='Strada Principală 100',
            address_line2='Bloc A, Ap. 15',
            city='Timișoara',
            county='Timiș',
            postal_code='300001',
            country='România',
            is_current=True
        )
        
        full_address = address.get_full_address()
        expected = "Strada Principală 100, Bloc A, Ap. 15, Timișoara, Timiș, 300001, România"
        self.assertEqual(full_address, expected)

    def test_customer_get_primary_address(self):
        """Test customer.get_primary_address() method"""
        # No address initially
        self.assertIsNone(self.customer.get_primary_address())
        
        # Create primary address
        primary_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='primary',
            address_line1='Primary Street 1',
            city='Iași',
            county='Iași',
            postal_code='700000',
            is_current=True
        )
        
        # Should return the primary address
        retrieved_address = self.customer.get_primary_address()
        self.assertEqual(retrieved_address, primary_address)

    def test_customer_get_billing_address(self):
        """Test customer.get_billing_address() method"""
        # Create primary address
        primary_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='primary',
            address_line1='Primary Street 1',
            city='Brașov',
            county='Brașov',
            postal_code='500000',
            is_current=True
        )
        
        # Should fall back to primary when no billing address
        billing_address = self.customer.get_billing_address()
        self.assertEqual(billing_address, primary_address)
        
        # Create billing address
        specific_billing = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Billing Street 1',
            city='Constanța',
            county='Constanța',
            postal_code='900000',
            is_current=True
        )
        
        # Should return specific billing address
        billing_address = self.customer.get_billing_address()
        self.assertEqual(billing_address, specific_billing)


# ===============================================================================
# CUSTOMER PAYMENT METHOD TESTS
# ===============================================================================

class CustomerPaymentMethodTestCase(TestCase):
    """Test CustomerPaymentMethod model"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Payment Test Company', self.admin_user)

    def test_payment_method_creation(self):
        """Test creating payment method"""
        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Visa ending in 1234',
            last_four='1234',
            is_default=True,
            is_active=True
        )
        
        self.assertEqual(payment_method.method_type, 'stripe_card')
        self.assertEqual(payment_method.last_four, '1234')
        self.assertTrue(payment_method.is_default)

    def test_payment_method_string_representation(self):
        """Test CustomerPaymentMethod __str__ method"""
        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='Transfer bancar ING',
            is_active=True
        )
        
        expected = f"{self.customer.name} - Transfer bancar ING"
        self.assertEqual(str(payment_method), expected)


# ===============================================================================
# CUSTOMER NOTES TESTS
# ===============================================================================

class CustomerNoteTestCase(TestCase):
    """Test CustomerNote model"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')
        self.customer = create_test_customer('Notes Test Company', self.admin_user)

    def test_customer_note_creation(self):
        """Test creating customer note"""
        note = CustomerNote.objects.create(
            customer=self.customer,
            title='Important Client Information',
            content='Client prefers email communication in Romanian.',
            note_type='general',
            is_important=True,
            created_by=self.admin_user
        )
        
        self.assertEqual(note.title, 'Important Client Information')
        self.assertEqual(note.note_type, 'general')
        self.assertTrue(note.is_important)
        self.assertEqual(note.created_by, self.admin_user)

    def test_customer_note_string_representation(self):
        """Test CustomerNote __str__ method"""
        note = CustomerNote.objects.create(
            customer=self.customer,
            title='Client Meeting Notes',
            content='Discussed hosting requirements.',
            note_type='meeting',
            created_by=self.admin_user
        )
        
        expected = f"Client Meeting Notes - {self.customer.name}"
        self.assertEqual(str(note), expected)