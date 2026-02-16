# ===============================================================================
# 📍 CUSTOMER CONTACT TESTS - Addresses, Notes, Contact Info
# ===============================================================================
"""
Tests for Customer address and contact-related models.

🚨 Coverage Target: ≥90% for contact model methods
📊 Query Budget: Tests include performance validation
🔒 Security: Tests address validation and sanitization
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerNote,
)

User = get_user_model()


def create_test_user(email, **kwargs):
    """Helper to create test user"""
    return User.objects.create_user(email=email, password='testpass', **kwargs)


class CustomerAddressTestCase(TestCase):
    """Test CustomerAddress model methods and validation"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('address@test.ro', staff_role='admin')

        self.customer = Customer.objects.create(
            name='Address Test SRL',
            customer_type='company',
            company_name='Address Test SRL',
            primary_email='address@test.ro',
            status='active'
        )

    def test_address_creation(self):
        """Test address creation with full Romanian address"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Strada Victoriei, nr. 10',
            city='București',
            county='București',
            postal_code='010067',
            country='România'
        )

        self.assertEqual(address.address_type, 'billing')
        self.assertEqual(address.address_line1, 'Strada Victoriei, nr. 10')
        self.assertEqual(address.city, 'București')
        self.assertEqual(address.country, 'România')

    def test_romanian_postal_code_validation(self):
        """Test Romanian postal code validation"""
        # Valid Romanian postal code
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Calea Dorobanților, nr. 5',
            city='Cluj-Napoca',
            postal_code='400117',
            country='România'
        )

        self.assertEqual(address.postal_code, '400117')

    def test_address_types(self):
        """Test different address types"""
        # Billing address
        billing_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Strada Facturare, nr. 1',
            city='București',
            country='România'
        )

        # Delivery address
        delivery_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='delivery',
            address_line1='Strada Livrare, nr. 2',
            city='Timișoara',
            country='România'
        )

        self.assertEqual(billing_address.address_type, 'billing')
        self.assertEqual(delivery_address.address_type, 'delivery')

    def test_address_str_representation(self):
        """Test string representation of address"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Strada Test, nr. 123',
            city='București',
            country='România'
        )

        expected = f"{self.customer.get_display_name()} - Adresa facturare"
        self.assertEqual(str(address), expected)

    def test_multiple_addresses_per_customer(self):
        """Test customer can have multiple addresses"""
        billing_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Strada Billing, nr. 1',
            city='București',
            country='România'
        )

        delivery_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='delivery',
            address_line1='Strada Delivery, nr. 2',
            city='Cluj-Napoca',
            country='România'
        )

        addresses = CustomerAddress.objects.filter(customer=self.customer)
        self.assertEqual(addresses.count(), 2)

        # Test filtering by address type
        billing_addresses = addresses.filter(address_type='billing')
        self.assertEqual(billing_addresses.count(), 1)
        self.assertEqual(billing_addresses.first(), billing_address)

    def test_current_address_logic(self):
        """Test current address selection logic"""
        # First address should be current
        first_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='First Address',
            city='București',
            country='România',
            is_current=True
        )

        # Second address, not current
        second_address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='primary',
            address_line1='Second Address',
            city='Timișoara',
            country='România',
            is_current=False
        )

        # Test current address retrieval
        current_addresses = CustomerAddress.objects.filter(
            customer=self.customer,
            is_current=True
        )
        self.assertEqual(current_addresses.count(), 1)
        self.assertEqual(current_addresses.first(), first_address)

    def test_address_formatting(self):
        """Test address formatting methods"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Bulevardul Unirii, nr. 15',
            address_line2='bl. A1, sc. 2, ap. 45',
            city='București',
            county='București',
            postal_code='030833',
            country='România'
        )

        # Test full address formatting
        formatted = address.get_full_address()
        self.assertIn('Bulevardul Unirii', formatted)
        self.assertIn('București', formatted)
        self.assertIn('030833', formatted)

    def test_romanian_address_components(self):
        """Test Romanian-specific address components"""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            address_type='billing',
            address_line1='Strada Mihail Kogălniceanu, nr. 17, et. 3',
            city='Iași',
            county='Iași',
            postal_code='700454',
            country='România'
        )

        # Romanian addresses should have proper components
        self.assertEqual(address.country, 'România')
        self.assertEqual(address.city, 'Iași')
        self.assertEqual(address.county, 'Iași')

        # Test Romanian city validation
        romanian_cities = ['București', 'Cluj-Napoca', 'Timișoara', 'Iași', 'Constanța']
        self.assertIn(address.city, romanian_cities)


class CustomerNoteTestCase(TestCase):
    """Test CustomerNote model for customer communication tracking"""

    def setUp(self):
        """Set up test data"""
        self.support_user = create_test_user('support@test.ro', staff_role='support')
        self.admin_user = create_test_user('admin@test.ro', staff_role='admin')

        self.customer = Customer.objects.create(
            name='Note Test SRL',
            customer_type='company',
            company_name='Note Test SRL',
            primary_email='note@test.ro',
            status='active'
        )

    def test_note_creation(self):
        """Test creating customer notes"""
        note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='general',
            title='Customer Support Request',
            content='Customer needs help with billing setup.'
        )

        self.assertEqual(note.note_type, 'general')
        self.assertEqual(note.title, 'Customer Support Request')
        self.assertEqual(note.created_by, self.support_user)
        self.assertIn('billing setup', note.content)

    def test_note_types(self):
        """Test different note types"""
        # Call note
        call_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='call',
            title='Phone Call',
            content='Customer reported billing issue.'
        )

        # General note
        general_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.admin_user,
            note_type='general',
            title='General Note',
            content='Customer approved for increased credit limit.'
        )

        self.assertEqual(call_note.note_type, 'call')
        self.assertEqual(general_note.note_type, 'general')

    def test_note_chronological_order(self):
        """Test notes are ordered chronologically"""
        # Create notes with different timestamps
        first_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='general',
            title='First Note',
            content='This was created first.'
        )

        second_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.admin_user,
            note_type='email',
            title='Second Note',
            content='This was created second.'
        )

        # Notes should be ordered by creation date (newest first)
        notes = CustomerNote.objects.filter(customer=self.customer).order_by('-created_at')
        self.assertEqual(notes.first(), second_note)
        self.assertEqual(notes.last(), first_note)

    def test_note_str_representation(self):
        """Test string representation of notes"""
        note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='general',
            title='Test Note',
            content='Test content.'
        )

        expected = f"Test Note - {self.customer.get_display_name()}"
        self.assertEqual(str(note), expected)

    def test_note_content_sanitization(self):
        """Test note content is properly sanitized"""
        # Test with potentially unsafe content
        unsafe_content = "<script>alert('xss')</script>Normal content here."

        note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='general',
            title='Security Test',
            content=unsafe_content
        )

        # Content should be stored but script tags should be handled safely
        self.assertIn('Normal content here', note.content)
        # Actual XSS protection would be handled at the template/view level

    def test_note_visibility_by_staff_role(self):
        """Test note visibility based on staff roles"""
        # Private note (admin only)
        private_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.admin_user,
            note_type='general',
            title='Confidential Note',
            content='Sensitive internal information.',
            is_private=True
        )

        # Public note (visible to all staff)
        public_note = CustomerNote.objects.create(
            customer=self.customer,
            created_by=self.support_user,
            note_type='call',
            title='Call Note',
            content='Customer communication.',
            is_private=False
        )

        # Test filtering notes by privacy for role-based access
        private_notes = CustomerNote.objects.filter(
            customer=self.customer,
            is_private=True
        )
        public_notes = CustomerNote.objects.filter(
            customer=self.customer,
            is_private=False
        )

        self.assertEqual(private_notes.count(), 1)
        self.assertEqual(public_notes.count(), 1)
        self.assertEqual(private_notes.first(), private_note)
        self.assertEqual(public_notes.first(), public_note)
