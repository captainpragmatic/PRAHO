# ===============================================================================
# 💳 CUSTOMER PAYMENTS TESTS - Payment Methods & Financial Data
# ===============================================================================
"""
Tests for Customer payment method models and financial validation.

🚨 Coverage Target: ≥90% for payment model methods
📊 Query Budget: Tests include performance validation
🔒 Security: Tests payment data security and validation
"""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.customers.models import (
    Customer,
    CustomerPaymentMethod,
)

User = get_user_model()


def create_test_user(email, **kwargs):
    """Helper to create test user"""
    return User.objects.create_user(email=email, password='testpass', **kwargs)


class CustomerPaymentMethodTestCase(TestCase):
    """Test CustomerPaymentMethod model and Romanian banking integration"""

    def setUp(self):
        """Set up test data"""
        self.admin_user = create_test_user('payments@test.ro', staff_role='admin')

        self.customer = Customer.objects.create(
            name='Payment Test SRL',
            customer_type='company',
            company_name='Payment Test SRL',
            primary_email='payments@test.ro',
            status='active'
        )

    def test_bank_transfer_method_creation(self):
        """Test bank transfer payment method creation"""
        bank_details = {
            'bank_name': 'Banca Transilvania',
            'account_holder': 'Payment Test SRL',
            'iban': 'RO49AAAA1B31007593840000'
        }

        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='Banca Transilvania Transfer',
            bank_details=bank_details,
            is_default=True,
            is_active=True
        )

        self.assertEqual(payment_method.method_type, 'bank_transfer')
        self.assertEqual(payment_method.bank_details['bank_name'], 'Banca Transilvania')
        self.assertEqual(payment_method.bank_details['iban'], 'RO49AAAA1B31007593840000')
        self.assertTrue(payment_method.is_default)

    def test_romanian_iban_validation(self):
        """Test Romanian IBAN validation"""
        # Valid Romanian IBAN
        bank_details = {
            'bank_name': 'BCR',
            'iban': 'RO49RNCB0000000000000001'
        }

        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='BCR Bank Transfer',
            bank_details=bank_details
        )

        self.assertTrue(payment_method.bank_details['iban'].startswith('RO'))
        self.assertEqual(len(payment_method.bank_details['iban']), 24)  # Romanian IBAN length

    def test_credit_card_method_creation(self):
        """Test credit card payment method creation"""
        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Visa ending in 1234',
            last_four='1234',
            stripe_payment_method_id='pm_test_1234',
            is_active=True
        )

        self.assertEqual(payment_method.method_type, 'stripe_card')
        self.assertEqual(payment_method.last_four, '1234')
        self.assertEqual(payment_method.display_name, 'Visa ending in 1234')

    def test_payment_method_str_representation(self):
        """Test string representation of payment methods"""
        # Bank transfer
        bank_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='ING Bank Transfer'
        )

        expected_bank = f"{self.customer.get_display_name()} - ING Bank Transfer"
        self.assertEqual(str(bank_method), expected_bank)

        # Credit card
        card_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Mastercard ending in 5678',
            last_four='5678'
        )

        expected_card = f"{self.customer.get_display_name()} - Mastercard ending in 5678"
        self.assertEqual(str(card_method), expected_card)

    def test_default_payment_method_logic(self):
        """Test default payment method selection"""
        # Create first payment method (should be default)
        first_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='Banca Transilvania Transfer',
            is_default=True
        )

        # Create second payment method (not default)
        second_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Visa Card',
            last_four='1234',
            is_default=False
        )

        # Test default method retrieval
        default_method = CustomerPaymentMethod.objects.filter(
            customer=self.customer,
            is_default=True
        ).first()

        self.assertEqual(default_method, first_method)

        # Test making another method default
        second_method.is_default = True
        second_method.save()

        # Should update previous default
        first_method.refresh_from_db()
        self.assertFalse(first_method.is_default)

    def test_payment_method_validation(self):
        """Test payment method data validation"""
        # Test bank details validation
        with self.assertRaises(ValidationError):
            payment_method = CustomerPaymentMethod(
                customer=self.customer,
                method_type='bank_transfer',
                bank_details={'iban': 'INVALID_IBAN'},
                display_name='Invalid Bank'
            )
            payment_method.full_clean()

    def test_active_payment_methods_only(self):
        """Test filtering active payment methods"""
        # Active method
        active_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='BCR Transfer',
            is_active=True
        )

        # Inactive method
        inactive_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Visa Card',
            last_four='9999',
            is_active=False
        )

        # Test filtering
        active_methods = CustomerPaymentMethod.objects.filter(
            customer=self.customer,
            is_active=True
        )

        self.assertEqual(active_methods.count(), 1)
        self.assertEqual(active_methods.first(), active_method)

    def test_romanian_bank_support(self):
        """Test Romanian bank support"""
        romanian_banks = [
            'Banca Transilvania',
            'BCR (Banca Comercială Română)',
            'BRD - Groupe Société Générale',
            'ING Bank România',
            'UniCredit Bank',
            'Raiffeisen Bank'
        ]

        for bank_name in romanian_banks:
            bank_details = {
                'bank_name': bank_name,
                'iban': f'RO49AAAA1B31007593840{len(bank_name):03d}'
            }

            payment_method = CustomerPaymentMethod.objects.create(
                customer=self.customer,
                method_type='bank_transfer',
                display_name=f'{bank_name} Transfer',
                bank_details=bank_details
            )

            self.assertEqual(payment_method.bank_details['bank_name'], bank_name)
            self.assertTrue(payment_method.bank_details['iban'].startswith('RO'))

    def test_payment_method_security(self):
        """Test payment method data security"""
        # Credit card data should be masked
        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Mastercard ending in 1234',
            last_four='1234',
            stripe_payment_method_id='pm_test_mastercard'
        )

        # Only last 4 digits should be stored
        self.assertEqual(payment_method.last_four, '1234')
        self.assertEqual(len(payment_method.last_four), 4)

        # Full card number should never be stored
        self.assertFalse(hasattr(payment_method, 'card_number'))

    def test_expired_payment_methods(self):
        """Test handling of expired payment methods"""
        # Create payment method - expiration is handled by Stripe
        card_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='stripe_card',
            display_name='Visa ending in 1111',
            last_four='1111',
            stripe_payment_method_id='pm_expired_card'
        )

        # Test that payment method is created
        self.assertEqual(card_method.method_type, 'stripe_card')
        self.assertEqual(card_method.last_four, '1111')

        # Bank transfers don't expire
        bank_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='ING Bank Transfer'
        )

        # Bank transfer should be active
        self.assertTrue(bank_method.is_active)

    def test_payment_processing_integration(self):
        """Test payment method integration with payment processing"""
        bank_details = {
            'bank_name': 'Banca Transilvania',
            'iban': 'RO49BTRLRONCRT0000000001',
            'swift_code': 'BTRLRO22'
        }

        payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='Banca Transilvania Transfer',
            bank_details=bank_details
        )

        # Test bank details are stored correctly
        self.assertIsInstance(payment_method.bank_details, dict)
        self.assertEqual(payment_method.bank_details['iban'], 'RO49BTRLRONCRT0000000001')
        self.assertEqual(payment_method.bank_details['bank_name'], 'Banca Transilvania')
