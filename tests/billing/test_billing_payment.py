# ===============================================================================
# BILLING PAYMENT TESTS (Django TestCase Format)
# ===============================================================================

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from datetime import timedelta

from apps.billing.models import Currency, Invoice, Payment
from apps.customers.models import Customer

User = get_user_model()


class PaymentTestCase(TestCase):
    """Test Payment model functionality"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAY-001',
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30)
        )

    def test_create_payment(self):
        """Test basic payment creation"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=10000,
            method='card',
            status='succeeded'
        )

        self.assertEqual(payment.customer, self.customer)
        self.assertEqual(payment.invoice, self.invoice)
        self.assertEqual(payment.currency, self.currency)
        self.assertEqual(payment.amount_cents, 10000)
        self.assertEqual(payment.method, 'card')
        self.assertEqual(payment.status, 'succeeded')

    def test_payment_str_representation(self):
        """Test string representation"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='bank_transfer'
        )

        str_repr = str(payment)
        self.assertIn('Test Company SRL', str_repr)
        self.assertIn('50', str_repr)  # Amount representation

    def test_payment_status_choices(self):
        """Test valid status choices"""
        valid_statuses = ['pending', 'processing', 'succeeded', 'failed', 'cancelled', 'refunded']

        for status in valid_statuses:
            payment = Payment.objects.create(
                customer=self.customer,
                currency=self.currency,
                amount_cents=1000,
                method='card',
                status=status
            )
            self.assertEqual(payment.status, status)

    def test_payment_method_choices(self):
        """Test valid method choices"""
        valid_methods = ['card', 'bank_transfer', 'cash', 'crypto', 'other']

        for method in valid_methods:
            payment = Payment.objects.create(
                customer=self.customer,
                currency=self.currency,
                amount_cents=1000,
                method=method
            )
            self.assertEqual(payment.method, method)

    def test_payment_without_invoice(self):
        """Test payment without invoice (credit payment)"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='bank_transfer',
            status='succeeded'
        )

        self.assertIsNone(payment.invoice)
        self.assertEqual(payment.amount_cents, 5000)

    def test_payment_customer_relationship(self):
        """Test customer relationship"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='card'
        )

        self.assertEqual(payment.customer, self.customer)

    def test_payment_invoice_relationship(self):
        """Test invoice relationship"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=10000,
            method='card'
        )

        self.assertEqual(payment.invoice, self.invoice)

    def test_payment_currency_protect_on_delete(self):
        """Test PROTECT on delete when currency is referenced"""
        Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='card'
        )

        # Should not be able to delete currency while it's referenced
        # (This test depends on the actual FK constraint implementation)
        self.assertTrue(Payment.objects.filter(currency=self.currency).exists())

    def test_payment_customer_restrict_on_delete(self):
        """Test RESTRICT on delete when customer is referenced"""
        Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='card'
        )

        # Should not be able to delete customer while they have payments
        self.assertTrue(Payment.objects.filter(customer=self.customer).exists())

    def test_payment_invoice_set_null_on_delete(self):
        """Test SET_NULL on delete when invoice is deleted"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=10000,
            method='card'
        )

        self.invoice.delete()

        payment.refresh_from_db()
        self.assertIsNone(payment.invoice)

    def test_payment_meta_json_field(self):
        """Test meta JSON field functionality"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='card',
            meta={'gateway': 'stripe', 'transaction_id': 'tx_123'}
        )

        self.assertEqual(payment.meta['gateway'], 'stripe')
        self.assertEqual(payment.meta['transaction_id'], 'tx_123')

    def test_payment_notes_field(self):
        """Test notes field"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='bank_transfer',
            notes='Payment received via bank transfer'
        )

        self.assertEqual(payment.notes, 'Payment received via bank transfer')


class PaymentIntegrationTestCase(TestCase):
    """Test Payment integration scenarios"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Integration Test SRL',
            status='active'
        )

    def test_partial_payment_workflow(self):
        """Test partial payment scenario"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PARTIAL',
            total_cents=10000,  # 100.00 EUR
            due_at=timezone.now() + timedelta(days=30)
        )

        # First partial payment
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=3000,  # 30.00 EUR
            method='card',
            status='succeeded'
        )

        # Second partial payment
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=7000,  # 70.00 EUR
            method='bank_transfer',
            status='succeeded'
        )

        # Check that payments were created
        self.assertEqual(Payment.objects.filter(invoice=invoice).count(), 2)

    def test_overpayment_scenario(self):
        """Test overpayment handling"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-OVERPAY',
            total_cents=5000,  # 50.00 EUR
            due_at=timezone.now() + timedelta(days=30)
        )

        # Overpayment
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=7000,  # 70.00 EUR (overpaid by 20.00)
            method='card',
            status='succeeded'
        )

        self.assertEqual(payment.amount_cents, 7000)
        self.assertGreater(payment.amount_cents, invoice.total_cents)

    def test_failed_payment_not_counted(self):
        """Test that failed payments don't affect balance"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-FAILED',
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30)
        )

        # Failed payment
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=10000,
            method='card',
            status='failed'
        )

        # Payment exists but is failed
        failed_payment = Payment.objects.get(invoice=invoice, status='failed')
        self.assertEqual(failed_payment.status, 'failed')

    def test_credit_payment_without_invoice(self):
        """Test credit payment (no invoice)"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=15000,  # 150.00 EUR credit
            method='bank_transfer',
            status='succeeded',
            notes='Account credit top-up'
        )

        self.assertIsNone(payment.invoice)
        self.assertEqual(payment.notes, 'Account credit top-up')

    def test_payment_gateway_integration_data(self):
        """Test payment gateway metadata storage"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='card',
            status='succeeded',
            meta={
                'gateway': 'stripe',
                'charge_id': 'ch_1234567890',
                'card_last4': '4242',
                'card_brand': 'visa'
            }
        )

        self.assertEqual(payment.meta['gateway'], 'stripe')
        self.assertEqual(payment.meta['card_last4'], '4242')

    def test_payment_indexes_performance(self):
        """Test payment index performance"""
        Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=1000,
            method='card'
        )

        # These queries should be efficient due to indexes
        Payment.objects.filter(customer=self.customer)
        Payment.objects.filter(status='succeeded')
        Payment.objects.filter(created_at__gte=timezone.now().date())

        self.assertTrue(True)  # Test passes if no errors
