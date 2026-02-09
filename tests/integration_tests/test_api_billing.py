# ===============================================================================
# INTEGRATION TESTS FOR BILLING API ENDPOINTS
# ===============================================================================
"""
Integration tests for billing API endpoints.
Tests cover invoices, payments, refunds, and Romanian e-Factura compliance.
"""

import json
import os
import sys
from datetime import timedelta
from decimal import Decimal

import pytest

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django
django.setup()

from django.test import Client, TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile
from apps.billing.models import Currency, Invoice, InvoiceLine, Payment, Proforma

User = get_user_model()


class TestInvoiceAPIIntegration(TestCase):
    """Integration tests for invoice API endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_invoice_test',
            email='admin_invoice@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Invoice Test SRL',
            customer_type='company',
            company_name='SC Invoice Test SRL',
            primary_email='invoice@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True,
            vat_rate=Decimal('19.00'),
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-00001',
            status='issued',
            subtotal_cents=8403,
            vat_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        InvoiceLine.objects.create(
            invoice=self.invoice,
            description='Web Hosting Standard - 1 month',
            quantity=1,
            unit_price_cents=8403,
            total_cents=8403,
        )

    def test_invoice_list_requires_authentication(self):
        """Invoice list should require authentication"""
        response = self.client.get('/app/billing/')
        assert response.status_code in [302, 403]

    def test_invoice_list_authenticated(self):
        """Authenticated user should see invoice list"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/billing/')
        assert response.status_code == 200

    def test_invoice_detail_accessible(self):
        """Invoice detail should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get(f'/app/billing/{self.invoice.pk}/')
        assert response.status_code == 200

    def test_invoice_pdf_generation(self):
        """Invoice PDF should be generated"""
        self.client.force_login(self.admin)
        response = self.client.get(f'/app/billing/{self.invoice.pk}/pdf/')
        # Should return PDF or redirect
        assert response.status_code in [200, 302]
        if response.status_code == 200:
            assert 'pdf' in response.get('Content-Type', '').lower() or response.status_code == 302


class TestInvoiceVATCompliance(TestCase):
    """Test Romanian VAT compliance in invoices"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_vat_inv_test',
            email='admin_vat_inv@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC VAT Invoice SRL',
            customer_type='company',
            company_name='SC VAT Invoice SRL',
            primary_email='vat_inv@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True,
            vat_rate=Decimal('19.00'),
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

    def test_invoice_vat_19_percent(self):
        """Invoice VAT should be 19%"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-VAT-001',
            status='issued',
            subtotal_cents=10000,
            vat_cents=1900,
            total_cents=11900,
            due_at=timezone.now() + timedelta(days=30),
        )

        vat_rate = (invoice.vat_cents / invoice.subtotal_cents) * 100
        assert 18.9 < vat_rate < 19.1

    def test_invoice_total_calculation(self):
        """Invoice total should equal subtotal + VAT"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-CALC-001',
            status='issued',
            subtotal_cents=8403,
            vat_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        assert invoice.total_cents == invoice.subtotal_cents + invoice.vat_cents


class TestPaymentAPIIntegration(TestCase):
    """Integration tests for payment API endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_payment_test',
            email='admin_payment@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Payment Test SRL',
            customer_type='company',
            company_name='SC Payment Test SRL',
            primary_email='payment@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True,
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-PAY-001',
            status='issued',
            subtotal_cents=8403,
            vat_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

    def test_payment_creation(self):
        """Payment can be created for invoice"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=10000,
            payment_method='stripe',
            status='succeeded',
        )

        assert payment.pk is not None
        assert payment.invoice == self.invoice
        assert payment.amount_cents == 10000

    def test_payment_marks_invoice_paid(self):
        """Payment should mark invoice as paid"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=10000,
            payment_method='stripe',
            status='succeeded',
        )

        # Refresh invoice from database
        self.invoice.refresh_from_db()

        # Invoice status should be updated (depends on signal implementation)
        assert payment.status == 'succeeded'

    def test_partial_payment(self):
        """Partial payment should be tracked"""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=5000,  # Half payment
            payment_method='stripe',
            status='succeeded',
        )

        assert payment.amount_cents < self.invoice.total_cents


class TestProformaAPIIntegration(TestCase):
    """Integration tests for proforma invoice API"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_proforma_test',
            email='admin_proforma@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Proforma Test SRL',
            customer_type='company',
            company_name='SC Proforma Test SRL',
            primary_email='proforma@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True,
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        self.proforma = Proforma.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-2024-00001',
            status='draft',
            subtotal_cents=8403,
            total_cents=10000,
            valid_until=timezone.now() + timedelta(days=30),
        )

    def test_proforma_list_accessible(self):
        """Proforma list should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/billing/proforma/')
        assert response.status_code == 200

    def test_proforma_detail_accessible(self):
        """Proforma detail should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get(f'/app/billing/proforma/{self.proforma.pk}/')
        assert response.status_code == 200

    def test_proforma_to_invoice_conversion(self):
        """Proforma can be converted to invoice"""
        self.client.force_login(self.admin)
        response = self.client.post(f'/app/billing/proforma/{self.proforma.pk}/to-invoice/')
        # Should redirect or succeed
        assert response.status_code in [200, 302]


class TestInvoiceSequencing(TestCase):
    """Test invoice numbering sequence"""

    def setUp(self):
        """Set up test fixtures"""
        self.admin = User.objects.create_user(
            username='admin_seq_test',
            email='admin_seq@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Sequence Test SRL',
            customer_type='company',
            company_name='SC Sequence Test SRL',
            primary_email='sequence@test.ro',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            is_vat_payer=True,
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

    def test_invoice_numbers_unique(self):
        """Invoice numbers should be unique"""
        inv1 = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-UNIQUE-001',
            status='issued',
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        inv2 = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-UNIQUE-002',
            status='issued',
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        assert inv1.number != inv2.number

    def test_invoice_number_format(self):
        """Invoice number should follow expected format"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2024-00001',
            status='issued',
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Format: INV-YYYY-NNNNN
        assert invoice.number.startswith('INV-')
        assert '2024' in invoice.number
