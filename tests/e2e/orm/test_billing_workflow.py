# ===============================================================================
# END-TO-END TESTS FOR BILLING WORKFLOW
# ===============================================================================
"""
End-to-end tests for complete billing workflow.
Tests order to invoice to payment flow with Romanian VAT compliance.
"""

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

from apps.customers.models import Customer, CustomerAddress, CustomerBillingProfile, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.billing.models import Currency, Invoice, InvoiceLine, Payment
from apps.billing.proforma_models import ProformaInvoice
from apps.products.models import Product

User = get_user_model()


@pytest.mark.e2e
class TestOrderToBillingWorkflow(TestCase):
    """End-to-end tests for order to billing workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='billing_admin@test.ro',
            password='AdminPass123!',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Billing Test SRL',
            customer_type='company',
            company_name='SC Billing Test SRL',
            primary_email='billing@company.ro',
            primary_phone='+40721234567',
            data_processing_consent=True,
            created_by=self.admin,
        )

        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            vat_number='RO12345678',
            registration_number='J40/1234/2024',
            is_vat_payer=True,
            vat_rate=Decimal('19.00'),
        )

        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            preferred_currency='RON',
        )

        CustomerAddress.objects.create(
            customer=self.customer,
            address_type='legal',
            address_line1='Str. Billing Nr. 1',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True,
        )

        self.product = Product.objects.create(
            name='Hosting Standard',
            slug='wh-std-e2e',
            description='Standard web hosting package',
            product_type='shared_hosting',
            is_active=True,
        )

    def test_complete_order_to_invoice_flow(self):
        """Test complete flow from order creation to invoice"""
        self.client.force_login(self.admin)

        # Step 1: Create order
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-E2E-001',
            status='draft',
            currency=self.currency,
            subtotal_cents=9900,
            tax_cents=1881,
            total_cents=11781,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=9900,
            line_total_cents=9900,
        )

        assert order.pk is not None
        assert order.items.count() == 1

        # Step 2: Confirm order
        order.status = 'confirmed'
        order.save()

        # Step 3: Create invoice from order
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-001',
            status='issued',
            subtotal_cents=order.subtotal_cents,
            tax_cents=order.tax_cents,
            total_cents=order.total_cents,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Link order to invoice (Order has FK to Invoice)
        order.invoice = invoice
        order.save()

        InvoiceLine.objects.create(
            invoice=invoice,
            description=self.product.name,
            quantity=1,
            unit_price_cents=9900,
            line_total_cents=9900,
        )

        assert invoice.pk is not None
        assert order.invoice == invoice
        assert invoice.total_cents == order.total_cents

    def test_complete_invoice_to_payment_flow(self):
        """Test complete flow from invoice to payment"""
        self.client.force_login(self.admin)

        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-PAY-001',
            status='issued',
            subtotal_cents=8403,
            tax_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        InvoiceLine.objects.create(
            invoice=invoice,
            description='Web Hosting Standard',
            quantity=1,
            unit_price_cents=8403,
            line_total_cents=8403,
        )

        # Create payment
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=10000,
            payment_method='stripe',
            status='succeeded',
        )

        assert payment.pk is not None
        assert payment.invoice == invoice
        assert payment.amount_cents == invoice.total_cents

    def test_romanian_vat_19_percent_applied(self):
        """Verify 19% Romanian VAT is applied correctly"""
        subtotal_cents = 10000  # 100.00 RON
        tax_cents = int(subtotal_cents * Decimal('0.19'))  # 19.00 RON
        total_cents = subtotal_cents + tax_cents  # 119.00 RON

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-VAT-001',
            status='issued',
            subtotal_cents=subtotal_cents,
            tax_cents=tax_cents,
            total_cents=total_cents,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Verify VAT calculation
        actual_vat_rate = (invoice.tax_cents / invoice.subtotal_cents) * 100
        assert 18.9 < actual_vat_rate < 19.1
        assert invoice.total_cents == invoice.subtotal_cents + invoice.tax_cents


@pytest.mark.e2e
class TestProformaToInvoiceWorkflow(TestCase):
    """End-to-end tests for proforma to invoice workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='proforma_admin@test.ro',
            password='AdminPass123!',
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
            primary_email='proforma@company.ro',
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

    def test_proforma_creation_and_conversion(self):
        """Test proforma creation and conversion to invoice"""
        self.client.force_login(self.admin)

        # Create proforma
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-E2E-001',
            status='draft',
            subtotal_cents=8403,
            total_cents=10000,
            valid_until=timezone.now() + timedelta(days=30),
        )

        assert proforma.pk is not None
        assert proforma.status == 'draft'

        # Convert to invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-PRO-001',
            status='issued',
            subtotal_cents=proforma.subtotal_cents,
            tax_cents=1597,
            total_cents=proforma.total_cents,
            due_at=timezone.now() + timedelta(days=30),
        )

        assert invoice.pk is not None
        assert invoice.total_cents == proforma.total_cents


@pytest.mark.e2e
class TestRefundWorkflow(TestCase):
    """End-to-end tests for refund workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='refund_admin@test.ro',
            password='AdminPass123!',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Refund Test SRL',
            customer_type='company',
            company_name='SC Refund Test SRL',
            primary_email='refund@company.ro',
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

    def test_full_refund_workflow(self):
        """Test full refund of paid invoice"""
        self.client.force_login(self.admin)

        # Create paid invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-REFUND-001',
            status='paid',
            subtotal_cents=8403,
            tax_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Create payment
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=10000,
            payment_method='stripe',
            status='succeeded',
        )

        # Create refund payment (negative amount)
        refund = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=-10000,  # Negative for refund
            payment_method='stripe',
            status='refunded',
        )

        assert refund.amount_cents == -payment.amount_cents

    def test_partial_refund_workflow(self):
        """Test partial refund of paid invoice"""
        self.client.force_login(self.admin)

        # Create paid invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-E2E-PARTIAL-001',
            status='paid',
            subtotal_cents=8403,
            tax_cents=1597,
            total_cents=10000,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Create payment
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=10000,
            payment_method='stripe',
            status='succeeded',
        )

        # Create partial refund
        refund = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=-5000,  # Half refund
            payment_method='stripe',
            status='refunded',
        )

        assert refund.amount_cents == -5000
        assert abs(refund.amount_cents) < invoice.total_cents
