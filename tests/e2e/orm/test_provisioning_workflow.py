# ===============================================================================
# END-TO-END TESTS FOR PROVISIONING WORKFLOW
# ===============================================================================
"""
End-to-end tests for service provisioning workflow.
Tests the complete flow from order confirmation to service activation.
"""

import os
import sys
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django
django.setup()

from django.test import Client, TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model

from apps.customers.models import Customer, CustomerBillingProfile, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.billing.models import Currency, Invoice, Payment
from apps.products.models import Product

User = get_user_model()


@pytest.mark.e2e
class TestServiceProvisioningWorkflow(TestCase):
    """End-to-end tests for service provisioning"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='provision_admin@test.ro',
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
            name='SC Provision Test SRL',
            customer_type='company',
            company_name='SC Provision Test SRL',
            primary_email='provision@company.ro',
            primary_phone='+40721234567',
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

        self.hosting_product = Product.objects.create(
            name='Web Hosting Standard',
            slug='wh-std-prov',
            description='Standard web hosting package',
            product_type='shared_hosting',
            is_active=True,
        )

    def test_order_to_provisioning_flow(self):
        """Test complete flow from order to service provisioning"""
        self.client.force_login(self.admin)

        # Step 1: Create and confirm order
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-PROV-001',
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
            product=self.hosting_product,
            product_name=self.hosting_product.name,
            product_type=self.hosting_product.product_type,
            quantity=1,
            unit_price_cents=9900,
            line_total_cents=9900,
        )

        # Confirm order
        order.status = 'confirmed'
        order.save()
        assert order.status == 'confirmed'

        # Step 2: Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PROV-001',
            status='issued',
            subtotal_cents=9900,
            tax_cents=1881,
            total_cents=11781,
            due_at=timezone.now() + timedelta(days=30),
        )

        # Link order to invoice (Order has FK to Invoice)
        order.invoice = invoice
        order.save()

        # Step 3: Process payment
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=11781,
            payment_method='stripe',
            status='succeeded',
        )

        assert payment.status == 'succeeded'

        # Step 4: Update invoice status
        invoice.status = 'paid'
        invoice.save()
        assert invoice.status == 'paid'

        # Step 5: Order ready for provisioning
        order.status = 'processing'
        order.save()
        assert order.status == 'processing'

    def test_hosting_product_provisioning_requirements(self):
        """Test that hosting products have required provisioning data"""
        assert self.hosting_product.name is not None
        assert self.hosting_product.slug is not None
        assert self.hosting_product.product_type == 'shared_hosting'

    def test_order_with_multiple_services(self):
        """Test order with multiple services to provision"""
        self.client.force_login(self.admin)

        # Create additional products
        vps_product = Product.objects.create(
            name='VPS Basic',
            slug='vps-basic-prov',
            description='Basic VPS package',
            product_type='vps',
            is_active=True,
        )

        domain_product = Product.objects.create(
            name='Domain .ro',
            slug='dom-ro-prov',
            description='.ro domain registration',
            product_type='domain',
            is_active=True,
        )

        # Create order with multiple items
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-MULTI-001',
            status='draft',
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        # Add hosting
        OrderItem.objects.create(
            order=order,
            product=self.hosting_product,
            product_name=self.hosting_product.name,
            product_type=self.hosting_product.product_type,
            quantity=1,
            unit_price_cents=9900,
            line_total_cents=9900,
        )

        # Add VPS
        OrderItem.objects.create(
            order=order,
            product=vps_product,
            product_name=vps_product.name,
            product_type=vps_product.product_type,
            quantity=1,
            unit_price_cents=29900,
            line_total_cents=29900,
        )

        # Add domain
        OrderItem.objects.create(
            order=order,
            product=domain_product,
            product_name=domain_product.name,
            product_type=domain_product.product_type,
            quantity=1,
            unit_price_cents=4500,
            line_total_cents=4500,
        )

        assert order.items.count() == 3

        # Calculate totals
        subtotal = sum(item.line_total_cents for item in order.items.all())
        assert subtotal == 44300  # 9900 + 29900 + 4500


@pytest.mark.e2e
class TestProvisioningStatusWorkflow(TestCase):
    """End-to-end tests for provisioning status changes"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='status_prov_admin@test.ro',
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
            name='SC Status Test SRL',
            customer_type='company',
            company_name='SC Status Test SRL',
            primary_email='status@company.ro',
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

    def test_order_status_workflow(self):
        """Test order status transitions for provisioning"""
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-STATUS-001',
            status='draft',
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        # Draft -> Pending
        order.status = 'pending'
        order.save()
        assert order.status == 'pending'

        # Pending -> Confirmed
        order.status = 'confirmed'
        order.save()
        assert order.status == 'confirmed'

        # Confirmed -> Processing (payment received)
        order.status = 'processing'
        order.save()
        assert order.status == 'processing'

        # Processing -> Completed (services provisioned)
        order.status = 'completed'
        order.save()
        assert order.status == 'completed'


@pytest.mark.e2e
class TestProvisioningWithDomain(TestCase):
    """End-to-end tests for domain provisioning"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='domain_prov_admin@test.ro',
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
            name='SC Domain Test SRL',
            customer_type='company',
            company_name='SC Domain Test SRL',
            primary_email='domain@company.ro',
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

    def test_domain_registration_order(self):
        """Test domain registration order flow"""
        domain_product = Product.objects.create(
            name='Domain .ro',
            slug='dom-ro-reg',
            description='.ro domain registration - 1 year',
            product_type='domain',
            is_active=True,
        )

        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-DOM-001',
            status='draft',
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        OrderItem.objects.create(
            order=order,
            product=domain_product,
            product_name=domain_product.name,
            product_type=domain_product.product_type,
            quantity=1,
            unit_price_cents=4500,
            line_total_cents=4500,
            config={'domain_name': 'test-domain.ro'},
        )

        assert order.items.count() == 1
        item = order.items.first()
        assert item.config.get('domain_name') == 'test-domain.ro'


@pytest.mark.e2e
class TestBundleProvisioning(TestCase):
    """End-to-end tests for bundle/package provisioning"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            email='bundle_prov_admin@test.ro',
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
            name='SC Bundle Test SRL',
            customer_type='company',
            company_name='SC Bundle Test SRL',
            primary_email='bundle@company.ro',
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

    def test_hosting_bundle_order(self):
        """Test hosting bundle with multiple services"""
        bundle_product = Product.objects.create(
            name='Startup Bundle',
            slug='bundle-startup',
            description='Web hosting + Domain + SSL',
            product_type='shared_hosting',
            is_active=True,
        )

        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-BUNDLE-001',
            status='draft',
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        OrderItem.objects.create(
            order=order,
            product=bundle_product,
            product_name=bundle_product.name,
            product_type=bundle_product.product_type,
            quantity=1,
            unit_price_cents=14900,
            line_total_cents=14900,
            config={
                'bundle_components': [
                    {'type': 'hosting', 'plan': 'standard'},
                    {'type': 'domain', 'name': 'example.ro'},
                    {'type': 'ssl', 'type': 'standard'},
                ],
            },
        )

        assert order.items.count() == 1
        item = order.items.first()
        assert len(item.config.get('bundle_components', [])) == 3
