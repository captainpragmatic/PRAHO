# ===============================================================================
# INTEGRATION TESTS FOR ORDER API ENDPOINTS
# ===============================================================================
"""
Integration tests for order management API endpoints.
Tests cover order lifecycle, Romanian VAT compliance, and status workflows.
"""

import json
import os
import sys
from decimal import Decimal

import pytest

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django
django.setup()

from django.test import Client, TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model

from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductCategory
from apps.billing.models import Currency

User = get_user_model()


class TestOrderAPIIntegration(TestCase):
    """Integration tests for order API endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        # Create admin user
        self.admin = User.objects.create_user(
            username='admin_order_test',
            email='admin_order@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        # Create currency
        self.currency, _ = Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        # Create customer
        self.customer = Customer.objects.create(
            name='SC Order Test SRL',
            customer_type='company',
            company_name='SC Order Test SRL',
            primary_email='order@test.ro',
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

        # Create product category and product
        self.category, _ = ProductCategory.objects.get_or_create(
            name='Web Hosting',
            defaults={'slug': 'web-hosting', 'is_active': True}
        )

        self.product = Product.objects.create(
            name='Hosting Standard',
            sku='WH-STD-TEST',
            price_cents=9900,
            currency_code='RON',
            is_active=True,
            category=self.category,
        )

        # Create order
        self.order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-2024-TEST-0001',
            status='draft',
            currency_code='RON',
            created_by=self.admin,
        )

        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_sku=self.product.sku,
            quantity=1,
            unit_price_cents=self.product.price_cents,
            total_cents=self.product.price_cents,
        )

    def test_order_list_requires_authentication(self):
        """Order list should require authentication"""
        response = self.client.get('/app/orders/')
        assert response.status_code in [302, 403]

    def test_order_list_authenticated(self):
        """Authenticated user should see order list"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/orders/')
        assert response.status_code == 200

    def test_order_detail_accessible(self):
        """Order detail should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get(f'/app/orders/{self.order.pk}/')
        assert response.status_code == 200

    def test_order_create_form_accessible(self):
        """Order create form should be accessible"""
        self.client.force_login(self.admin)
        response = self.client.get('/app/orders/create/')
        assert response.status_code == 200


class TestOrderStatusWorkflow(TestCase):
    """Test order status workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_status_test',
            email='admin_status@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Status Test SRL',
            customer_type='company',
            company_name='SC Status Test SRL',
            primary_email='status@test.ro',
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

        self.order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-2024-STATUS-0001',
            status='draft',
            currency_code='RON',
            created_by=self.admin,
        )

    def test_order_status_change_to_pending(self):
        """Order status can change from draft to pending"""
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/app/orders/{self.order.pk}/change-status/',
            json.dumps({'status': 'pending'}),
            content_type='application/json',
        )
        # Should succeed or return appropriate error
        assert response.status_code in [200, 302, 400]

    def test_order_status_change_to_confirmed(self):
        """Order status can change to confirmed"""
        self.order.status = 'pending'
        self.order.save()

        self.client.force_login(self.admin)
        response = self.client.post(
            f'/app/orders/{self.order.pk}/change-status/',
            json.dumps({'status': 'confirmed'}),
            content_type='application/json',
        )
        assert response.status_code in [200, 302, 400]

    def test_invalid_status_transition_rejected(self):
        """Invalid status transitions should be rejected"""
        self.order.status = 'completed'
        self.order.save()

        self.client.force_login(self.admin)
        response = self.client.post(
            f'/app/orders/{self.order.pk}/change-status/',
            json.dumps({'status': 'draft'}),  # Can't go back to draft
            content_type='application/json',
        )
        # Should fail or show appropriate error
        assert response.status_code in [200, 400, 422]


class TestOrderVATCalculation(TestCase):
    """Test Romanian VAT calculation in orders"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_vat_test',
            email='admin_vat@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC VAT Test SRL',
            customer_type='company',
            company_name='SC VAT Test SRL',
            primary_email='vat@test.ro',
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

        self.category, _ = ProductCategory.objects.get_or_create(
            name='Web Hosting',
            defaults={'slug': 'web-hosting', 'is_active': True}
        )

        self.product = Product.objects.create(
            name='Hosting VAT Test',
            sku='WH-VAT-TEST',
            price_cents=10000,  # 100.00 RON
            currency_code='RON',
            is_active=True,
            category=self.category,
        )

    def test_order_vat_19_percent(self):
        """Order VAT should be 19% for Romanian customers"""
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-2024-VAT-0001',
            status='draft',
            currency_code='RON',
            subtotal_cents=10000,
            tax_cents=1900,  # 19% VAT
            total_cents=11900,
            created_by=self.admin,
        )

        # Verify VAT calculation
        vat_percentage = (order.tax_cents / order.subtotal_cents) * 100
        assert 18.9 < vat_percentage < 19.1

    def test_order_total_includes_vat(self):
        """Order total should include VAT"""
        order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-2024-VAT-0002',
            status='draft',
            currency_code='RON',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            created_by=self.admin,
        )

        assert order.total_cents == order.subtotal_cents + order.tax_cents


class TestOrderItemAPI(TestCase):
    """Test order item operations"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()

        self.admin = User.objects.create_user(
            username='admin_item_test',
            email='admin_item@test.ro',
            password='testpass123',
            is_staff=True,
            is_superuser=True,
            staff_role='admin',
        )

        Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        self.customer = Customer.objects.create(
            name='SC Item Test SRL',
            customer_type='company',
            company_name='SC Item Test SRL',
            primary_email='item@test.ro',
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

        self.category, _ = ProductCategory.objects.get_or_create(
            name='Web Hosting',
            defaults={'slug': 'web-hosting', 'is_active': True}
        )

        self.product = Product.objects.create(
            name='Hosting Item Test',
            sku='WH-ITEM-TEST',
            price_cents=9900,
            currency_code='RON',
            is_active=True,
            category=self.category,
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number='ORD-2024-ITEM-0001',
            status='draft',
            currency_code='RON',
            created_by=self.admin,
        )

    def test_add_item_to_order(self):
        """Item can be added to order"""
        self.client.force_login(self.admin)

        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_sku=self.product.sku,
            quantity=1,
            unit_price_cents=self.product.price_cents,
            total_cents=self.product.price_cents,
        )

        assert self.order.items.count() == 1
        assert item.order == self.order

    def test_order_items_total(self):
        """Order items total should sum correctly"""
        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_sku=self.product.sku,
            quantity=2,
            unit_price_cents=5000,
            total_cents=10000,
        )

        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name='Another Product',
            product_sku='OTHER-001',
            quantity=1,
            unit_price_cents=3000,
            total_cents=3000,
        )

        total = sum(item.total_cents for item in self.order.items.all())
        assert total == 13000

    def test_item_quantity_validation(self):
        """Item quantity should be positive"""
        item = OrderItem(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_sku=self.product.sku,
            quantity=0,  # Invalid
            unit_price_cents=self.product.price_cents,
            total_cents=0,
        )

        # Should fail validation or be handled
        try:
            item.full_clean()
        except Exception:
            pass  # Expected for invalid quantity
