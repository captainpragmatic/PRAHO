"""
Tests for product price view authorization.
Verifies @admin_required on price edit and delete views.
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.products.models import Product, ProductPrice

User = get_user_model()


class ProductPriceAuthTests(TestCase):
    """Verify product_price_edit and product_price_delete require admin."""

    def setUp(self):
        self.non_admin_user = User.objects.create_user(
            email="staff@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="support",
        )
        self.admin_user = User.objects.create_user(
            email="admin@example.com",
            password="adminpass123",
            is_staff=True,
            is_superuser=True,
        )
        self.product = Product.objects.create(
            name="Test Product",
            slug="test-product",
            product_type="hosting",
            is_active=True,
        )
        self.currency = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei"},
        )[0]
        self.price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=1000,
            is_active=True,
        )
        self.client = Client()

    def test_price_edit_requires_admin(self):
        """Non-admin staff should get 403 on price edit."""
        self.client.force_login(self.non_admin_user)
        url = reverse(
            "products:product_price_edit",
            kwargs={"slug": self.product.slug, "price_id": self.price.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_price_delete_requires_admin(self):
        """Non-admin staff should get 403 on price delete."""
        self.client.force_login(self.non_admin_user)
        url = reverse(
            "products:product_price_delete",
            kwargs={"slug": self.product.slug, "price_id": self.price.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_price_edit_admin_succeeds(self):
        """Admin should be able to access price edit."""
        self.client.force_login(self.admin_user)
        url = reverse(
            "products:product_price_edit",
            kwargs={"slug": self.product.slug, "price_id": self.price.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_price_delete_admin_succeeds(self):
        """Admin should be able to access price delete confirmation."""
        self.client.force_login(self.admin_user)
        url = reverse(
            "products:product_price_delete",
            kwargs={"slug": self.product.slug, "price_id": self.price.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
