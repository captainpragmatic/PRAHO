from __future__ import annotations

import time

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.api.orders.views import calculate_cart_totals, product_detail, product_list
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice
from apps.users.models import CustomerMembership, User


class OrdersAPIIntegrationTests(TestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()

        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Orders API Customer SRL",
            company_name="Orders API Customer SRL",
            customer_type="company",
            status="active",
            primary_email="orders-api@example.ro",
        )
        self.user = User.objects.create_user(email="orders-api-user@example.ro", password="testpass123")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_active=True)

        self.product = Product.objects.create(
            slug="integration-shared-hosting",
            name="Integration Shared Hosting",
            product_type="shared_hosting",
            is_active=True,
            is_public=True,
        )
        self.product_price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2500,
            setup_cents=0,
            is_active=True,
        )

    def _auth_payload(self, **extra: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "customer_id": self.customer.id,
            "user_id": self.user.id,
            "timestamp": int(time.time()),
        }
        payload.update(extra)
        return payload

    def test_product_list_filters_inactive_and_non_public_products(self) -> None:
        hidden = Product.objects.create(
            slug="integration-hidden",
            name="Hidden Product",
            product_type="shared_hosting",
            is_active=True,
            is_public=False,
        )
        ProductPrice.objects.create(
            product=hidden,
            currency=self.currency,
            monthly_price_cents=3000,
            is_active=True,
        )

        inactive = Product.objects.create(
            slug="integration-inactive",
            name="Inactive Product",
            product_type="shared_hosting",
            is_active=False,
            is_public=True,
        )
        ProductPrice.objects.create(
            product=inactive,
            currency=self.currency,
            monthly_price_cents=3000,
            is_active=True,
        )

        request = self.factory.get("/api/orders/products/")

        response = product_list(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["slug"], self.product.slug)

    def test_product_detail_returns_404_for_unknown_slug(self) -> None:
        request = self.factory.get("/api/orders/products/does-not-exist/")

        response = product_detail(request, "does-not-exist")

        self.assertEqual(response.status_code, 404)

    def test_calculate_cart_totals_requires_hmac_auth_context(self) -> None:
        request = self.factory.post(
            "/api/orders/calculate/",
            data=self._auth_payload(
                currency=self.currency.code,
                items=[
                    {
                        "product_id": str(self.product.id),
                        "quantity": 1,
                        "billing_period": "monthly",
                    }
                ],
            ),
            format="json",
        )

        response = calculate_cart_totals(request)

        self.assertEqual(response.status_code, 401)

    def test_calculate_cart_totals_returns_server_authoritative_totals(self) -> None:
        request = self.factory.post(
            "/api/orders/calculate/",
            data=self._auth_payload(
                currency=self.currency.code,
                items=[
                    {
                        "product_id": str(self.product.id),
                        "quantity": 2,
                        "billing_period": "monthly",
                    }
                ],
            ),
            format="json",
        )
        request._portal_authenticated = True

        response = calculate_cart_totals(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["subtotal_cents"], self.product_price.monthly_price_cents * 2)
        self.assertEqual(response.data["total_cents"], response.data["subtotal_cents"] + response.data["tax_cents"])
        self.assertEqual(len(response.data["items"]), 1)
        self.assertEqual(response.data["warnings"], [])
