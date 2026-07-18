"""Regression tests for period-correct, promotion-aware API order pricing."""

from __future__ import annotations

import json
import secrets
from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.price_sealing import create_sealed_price_for_product_price
from apps.products.models import Product, ProductPrice


@override_settings(PRICE_SEALING_SECRET="period-pricing-test-secret-key-at-least-32-characters")
class PeriodCorrectAPIOrderPricingTests(TestCase):
    """All public API order stages must use the same authoritative period price."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Period Pricing SRL",
            company_name="Period Pricing SRL",
            customer_type="company",
            primary_email="period-pricing@example.ro",
            status="active",
        )
        self.product = Product.objects.create(
            slug="period-pricing-hosting",
            name="Period Pricing Hosting",
            product_type="shared_hosting",
            is_active=True,
            is_public=True,
        )
        self.price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10_000,
            semiannual_discount_percent=Decimal("5.00"),
            annual_discount_percent=Decimal("10.00"),
            is_active=True,
        )
        self.factory = RequestFactory()

    def _post(self, path: str, data: dict[str, Any], **headers: str) -> Any:
        return self.factory.post(
            path,
            data=json.dumps(data, default=str).encode(),
            content_type="application/json",
            **headers,
        )

    def _cart_item(self, billing_period: str, *, sealed_price_token: str = "") -> dict[str, Any]:
        item = {
            "product_id": str(self.product.id),
            "quantity": 1,
            "billing_period": billing_period,
            "config": {},
        }
        if sealed_price_token:
            item["sealed_price_token"] = sealed_price_token
        return item

    def test_period_accessor_applies_active_reduced_and_free_promotions(self) -> None:
        self.price.promo_valid_until = timezone.now() + timedelta(days=1)

        self.price.promo_price_cents = 8_000
        self.assertEqual(self.price.get_price_cents_for_period("annual"), 86_400)

        self.price.promo_price_cents = 0
        self.assertEqual(self.price.get_price_cents_for_period("monthly"), 0)
        self.assertEqual(self.price.get_price_cents_for_period("annual"), 0)

    def test_catalog_serializer_exposes_the_effective_monthly_promotion_price(self) -> None:
        from apps.api.orders.serializers import ProductPriceSerializer  # noqa: PLC0415

        self.price.promo_valid_until = timezone.now() + timedelta(days=1)
        self.assertEqual(self.price.monthly_price, Decimal("100.00"))

        for promo_price_cents, expected in ((8_000, "80.00"), (0, "0.00")):
            with self.subTest(promo_price_cents=promo_price_cents):
                self.price.promo_price_cents = promo_price_cents

                serialized = ProductPriceSerializer(self.price).data

                self.assertEqual(serialized["monthly_price"], expected)

    def test_period_accessor_ignores_expired_promotion(self) -> None:
        self.price.promo_price_cents = 8_000
        self.price.promo_valid_until = timezone.now() - timedelta(seconds=1)

        self.assertEqual(self.price.get_price_cents_for_period("monthly"), 10_000)
        self.assertEqual(self.price.get_price_cents_for_period("annual"), 108_000)

    def test_calculate_cart_uses_annual_price_for_unit_and_subtotal(self) -> None:
        from apps.api.orders.views import calculate_cart_totals  # noqa: PLC0415

        request = self._post(
            "/api/orders/calculate/",
            {"currency": "RON", "items": [self._cart_item("annual")]},
        )

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = calculate_cart_totals(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["items"][0]["unit_price_cents"], 108_000)
        self.assertEqual(response.data["items"][0]["line_total_cents"], 108_000)
        self.assertEqual(response.data["subtotal_cents"], 108_000)

    def test_preflight_uses_semiannual_price_for_preview_subtotal(self) -> None:
        from apps.api.orders.views import preflight_order  # noqa: PLC0415

        request = self._post(
            "/api/orders/preflight/",
            {"currency": "RON", "items": [self._cart_item("semiannual")]},
        )

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = preflight_order(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["preview"]["subtotal_cents"], 57_000)

    def test_preflight_rejects_periods_without_price_model_support(self) -> None:
        from apps.api.orders.views import preflight_order  # noqa: PLC0415

        for billing_period in ("quarterly", "yearly", "biennial", "triennial"):
            with self.subTest(billing_period=billing_period):
                request = self._post(
                    "/api/orders/preflight/",
                    {"currency": "RON", "items": [self._cart_item(billing_period)]},
                )

                with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
                    response = preflight_order(request)

                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.data["success"])
                self.assertIn("billing_period", response.data["details"][0])

    def test_create_order_persists_sealed_price_for_every_billing_period(self) -> None:
        from apps.api.orders.views import create_order  # noqa: PLC0415

        expected_prices = {"monthly": 10_000, "semiannual": 57_000, "annual": 108_000}

        for billing_period, expected_price in expected_prices.items():
            with self.subTest(billing_period=billing_period):
                sealed_token = create_sealed_price_for_product_price(
                    self.price,
                    client_ip="203.0.113.10",
                    billing_period=billing_period,
                )
                idempotency_key = secrets.token_urlsafe(24)
                cart_item = self._cart_item(billing_period, sealed_price_token=sealed_token)
                cart_item["config"]["billing_period"] = "once"
                request = self._post(
                    "/api/orders/create/",
                    {
                        "currency": "RON",
                        "items": [cart_item],
                    },
                    HTTP_IDEMPOTENCY_KEY=idempotency_key,
                )

                with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
                    response = create_order(request)

                self.assertEqual(response.status_code, 201, response.data)
                order = Order.objects.get(pk=response.data["order"]["id"])
                order_item = order.items.get()
                # The validated top-level period is authoritative over client-controlled config.
                self.assertEqual(order_item.billing_period, billing_period)
                self.assertEqual(order_item.unit_price_cents, expected_price)
