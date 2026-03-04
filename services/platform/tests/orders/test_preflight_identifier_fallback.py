"""
Tests for preflight_order slug fallback — ensures the preflight endpoint resolves
products by slug when product_id is absent (C1 fix regression test).

Uses the same mock-serializer pattern as test_calculate_cart.py to bypass DRF
field validation and inject arbitrary cart_items into the view's inner loop.
"""

import json
from unittest.mock import patch

from django.test import RequestFactory, TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice

BILLING_PERIOD = "monthly"


def _make_currency(code: str = "RON") -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code=code,
        defaults={"symbol": "lei", "decimals": 2},
    )
    return currency


def _make_customer() -> Customer:
    return Customer.objects.create(
        name="Preflight Test SRL",
        company_name="Preflight Test SRL",
        customer_type="company",
        primary_email="preflight@example.ro",
        status="active",
    )


def _make_product(slug: str = "preflight-test-product") -> Product:
    return Product.objects.create(
        slug=slug,
        name="Preflight Test Product",
        product_type="shared_hosting",
        is_active=True,
        is_public=True,
    )


def _make_price(product: Product, currency: Currency, monthly_price_cents: int = 2500) -> ProductPrice:
    return ProductPrice.objects.create(
        product=product,
        currency=currency,
        monthly_price_cents=monthly_price_cents,
        is_active=True,
    )


def _call_preflight(customer: Customer, cart_items: list[dict]) -> tuple[int, dict]:
    """Call preflight_order with mocked auth. Returns (status_code, response_data)."""
    from apps.api.orders.views import preflight_order  # noqa: PLC0415

    body = json.dumps({"items": cart_items}, default=str).encode()
    factory = RequestFactory()
    raw_request = factory.post(
        "/api/orders/preflight/",
        data=body,
        content_type="application/json",
    )

    with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
        response = preflight_order(raw_request)

    return response.status_code, response.data  # type: ignore[union-attr]  # DRF Response always has .data


class PreflightSlugFallbackTestCase(TestCase):
    """preflight_order resolves products by slug when product_id is absent."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product("preflight-slug-product")
        self.price = _make_price(self.product, self.currency, monthly_price_cents=3000)

    def test_preflight_slug_only_resolves_product(self) -> None:
        """POST with product_slug only → product resolved, subtotal calculated (preview has positive totals)."""
        items = [{"product_slug": self.product.slug, "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        # Preflight may report validation errors (e.g. missing billing address) but
        # the key assertion is: the product resolved and pricing calculated correctly.
        self.assertEqual(status_code, 200)
        self.assertIn("preview", data)
        self.assertGreater(data["preview"]["subtotal_cents"], 0)

    def test_preflight_uuid_still_works(self) -> None:
        """POST with product_id (UUID) → product resolved, pricing calculated."""
        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        self.assertEqual(status_code, 200)
        self.assertIn("preview", data)
        self.assertGreater(data["preview"]["subtotal_cents"], 0)

    def test_preflight_missing_both_identifiers_returns_400(self) -> None:
        """POST with neither product_id nor product_slug → 400."""
        items = [{"quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        self.assertEqual(status_code, 400)
        self.assertFalse(data.get("success"))

    def test_preflight_uuid_inactive_product_returns_400(self) -> None:
        """UUID lookup of inactive product returns 400."""
        self.product.is_active = False
        self.product.save()

        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        self.assertEqual(status_code, 400)
        self.assertFalse(data.get("success"))

    def test_preflight_uuid_non_public_product_returns_400(self) -> None:
        """UUID lookup of non-public product returns 400."""
        self.product.is_public = False
        self.product.save()

        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        self.assertEqual(status_code, 400)
        self.assertFalse(data.get("success"))

    def test_preflight_nonexistent_slug_returns_400(self) -> None:
        """POST with unknown product_slug → 400 product not found."""
        items = [{"product_slug": "nonexistent-product", "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_preflight(self.customer, items)

        self.assertEqual(status_code, 400)
        self.assertFalse(data.get("success"))
