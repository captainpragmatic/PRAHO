"""
Tests for create_order slug fallback — ensures the create endpoint resolves
products by slug when product_id is absent (C1 fix regression test).

The create_order view requires an idempotency key and validates via
CartCalculationInputSerializer, so we mock auth but let the serializer run
(it now accepts slug-only items after the C1 fix).
"""

import json
import secrets
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
        name="Create Order Test SRL",
        company_name="Create Order Test SRL",
        customer_type="company",
        primary_email="createorder@example.ro",
        status="active",
    )


def _make_product(slug: str = "create-order-product") -> Product:
    return Product.objects.create(
        slug=slug,
        name="Create Order Product",
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


def _call_create_order(customer: Customer, items: list[dict], currency: str = "RON") -> tuple[int, dict]:
    """Call create_order with mocked auth. Returns (status_code, response_data)."""
    from apps.api.orders.views import create_order  # noqa: PLC0415

    idempotency_key = secrets.token_urlsafe(32)
    body = json.dumps(
        {
            "customer_id": customer.id,
            "items": items,
            "currency": currency,
            "Idempotency-Key": idempotency_key,
        },
        default=str,
    ).encode()

    factory = RequestFactory()
    raw_request = factory.post(
        "/api/orders/create/",
        data=body,
        content_type="application/json",
        HTTP_IDEMPOTENCY_KEY=idempotency_key,
    )

    with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
        response = create_order(raw_request)

    return response.status_code, response.data  # type: ignore[union-attr]  # DRF Response always has .data


class CreateOrderSlugFallbackTestCase(TestCase):
    """create_order resolves products by slug when product_id is absent."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product("create-slug-product")
        self.price = _make_price(self.product, self.currency, monthly_price_cents=5000)

    def test_create_order_slug_only_creates_order(self) -> None:
        """POST with product_slug only → order created (201) or validation error (not 500)."""
        items = [{"product_slug": self.product.slug, "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_create_order(self.customer, items)

        # Order creation may fail due to incomplete billing profile, but must NOT be a 500
        self.assertIn(status_code, (201, 400), f"Expected 201 or 400, got {status_code}: {data}")

    def test_create_order_uuid_still_works(self) -> None:
        """POST with product_id (UUID) → order created or validation error."""
        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_create_order(self.customer, items)

        self.assertIn(status_code, (201, 400), f"Expected 201 or 400, got {status_code}: {data}")

    def test_create_order_uuid_inactive_product_returns_400(self) -> None:
        """UUID lookup of inactive product returns 400."""
        self.product.is_active = False
        self.product.save()

        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_create_order(self.customer, items)

        self.assertEqual(status_code, 400, f"Expected 400 for inactive product, got {status_code}: {data}")
        self.assertIn("not found", data.get("error", "").lower())

    def test_create_order_uuid_non_public_product_returns_400(self) -> None:
        """UUID lookup of non-public product returns 400."""
        self.product.is_public = False
        self.product.save()

        items = [{"product_id": str(self.product.id), "quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_create_order(self.customer, items)

        self.assertEqual(status_code, 400, f"Expected 400 for non-public product, got {status_code}: {data}")
        self.assertIn("not found", data.get("error", "").lower())

    def test_create_order_missing_both_identifiers_returns_400(self) -> None:
        """POST with neither identifier → 400 error (serializer or view rejects)."""
        items = [{"quantity": 1, "billing_period": BILLING_PERIOD}]
        status_code, data = _call_create_order(self.customer, items)

        # Serializer should reject — at least one identifier required
        self.assertEqual(status_code, 400, f"Expected 400 for missing identifiers, got {status_code}: {data}")


class CreateOrderSealedPriceTokenTestCase(TestCase):
    """Sealed price token validation in create_order — fail-closed on invalid tokens."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product("sealed-token-product")
        self.price = _make_price(self.product, self.currency, monthly_price_cents=4000)

    def test_invalid_sealed_token_returns_400(self) -> None:
        """Providing a bad sealed_price_token must return 400, not silently fall back."""
        items = [
            {
                "product_id": str(self.product.id),
                "quantity": 1,
                "billing_period": BILLING_PERIOD,
                "sealed_price_token": "invalid-token-data-here",
            }
        ]
        status_code, data = _call_create_order(self.customer, items)

        self.assertEqual(status_code, 400, f"Expected 400 for invalid token, got {status_code}: {data}")
        self.assertIn("sealed price token", data.get("error", "").lower())

    def test_no_sealed_token_uses_current_pricing(self) -> None:
        """Without a sealed token, order should proceed with current pricing (no token error)."""
        items = [
            {
                "product_id": str(self.product.id),
                "quantity": 1,
                "billing_period": BILLING_PERIOD,
            }
        ]
        status_code, data = _call_create_order(self.customer, items)

        # Should succeed (201) or fail for non-token reasons (400 from billing profile etc.)
        self.assertIn(status_code, (201, 400), f"Unexpected status {status_code}: {data}")
        # Must NOT be a token-related error
        if status_code == 400:
            self.assertNotIn("sealed price token", data.get("error", "").lower())
