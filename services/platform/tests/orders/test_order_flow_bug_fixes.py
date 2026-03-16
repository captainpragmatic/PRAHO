"""
Regression tests for PR #112 order flow bug fixes.

Tests two platform-side fixes:
1. Preflight rejects unsupported currencies
2. Null server guard returns error instead of creating ghost Service

Portal quantity validation tests are in services/portal/tests/.
"""

from __future__ import annotations

import json
from decimal import Decimal
from unittest.mock import patch

from django.test import RequestFactory, TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import ServicePlan

# ---------------------------------------------------------------------------
# 1. Preflight currency validation
# ---------------------------------------------------------------------------


def _call_preflight(customer: Customer, cart_items: list[dict], currency: str | None = None) -> tuple[int, dict]:
    """Call preflight_order with optional currency. Returns (status_code, response_data)."""
    from apps.api.orders.views import preflight_order  # noqa: PLC0415

    body_data: dict = {"items": cart_items}
    if currency is not None:
        body_data["currency"] = currency
    body = json.dumps(body_data, default=str).encode()
    factory = RequestFactory()
    raw_request = factory.post(
        "/api/orders/preflight/",
        data=body,
        content_type="application/json",
    )

    with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
        response = preflight_order(raw_request)

    return response.status_code, response.data  # type: ignore[union-attr]  # DRF Response always has .data


class PreflightCurrencyValidationTests(TestCase):
    """Verify preflight rejects unsupported and malformed currencies."""

    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Currency Test SRL",
            company_name="Currency Test SRL",
            customer_type="company",
            primary_email="currency@example.ro",
            status="active",
        )
        product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting",
            is_active=True,
            is_public=True,
        )
        ProductPrice.objects.create(
            product=product,
            currency=Currency.objects.get(code="RON"),
            monthly_price_cents=2500,
            is_active=True,
        )
        self.cart_items = [{"product_slug": "test-product", "quantity": 1, "billing_period": "monthly"}]

    def test_default_ron_accepted(self) -> None:
        """No currency field defaults to RON."""
        _status_code, data = _call_preflight(self.customer, self.cart_items)
        # Should not fail on currency validation (may fail later on other checks)
        if not data.get("success"):
            errors = data.get("errors", [])
            for err in errors:
                self.assertNotIn("currency", err.lower())

    def test_unsupported_currency_rejected(self) -> None:
        """GBP is not in CurrencyCode enum."""
        status_code, data = _call_preflight(self.customer, self.cart_items, currency="GBP")
        self.assertEqual(status_code, 400)
        self.assertFalse(data["success"])
        self.assertTrue(any("currency" in e.lower() for e in data["errors"]))

    def test_empty_string_currency_rejected(self) -> None:
        status_code, _data = _call_preflight(self.customer, self.cart_items, currency="")
        self.assertEqual(status_code, 400)

    def test_non_string_currency_rejected(self) -> None:
        """Numeric currency code should be rejected."""
        status_code, data = _call_preflight(self.customer, self.cart_items, currency=123)
        self.assertEqual(status_code, 400)
        self.assertTrue(any("string" in e.lower() for e in data["errors"]))

    def test_missing_db_record_distinct_error(self) -> None:
        """Currency passes enum but has no DB row — should say 'not configured', not 'unsupported'."""
        Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        # Delete EUR from DB to simulate missing record
        Currency.objects.filter(code="EUR").delete()
        status_code, data = _call_preflight(self.customer, self.cart_items, currency="EUR")
        self.assertEqual(status_code, 400)
        self.assertTrue(any("not configured" in e.lower() for e in data["errors"]))


# ---------------------------------------------------------------------------
# 3. Null server guard
# ---------------------------------------------------------------------------


class NullServerGuardTests(TestCase):
    """Verify _provision_confirmed_order_item returns error when no server available."""

    def test_no_server_returns_error_dict(self) -> None:
        """When _get_server_for_product_type returns None, provisioning returns error."""
        from apps.api.orders.views import _provision_confirmed_order_item  # noqa: PLC0415

        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        customer = Customer.objects.create(
            name="Server Test SRL",
            company_name="Server Test SRL",
            customer_type="company",
            primary_email="server@example.ro",
            status="active",
        )
        plan = ServicePlan.objects.create(
            name="Basic Plan", plan_type="shared_hosting", is_active=True,
            price_monthly=Decimal("25.00"), price_quarterly=Decimal("70.00"),
            price_annual=Decimal("250.00"),
        )
        product = Product.objects.create(
            slug="hosting-basic",
            name="Basic Hosting",
            product_type="shared_hosting",
            is_active=True,
            default_service_plan=plan,
        )
        order = Order.objects.create(customer=customer, currency=currency)
        item = OrderItem.objects.create(
            order=order,
            product=product,
            product_name="Basic Hosting",
            quantity=1,
            unit_price_cents=2500,
            setup_cents=0,
            tax_rate=Decimal("21.00"),
            billing_period="monthly",
        )

        with patch("apps.api.orders.views._get_server_for_product_type", return_value=(None, False)):
            result = _provision_confirmed_order_item(item, customer, order)

        self.assertIn("error", result)
        self.assertIn("No provisioning server", result["error"])
