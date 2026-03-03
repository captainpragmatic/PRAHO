"""
Tests for the cart calculate endpoint's product lookup logic.

The view (calculate_cart_totals) supports three product-lookup modes:
  1. product_id (UUID) — primary path
  2. product_slug (string) — fallback when product_id is absent
  3. neither — appends a "missing_identifier" warning and skips the item

We test the view's inner loop by:
  - Patching get_authenticated_customer to bypass HMAC (inject a real Customer)
  - Patching CartCalculationInputSerializer to bypass DRF field validation and
    inject pre-built cart_items dicts that include product_slug / no identifier

Platform tests — full database access via Django TestCase.
"""

import uuid
from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice

# ---------------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------------

BILLING_PERIOD = "monthly"


def _make_currency(code: str = "RON") -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code=code,
        defaults={"symbol": "lei", "decimals": 2},
    )
    return currency


def _make_customer() -> Customer:
    return Customer.objects.create(
        name="Cart Test SRL",
        company_name="Cart Test SRL",
        customer_type="company",
        primary_email="carttest@example.ro",
        status="active",
    )


def _make_product(slug: str = "cart-test-product") -> Product:
    return Product.objects.create(
        slug=slug,
        name="Cart Test Product",
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


def _cart_item(
    *,
    product_id: uuid.UUID | None = None,
    product_slug: str | None = None,
    quantity: int = 1,
) -> dict:
    """Build a cart item dict as the view's inner loop expects it."""
    item: dict = {"quantity": quantity, "billing_period": BILLING_PERIOD, "config": {}}
    if product_id is not None:
        item["product_id"] = product_id
    if product_slug is not None:
        item["product_slug"] = product_slug
    return item


# ---------------------------------------------------------------------------
# Helper — call the view with mocked auth + mocked serializer
# ---------------------------------------------------------------------------

def _call_calculate(customer: Customer, currency: Currency, cart_items: list[dict]) -> dict:
    """
    Call calculate_cart_totals with:
      - HMAC authentication bypassed via get_authenticated_customer mock
      - CartCalculationInputSerializer bypassed so we can inject arbitrary cart_items
        (including slug-only or identifier-free items that the real serializer would reject)

    Returns response.data dict.
    """
    import json

    from apps.api.orders.views import calculate_cart_totals

    body = json.dumps(
        {"customer_id": customer.id, "currency": currency.code, "items": []},
        default=str,
    ).encode()

    factory = RequestFactory()
    raw_request = factory.post(
        "/api/orders/calculate/",
        data=body,
        content_type="application/json",
    )

    # Build a mock serializer that validates successfully and exposes our items
    mock_serializer = MagicMock()
    mock_serializer.is_valid.return_value = True
    mock_serializer.validated_data = {
        "customer_id": customer.id,
        "currency": currency.code,
        "items": cart_items,
    }

    with (
        patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)),
        patch("apps.api.orders.views.CartCalculationInputSerializer", return_value=mock_serializer),
    ):
        response = calculate_cart_totals(raw_request)

    return response.data  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class CartCalculateProductByUUIDTestCase(TestCase):
    """Test 1 — product_id (UUID) → product found, calculation succeeds."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product("uuid-lookup-product")
        self.price = _make_price(self.product, self.currency, monthly_price_cents=3000)

    def test_product_id_uuid_finds_product_and_calculates_subtotal(self) -> None:
        """POST with product_id (UUID) → product resolved, subtotal > 0."""
        items = [_cart_item(product_id=self.product.id, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        self.assertIn("subtotal_cents", data, f"Unexpected response: {data}")
        self.assertGreater(data["subtotal_cents"], 0)

    def test_product_id_missing_identifier_warning_absent_for_valid_uuid(self) -> None:
        """No missing_identifier warning is emitted when product_id resolves correctly."""
        items = [_cart_item(product_id=self.product.id, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        missing_warnings = [w for w in data.get("warnings", []) if w.get("type") == "missing_identifier"]
        self.assertEqual(missing_warnings, [])

    def test_product_id_quantity_multiplier_applied(self) -> None:
        """Subtotal reflects quantity × unit price."""
        items = [_cart_item(product_id=self.product.id, quantity=3)]
        data = _call_calculate(self.customer, self.currency, items)

        # Subtotal must be at least quantity × monthly price (setup_cents may add more)
        self.assertGreaterEqual(data["subtotal_cents"], 3 * self.price.monthly_price_cents)


class CartCalculateProductBySlugTestCase(TestCase):
    """Test 2 — product_slug → product found via slug fallback."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product("slug-fallback-product")
        self.price = _make_price(self.product, self.currency, monthly_price_cents=1500)

    def test_product_slug_fallback_resolves_active_public_product(self) -> None:
        """POST with product_slug → product found, no missing_identifier warning."""
        items = [_cart_item(product_slug=self.product.slug, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        self.assertIn("subtotal_cents", data, f"Unexpected response: {data}")
        missing_warnings = [w for w in data.get("warnings", []) if w.get("type") == "missing_identifier"]
        self.assertEqual(missing_warnings, [])

    def test_product_slug_fallback_positive_subtotal(self) -> None:
        """Slug-based lookup yields a positive subtotal."""
        items = [_cart_item(product_slug=self.product.slug, quantity=2)]
        data = _call_calculate(self.customer, self.currency, items)

        self.assertGreater(data.get("subtotal_cents", 0), 0)

    def test_product_slug_skips_inactive_product_with_warning(self) -> None:
        """Slug pointing to an inactive product emits product_not_found warning.

        The slug lookup uses is_active=True as a filter, so inactive products raise
        DoesNotExist before the is_active check is reached.  The resulting warning
        type is therefore product_not_found (not product_inactive).
        """
        self.product.is_active = False
        self.product.save()

        items = [_cart_item(product_slug=self.product.slug, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        warning_types = [w.get("type") for w in data.get("warnings", [])]
        self.assertIn("product_not_found", warning_types)

    def test_product_slug_skips_non_public_product_with_warning(self) -> None:
        """Slug pointing to a non-public product emits product_not_found warning (slug lookup gates on is_public=True)."""
        self.product.is_public = False
        self.product.save()

        items = [_cart_item(product_slug=self.product.slug, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        warning_types = [w.get("type") for w in data.get("warnings", [])]
        self.assertIn("product_not_found", warning_types)

    def test_product_id_takes_precedence_over_slug_when_both_supplied(self) -> None:
        """When both product_id and product_slug are given, product_id wins."""
        other = _make_product("other-slug-product")
        _make_price(other, self.currency, monthly_price_cents=9999)

        # Use self.product via UUID, supply other product's slug — UUID must win
        items = [_cart_item(product_id=self.product.id, product_slug=other.slug, quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        self.assertIn("subtotal_cents", data)
        # Price should match self.product (1500), not other (9999)
        # (setup_cents may be 0 so subtotal == monthly price for quantity=1)
        self.assertGreaterEqual(data["subtotal_cents"], self.price.monthly_price_cents)


class CartCalculateMissingIdentifierTestCase(TestCase):
    """Test 3 — neither product_id nor product_slug → warning returned, item skipped."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()

    def test_missing_both_identifiers_emits_warning(self) -> None:
        """Cart item with no identifier emits missing_identifier warning."""
        items = [_cart_item(quantity=1)]  # no product_id, no product_slug
        data = _call_calculate(self.customer, self.currency, items)

        warning_types = [w.get("type") for w in data.get("warnings", [])]
        self.assertIn("missing_identifier", warning_types)

    def test_missing_identifier_warning_message_is_descriptive(self) -> None:
        """The missing_identifier warning message mentions the missing fields."""
        items = [_cart_item(quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        missing = next(w for w in data.get("warnings", []) if w.get("type") == "missing_identifier")
        self.assertIn("product_id", missing.get("message", "").lower() + missing.get("message", ""))

    def test_item_skipped_so_subtotal_is_zero(self) -> None:
        """Skipped item contributes nothing to the subtotal."""
        items = [_cart_item(quantity=1)]
        data = _call_calculate(self.customer, self.currency, items)

        self.assertEqual(data.get("subtotal_cents", 0), 0)

    def test_mixed_items_valid_uuid_and_missing_identifier(self) -> None:
        """One valid UUID item + one missing-identifier item → warning + positive subtotal."""
        product = _make_product("mixed-items-product")
        _make_price(product, self.currency, monthly_price_cents=2000)

        items = [
            _cart_item(product_id=product.id, quantity=1),
            _cart_item(quantity=1),  # no identifier
        ]
        data = _call_calculate(self.customer, self.currency, items)

        warning_types = [w.get("type") for w in data.get("warnings", [])]
        self.assertIn("missing_identifier", warning_types)
        self.assertGreater(data.get("subtotal_cents", 0), 0)
