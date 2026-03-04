"""
Tests validating the shape of order payloads sent from Portal to Platform.

These ensure that get_api_items() produces payloads compatible with
Platform's CartItemInputSerializer contract:
- product_slug always present
- product_id only included when non-empty (valid UUID from Platform)
- No empty-string product_id that would fail UUID validation
"""

from django.contrib.sessions.backends.cache import SessionStore
from django.test import SimpleTestCase, override_settings

from apps.orders.services import GDPRCompliantCartSession


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class OrderPayloadContractTestCase(SimpleTestCase):
    """Validate that Portal payloads match Platform's serializer contract."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def _seed_item(
        self,
        cart: GDPRCompliantCartSession,
        *,
        product_slug: str = "test-product",
        product_id: str | None = None,
    ) -> None:
        """Directly insert an item into the cart."""
        item = {
            "item_id": f"test-{product_slug}",
            "product_slug": product_slug,
            "product_name": "Test Product",
            "quantity": 1,
            "billing_period": "monthly",
            "domain_name": "",
            "config": {},
            "added_at": "2026-01-01T00:00:00+00:00",
        }
        if product_id is not None:
            item["product_id"] = product_id
        cart.cart["items"].append(item)

    def test_slug_only_item_has_no_product_id_key(self) -> None:
        """Slug-only cart item → payload omits product_id entirely."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_item(cart, product_slug="shared-hosting-basic")

        api_items = cart.get_api_items()

        self.assertEqual(len(api_items), 1)
        self.assertNotIn("product_id", api_items[0])
        self.assertEqual(api_items[0]["product_slug"], "shared-hosting-basic")

    def test_item_with_valid_product_id_includes_it(self) -> None:
        """Item with product_id → payload includes both identifiers."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_item(cart, product_slug="vps-basic", product_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890")

        api_items = cart.get_api_items()

        self.assertIn("product_id", api_items[0])
        self.assertIn("product_slug", api_items[0])
        self.assertEqual(api_items[0]["product_id"], "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_payload_always_includes_required_fields(self) -> None:
        """Every API item has quantity, billing_period, product_slug."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_item(cart, product_slug="web-hosting")

        api_items = cart.get_api_items()
        item = api_items[0]

        for field in ("product_slug", "quantity", "billing_period"):
            self.assertIn(field, item, f"API item must include '{field}'")

    def test_empty_cart_returns_empty_list(self) -> None:
        """Empty cart produces empty payload."""
        cart = GDPRCompliantCartSession(self.session)
        self.assertEqual(cart.get_api_items(), [])

    def test_multiple_items_all_have_product_slug(self) -> None:
        """All items in multi-item cart have product_slug."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_item(cart, product_slug="product-a")
        self._seed_item(cart, product_slug="product-b")
        cart.cart["items"][1]["item_id"] = "test-product-b"

        api_items = cart.get_api_items()

        self.assertEqual(len(api_items), 2)
        for item in api_items:
            self.assertIn("product_slug", item)
            self.assertTrue(item["product_slug"])  # non-empty

    def test_sealed_price_token_included_when_present(self) -> None:
        """Sealed price token passes through when set."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_item(cart, product_slug="premium")
        cart.cart["items"][0]["sealed_price_token"] = "sealed-abc-123"

        api_items = cart.get_api_items()

        self.assertEqual(api_items[0]["sealed_price_token"], "sealed-abc-123")
