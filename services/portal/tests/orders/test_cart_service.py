"""
Cart Service — product_id / get_api_items Tests

Verifies that CartService (GDPRCompliantCartSession):
  - Stores product_id from the platform API response in the cart item.
  - get_api_items() returns both product_id and product_slug keys.

No database access — session-backed with locmem cache.
"""

import unittest
from unittest.mock import patch, MagicMock

from django.test import SimpleTestCase, override_settings
from django.contrib.sessions.backends.cache import SessionStore

from apps.orders.services import GDPRCompliantCartSession


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class CartServiceProductIdTestCase(SimpleTestCase):
    """Test that add_item stores product_id from platform product data."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def _make_mock_api(self, product_id: object = 'prod-uuid-001') -> MagicMock:
        """Return a mock PlatformAPIClient whose .get() yields a valid product."""
        mock_instance = MagicMock()
        mock_instance.get.return_value = {
            'id': product_id,
            'slug': 'shared-hosting-basic',
            'name': 'Shared Hosting Basic',
            'product_type': 'hosting',
            'requires_domain': False,
            'is_active': True,
        }
        return mock_instance

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_stores_product_id_from_api(self, mock_cls: MagicMock) -> None:
        """add_item() records product_id from the platform response in the cart item."""
        mock_cls.return_value = self._make_mock_api(product_id='prod-uuid-001')

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertIn('product_id', items[0])
        self.assertEqual(items[0]['product_id'], 'prod-uuid-001')

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_stores_product_slug(self, mock_cls: MagicMock) -> None:
        """add_item() also records product_slug for display and cart operations."""
        mock_cls.return_value = self._make_mock_api()

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertEqual(items[0]['product_slug'], 'shared-hosting-basic')

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_product_id_is_integer(self, mock_cls: MagicMock) -> None:
        """add_item() stores integer product_id (as returned by real platform API)."""
        mock_cls.return_value = self._make_mock_api(product_id=42)

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertEqual(items[0]['product_id'], 42)


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class CartServiceGetApiItemsTestCase(SimpleTestCase):
    """Test that get_api_items() returns both product_id and product_slug."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def _seed_cart_item(
        self,
        cart: GDPRCompliantCartSession,
        product_id: object = 'prod-001',
        product_slug: str = 'shared-hosting-basic',
    ) -> None:
        """Directly insert an item dict into the cart bypassing API calls."""
        cart.cart['items'].append({
            'item_id': 'abc123',
            'product_id': product_id,
            'product_slug': product_slug,
            'product_name': 'Shared Hosting Basic',
            'quantity': 1,
            'billing_period': 'monthly',
            'domain_name': '',
            'config': {},
            'added_at': '2026-01-01T00:00:00+00:00',
        })

    def test_get_api_items_returns_product_id_key(self) -> None:
        """get_api_items() output includes the 'product_id' key."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_cart_item(cart, product_id='prod-001')

        api_items = cart.get_api_items()

        self.assertEqual(len(api_items), 1)
        self.assertIn('product_id', api_items[0])
        self.assertEqual(api_items[0]['product_id'], 'prod-001')

    def test_get_api_items_returns_product_slug_key(self) -> None:
        """get_api_items() output includes the 'product_slug' key."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_cart_item(cart, product_slug='shared-hosting-basic')

        api_items = cart.get_api_items()

        self.assertIn('product_slug', api_items[0])
        self.assertEqual(api_items[0]['product_slug'], 'shared-hosting-basic')

    def test_get_api_items_returns_both_keys_together(self) -> None:
        """get_api_items() returns both product_id AND product_slug in the same item dict."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_cart_item(cart, product_id=99, product_slug='vps-standard')

        api_items = cart.get_api_items()

        item = api_items[0]
        self.assertIn('product_id', item)
        self.assertIn('product_slug', item)
        self.assertEqual(item['product_id'], 99)
        self.assertEqual(item['product_slug'], 'vps-standard')

    def test_get_api_items_empty_cart_returns_empty_list(self) -> None:
        """get_api_items() on an empty cart returns an empty list."""
        cart = GDPRCompliantCartSession(self.session)
        self.assertEqual(cart.get_api_items(), [])

    def test_get_api_items_multiple_items_all_have_required_keys(self) -> None:
        """All items returned by get_api_items() have both product_id and product_slug."""
        cart = GDPRCompliantCartSession(self.session)
        self._seed_cart_item(cart, product_id='p1', product_slug='product-one')
        self._seed_cart_item(cart, product_id='p2', product_slug='product-two')
        # second item needs a different item_id to avoid collision
        cart.cart['items'][1]['item_id'] = 'def456'

        api_items = cart.get_api_items()

        self.assertEqual(len(api_items), 2)
        for item in api_items:
            with self.subTest(item=item):
                self.assertIn('product_id', item)
                self.assertIn('product_slug', item)

    def test_get_api_items_missing_product_id_defaults_to_empty_string(self) -> None:
        """If an old cart item lacks product_id, get_api_items() defaults to empty string."""
        cart = GDPRCompliantCartSession(self.session)
        # Insert an item without product_id (legacy format)
        cart.cart['items'].append({
            'item_id': 'legacy-001',
            'product_slug': 'old-product',
            'product_name': 'Old Product',
            'quantity': 1,
            'billing_period': 'monthly',
            'domain_name': '',
            'config': {},
            'added_at': '2026-01-01T00:00:00+00:00',
        })

        api_items = cart.get_api_items()

        self.assertEqual(len(api_items), 1)
        self.assertEqual(api_items[0]['product_id'], '')
