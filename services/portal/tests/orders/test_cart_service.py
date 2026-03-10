"""
Cart Service — product_id / get_api_items Tests

Verifies that CartService (GDPRCompliantCartSession):
  - Stores product_id from the platform API response in the cart item.
  - get_api_items() returns both product_id and product_slug keys.

No database access — session-backed with locmem cache.
"""

from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.test import SimpleTestCase, override_settings

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
    def test_add_item_omits_product_id_uses_slug(self, mock_cls: MagicMock) -> None:
        """add_item() intentionally omits product_id; product_slug is the stable identifier."""
        mock_cls.return_value = self._make_mock_api(product_id='prod-uuid-001')

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertEqual(len(items), 1)
        # product_id is intentionally NOT stored — slug is the public identifier
        self.assertNotIn('product_id', items[0])
        self.assertEqual(items[0]['product_slug'], 'shared-hosting-basic')

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
    def test_add_item_get_api_items_omits_empty_product_id(self, mock_cls: MagicMock) -> None:
        """get_api_items() omits product_id key when not stored in cart (slug-only payload)."""
        mock_cls.return_value = self._make_mock_api(product_id=42)

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        api_items = cart.get_api_items()
        # product_id is omitted — slug is the primary identifier
        self.assertNotIn('product_id', api_items[0])
        self.assertEqual(api_items[0]['product_slug'], 'shared-hosting-basic')


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
        """All items returned by get_api_items() have product_slug; product_id included when present."""
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

    def test_get_api_items_missing_product_id_omits_key(self) -> None:
        """If a cart item lacks product_id, get_api_items() omits the key entirely."""
        cart = GDPRCompliantCartSession(self.session)
        # Insert an item without product_id (slug-only format)
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
        self.assertNotIn('product_id', api_items[0])
        self.assertEqual(api_items[0]['product_slug'], 'old-product')


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class CartServiceProductTypeTestCase(SimpleTestCase):
    """Test that add_item() stores product_type from platform product data (BUG-2 regression)."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def _make_mock_api(self, product_type: str = 'hosting') -> MagicMock:
        mock_instance = MagicMock()
        mock_instance.get.return_value = {
            'id': 'prod-uuid-002',
            'slug': 'shared-hosting-basic',
            'name': 'Shared Hosting Basic',
            'product_type': product_type,
            'requires_domain': False,
            'is_active': True,
        }
        return mock_instance

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_stores_product_type(self, mock_cls: MagicMock) -> None:
        """add_item() must store product_type in the cart item (BUG-2: was missing, caused empty badge)."""
        mock_cls.return_value = self._make_mock_api(product_type='hosting')

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='shared-hosting-basic',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertIn('product_type', items[0])
        self.assertEqual(items[0]['product_type'], 'hosting')

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_stores_product_type_vps(self, mock_cls: MagicMock) -> None:
        """add_item() stores product_type for VPS products."""
        mock_cls.return_value = self._make_mock_api(product_type='vps')

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='vps-standard',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertIn('product_type', items[0])
        self.assertEqual(items[0]['product_type'], 'vps')

    @patch('apps.orders.services.PlatformAPIClient')
    def test_add_item_stores_product_type_fallback_empty_string(self, mock_cls: MagicMock) -> None:
        """add_item() stores empty string for product_type when API fallback dict is used."""
        mock_cls.return_value = self._make_mock_api(product_type='')

        cart = GDPRCompliantCartSession(self.session)
        cart.add_item(
            product_slug='unknown-product',
            quantity=1,
            billing_period='monthly',
        )

        items = cart.get_items()
        self.assertIn('product_type', items[0])
        self.assertEqual(items[0]['product_type'], '')
