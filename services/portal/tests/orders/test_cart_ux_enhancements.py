"""
Tests for ENH-1: Better-tier add-to-cart UX improvements.

Covers:
  ENH-1-A: add_to_cart view sets HX-Trigger: cartAdded header on success
  ENH-1-B: add_to_cart view passes product_slug to cart_updated.html context
  ENH-1-C: mini_cart_content view accepts ?just_added=<slug> query param
  ENH-1-D: mini_cart_content marks the just-added item with data-just-added attr

No database access — all tests use SimpleTestCase + locmem cache.
"""

import json
from unittest.mock import MagicMock, patch

from django.test import Client, SimpleTestCase, override_settings

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}


def _make_product_data(
    slug: str = "shared-hosting-basic",
    product_type: str = "hosting",
    requires_domain: bool = False,
) -> dict:
    return {
        "id": "prod-uuid-001",
        "slug": slug,
        "name": "Shared Hosting Basic",
        "product_type": product_type,
        "requires_domain": requires_domain,
        "is_active": True,
        "prices": [
            {
                "billing_period": "monthly",
                "billing_period_display": "Monthly",
                "monthly_price": "10.00",
                "setup_fee": "0.00",
                "has_annual_discount": False,
                "has_semiannual_discount": False,
            }
        ],
    }


def _auth_client_with_product_mocked(client: Client, slug: str = "shared-hosting-basic") -> None:
    """Configure client session with customer auth."""
    session = client.session
    session["customer_id"] = 42
    session["user_id"] = 7
    session.save()


# ---------------------------------------------------------------------------
# ENH-1-A / ENH-1-B: HX-Trigger header and product_slug in add_to_cart response
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestAddToCartHxTrigger(SimpleTestCase):
    """ENH-1-A/B: Successful add_to_cart returns HX-Trigger: cartAdded and includes product_slug."""

    def setUp(self) -> None:
        self.client = Client()
        _auth_client_with_product_mocked(self.client)

    def _post_add_to_cart(self, slug: str = "shared-hosting-basic") -> object:
        with (
            patch("apps.orders.views.PlatformAPIClient") as mock_cls,
            patch("apps.orders.services.PlatformAPIClient") as svc_mock_cls,
        ):
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data(slug=slug)
            mock_cls.return_value = mock_instance
            svc_mock_cls.return_value = mock_instance

            return self.client.post(
                "/order/cart/add/",
                {"product_slug": slug, "quantity": "1", "billing_period": "monthly"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

    def test_successful_add_sets_hx_trigger_header(self) -> None:
        """ENH-1-A: Successful add_to_cart response includes HX-Trigger header with cartAdded event."""
        response = self._post_add_to_cart()

        self.assertEqual(response.status_code, 200)
        self.assertIn("HX-Trigger", response)
        hx_trigger = response["HX-Trigger"]
        self.assertIn("cartAdded", hx_trigger)

    def test_hx_trigger_includes_product_slug(self) -> None:
        """ENH-1-B: HX-Trigger payload includes the slug of the just-added product."""

        slug = "shared-hosting-basic"
        response = self._post_add_to_cart(slug=slug)

        self.assertEqual(response.status_code, 200)
        hx_trigger_raw = response["HX-Trigger"]
        # Must be valid JSON with cartAdded key containing slug
        payload = json.loads(hx_trigger_raw)
        self.assertIn("cartAdded", payload)
        self.assertEqual(payload["cartAdded"]["slug"], slug)

    def test_error_response_does_not_set_hx_trigger(self) -> None:
        """ENH-1-A: Failed add_to_cart (e.g. missing product_slug) must NOT set HX-Trigger."""
        with (
            patch("apps.orders.views.PlatformAPIClient") as mock_cls,
            patch("apps.orders.services.PlatformAPIClient") as svc_mock_cls,
        ):
            mock_instance = MagicMock()
            mock_instance.get.side_effect = Exception("product not found")
            mock_cls.return_value = mock_instance
            svc_mock_cls.return_value = mock_instance

            response = self.client.post(
                "/order/cart/add/",
                {"product_slug": "nonexistent-product", "quantity": "1", "billing_period": "monthly"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertNotIn("HX-Trigger", response)


# ---------------------------------------------------------------------------
# ENH-1-C / ENH-1-D: mini_cart_content ?just_added param and data-just-added attr
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestMiniCartJustAdded(SimpleTestCase):
    """ENH-1-C/D: mini_cart_content marks the just-added item when ?just_added=<slug> is passed."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def _populate_cart(self, slug: str = "shared-hosting-basic") -> None:
        """Add one item to the client session cart (no network)."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        session = self.client.session
        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data(slug=slug)
            mock_cls.return_value = mock_instance
            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug=slug, quantity=1, billing_period="monthly")
        session.save()

    def test_just_added_item_has_data_attribute(self) -> None:
        """ENH-1-D: Item matching ?just_added=<slug> gets data-just-added in rendered HTML."""
        slug = "shared-hosting-basic"
        self._populate_cart(slug)

        response = self.client.get(f"/order/partials/mini-cart/?just_added={slug}")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('data-just-added="true"', content)

    def test_non_matching_item_lacks_data_attribute(self) -> None:
        """ENH-1-D: Items NOT matching the just_added slug do NOT get data-just-added."""
        slug = "shared-hosting-basic"
        self._populate_cart(slug)

        # Request with a different slug
        response = self.client.get("/order/partials/mini-cart/?just_added=other-product")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertNotIn('data-just-added="true"', content)

    def test_no_just_added_param_renders_normally(self) -> None:
        """ENH-1-C: Without ?just_added, mini_cart renders without any highlighting."""
        slug = "shared-hosting-basic"
        self._populate_cart(slug)

        response = self.client.get("/order/partials/mini-cart/")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertNotIn('data-just-added="true"', content)


# ---------------------------------------------------------------------------
# ENH-1: cart_updated template contains "View Cart" link
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestCartUpdatedToastViewCartLink(SimpleTestCase):
    """ENH-1-toast: cart_updated response includes a View Cart link to orders:cart_review."""

    def setUp(self) -> None:
        self.client = Client()
        _auth_client_with_product_mocked(self.client)

    def test_cart_updated_response_contains_view_cart_link(self) -> None:
        """The cart_updated HTMX response contains a link to cart review page."""
        with (
            patch("apps.orders.views.PlatformAPIClient") as mock_cls,
            patch("apps.orders.services.PlatformAPIClient") as svc_mock_cls,
        ):
            mock_instance = MagicMock()
            mock_instance.get.return_value = _make_product_data()
            mock_cls.return_value = mock_instance
            svc_mock_cls.return_value = mock_instance

            response = self.client.post(
                "/order/cart/add/",
                {"product_slug": "shared-hosting-basic", "quantity": "1", "billing_period": "monthly"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # View Cart link must be present in toast
        self.assertIn("/order/cart/", content)
