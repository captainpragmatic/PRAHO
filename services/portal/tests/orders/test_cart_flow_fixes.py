"""Regression tests for HTMX cart response/target alignment."""

from unittest.mock import MagicMock, patch

from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}

_PRODUCT_SLUG = "shared-hosting-basic"
_PRODUCT_DATA = {
    "id": "prod-uuid-001",
    "slug": _PRODUCT_SLUG,
    "name": "Shared Hosting Basic",
    "product_type": "hosting",
    "requires_domain": False,
    "is_active": True,
}
_CALCULATION_RESULT = {
    "items": [],
    "subtotal_cents": 2000,
    "tax_cents": 420,
    "total_cents": 2420,
    "currency": "RON",
    "vat_rate_percent": "21.00",
    "warnings": [],
}


@override_settings(**_CACHE_SETTINGS)
class TestCartFlowFixes(SimpleTestCase):
    """Cart mutation responses must match the HTMX elements they replace."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session.save()

    def _populate_cart(self) -> None:
        """Seed one real session-cart item while mocking only the platform API."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        session = self.client.session
        with patch("apps.orders.services.PlatformAPIClient") as mock_client_class:
            mock_client_class.return_value.get.return_value = _PRODUCT_DATA
            cart = GDPRCompliantCartSession(session)
            cart.add_item(product_slug=_PRODUCT_SLUG, quantity=1, billing_period="monthly")
        session.save()

    @patch(
        "apps.orders.views.CartCalculationService.calculate_cart_totals",
        return_value=_CALCULATION_RESULT,
    )
    def test_update_cart_item_returns_cart_totals_not_widget(self, _mock_calculate: MagicMock) -> None:
        self._populate_cart()

        response = self.client.post(
            reverse("orders:update_cart_item"),
            {
                "product_slug": _PRODUCT_SLUG,
                "billing_period": "monthly",
                "quantity": "2",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="cart-totals"', response.content)
        self.assertNotIn(b'id="cart-widget"', response.content)

    def test_add_to_cart_error_has_no_duplicate_cart_widget(self) -> None:
        with patch("apps.orders.services.PlatformAPIClient") as mock_client_class:
            mock_client_class.return_value.get.side_effect = RuntimeError("product lookup failed")

            response = self.client.post(
                reverse("orders:add_to_cart"),
                {
                    "product_slug": _PRODUCT_SLUG,
                    "billing_period": "monthly",
                    "quantity": "1",
                },
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn(b'id="cart-widget"', response.content)
