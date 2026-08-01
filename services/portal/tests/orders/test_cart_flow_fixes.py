"""Regression tests for HTMX cart response/target alignment."""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.template.loader import render_to_string
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils.translation import override

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
_SECOND_PRODUCT_SLUG = "managed-vps"
_SECOND_PRODUCT_DATA = {
    "id": "prod-uuid-002",
    "slug": _SECOND_PRODUCT_SLUG,
    "name": "Managed VPS",
    "product_type": "vps",
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

    def _populate_cart(self, *, include_second: bool = False) -> None:
        """Seed real session-cart items while mocking only the platform API."""
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        products = [(_PRODUCT_SLUG, _PRODUCT_DATA)]
        if include_second:
            products.append((_SECOND_PRODUCT_SLUG, _SECOND_PRODUCT_DATA))

        session = self.client.session
        with patch("apps.orders.services.PlatformAPIClient") as mock_client_class:
            mock_client_class.return_value.get.side_effect = [product_data for _, product_data in products]
            cart = GDPRCompliantCartSession(session)
            for product_slug, _ in products:
                cart.add_item(product_slug=product_slug, quantity=1, billing_period="monthly")
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

    def test_error_message_labels_localized(self) -> None:
        with override("en"):
            english_output = render_to_string("orders/partials/error_message.html", {"error": "boom"})

        self.assertIn("Error", english_output)
        self.assertNotIn("Eroare", english_output)
        self.assertNotIn("Închide notificarea", english_output)

        with override("ro"):
            romanian_output = render_to_string("orders/partials/error_message.html", {"error": "boom"})

        self.assertIn("Eroare", romanian_output)
        self.assertNotIn("Conversație", romanian_output)

    def test_remove_from_cart_review_rerenders_items_section(self) -> None:
        self._populate_cart(include_second=True)

        response = self.client.post(
            reverse("orders:remove_from_cart"),
            {
                "product_slug": _PRODUCT_SLUG,
                "billing_period": "monthly",
            },
            HTTP_HX_TARGET="cart-items",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="cart-items"', response.content)
        self.assertIn(_SECOND_PRODUCT_DATA["name"].encode(), response.content)
        self.assertNotIn(_PRODUCT_DATA["name"].encode(), response.content)
        self.assertNotIn(b'id="cart-widget"', response.content)

    def test_remove_last_item_shows_empty_state(self) -> None:
        self._populate_cart()

        response = self.client.post(
            reverse("orders:remove_from_cart"),
            {
                "product_slug": _PRODUCT_SLUG,
                "billing_period": "monthly",
            },
            HTTP_HX_TARGET="cart-items",
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Your cart is empty")
        self.assertNotIn(b'id="cart-widget"', response.content)

    def test_remove_from_cart_minicart_still_returns_widget(self) -> None:
        self._populate_cart()

        response = self.client.post(
            reverse("orders:remove_from_cart"),
            {
                "product_slug": _PRODUCT_SLUG,
                "billing_period": "monthly",
            },
            HTTP_HX_TARGET="cart-widget",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="cart-widget"', response.content)

    def test_cart_review_controls_rely_on_server_driven_error_toast(self) -> None:
        orders_templates = Path(__file__).resolve().parents[2] / "templates" / "orders"
        partial_path = orders_templates / "partials" / "cart_items.html"
        template_path = partial_path if partial_path.exists() else orders_templates / "cart_review.html"
        template_source = template_path.read_text()
        quantity_selects = re.findall(r'<select id="qty-.*?</select>', template_source, flags=re.DOTALL)
        remove_buttons = re.findall(
            r'<button hx-post="{% url \'orders:remove_from_cart\' %}".*?</button>',
            template_source,
            flags=re.DOTALL,
        )

        self.assertEqual(len(quantity_selects), 1)
        self.assertEqual(len(remove_buttons), 1)
        self.assertNotIn("hx-on::response-error", quantity_selects[0])
        self.assertNotIn("hx-on::response-error", remove_buttons[0])

    def test_base_wires_showtoast_htmx_event_once(self) -> None:
        portal_root = Path(__file__).resolve().parents[2]
        base_source = (portal_root / "templates" / "base.html").read_text()

        self.assertEqual(base_source.count("document.body.addEventListener('showToast'"), 1)
        self.assertIn("window.showToast(d.variant || 'error', d.message || '');", base_source)

    def test_remove_buttons_dispatch_cartupdated_only_after_success(self) -> None:
        partials_path = Path(__file__).resolve().parents[2] / "templates" / "orders" / "partials"
        template_paths = [partials_path / "cart_items.html", partials_path / "mini_cart_content.html"]
        remove_button_sites = [
            (template_path.name, line)
            for template_path in template_paths
            for line in template_path.read_text().splitlines()
            if "remove_from_cart" in line and "hx-post" in line
        ]

        self.assertEqual(len(remove_button_sites), 2)
        self.assertEqual(
            {template_name for template_name, _line in remove_button_sites},
            {"cart_items.html", "mini_cart_content.html"},
        )
        guarded_dispatch = (
            'hx-on::after-request="if(event.detail.successful){'
            "document.body.dispatchEvent(new CustomEvent('cartUpdated'));}"
            '"'
        )
        for template_name, remove_button in remove_button_sites:
            self.assertIn(guarded_dispatch, remove_button, template_name)

    def test_quantity_select_no_redundant_cartupdated_dispatch(self) -> None:
        orders_templates = Path(__file__).resolve().parents[2] / "templates" / "orders"
        partial_path = orders_templates / "partials" / "cart_items.html"
        template_path = partial_path if partial_path.exists() else orders_templates / "cart_review.html"
        template_source = template_path.read_text()

        quantity_selects = re.findall(r'<select id="qty-.*?</select>', template_source, flags=re.DOTALL)
        remove_buttons = re.findall(
            r'<button hx-post="{% url \'orders:remove_from_cart\' %}".*?</button>',
            template_source,
            flags=re.DOTALL,
        )

        self.assertEqual(len(quantity_selects), 1)
        self.assertEqual(quantity_selects[0].count("cartUpdated"), 0)
        self.assertEqual(len(remove_buttons), 1)
        self.assertEqual(remove_buttons[0].count("cartUpdated"), 1)

    def test_dead_cart_event_wiring_removed(self) -> None:
        portal_root = Path(__file__).resolve().parents[2]
        template_sources = [
            template_path.read_text()
            for template_path in (portal_root / "templates" / "orders").rglob("*.html")
        ]
        views_source = (portal_root / "apps" / "orders" / "views.py").read_text()

        self.assertEqual(sum(source.count("@cart-added") for source in template_sources), 0)
        self.assertEqual(views_source.count("cartAdded"), 0)
        self.assertEqual(sum(source.count("cart_total_quantity") for source in template_sources), 0)
        self.assertEqual(views_source.count('"cart_total_quantity"'), 0)
