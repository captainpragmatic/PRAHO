"""
Tests for remaining chaos monkey fixes (M8, L4, L5).

Covers:
  M8: Platform fallback must use requires_domain=True (fail-safe)
  L4: Cart item removal dispatches cartUpdated only once (no duplicate POST)
  L5: VAT rate templates use dynamic value without hardcoded default

No database access — all tests use SimpleTestCase + locmem cache.
"""

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.test import SimpleTestCase, override_settings

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}


# ---------------------------------------------------------------------------
# M8: Platform fallback must use requires_domain=True (fail-safe)
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestPlatformFallbackFailSafe(SimpleTestCase):
    """M8: During Platform outage, product fallback must assume domain is required."""

    def setUp(self) -> None:
        self.session = SessionStore()
        self.session.create()

    def test_fallback_requires_domain_true(self) -> None:
        """When Platform API is down, fallback product_data sets requires_domain=True."""
        from apps.api_client.services import PlatformAPIError  # noqa: PLC0415
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.side_effect = PlatformAPIError("Service unavailable")
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(self.session)

            # Without a domain_name, adding should raise ValidationError
            # because fallback now defaults to requires_domain=True
            from django.core.exceptions import ValidationError  # noqa: PLC0415

            with self.assertRaises(ValidationError) as ctx:
                cart.add_item(product_slug="hosting-plan", quantity=1, billing_period="monthly")

            self.assertIn("domain", str(ctx.exception).lower())

    def test_fallback_with_domain_succeeds(self) -> None:
        """When Platform API is down but domain_name is provided, add_item succeeds."""
        from apps.api_client.services import PlatformAPIError  # noqa: PLC0415
        from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

        with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.get.side_effect = PlatformAPIError("Service unavailable")
            mock_cls.return_value = mock_instance

            cart = GDPRCompliantCartSession(self.session)
            cart.add_item(
                product_slug="hosting-plan",
                quantity=1,
                billing_period="monthly",
                domain_name="example.com",
            )

            items = cart.get_items()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["product_slug"], "hosting-plan")


# ---------------------------------------------------------------------------
# L4: Cart remove button must not duplicate calculate_totals POST
# ---------------------------------------------------------------------------


class TestCartRemoveNoDuplicatePost(SimpleTestCase):
    """L4: Remove button should dispatch cartUpdated only, not also inline htmx.ajax()."""

    def test_remove_button_has_no_inline_calculate_totals(self) -> None:
        """cart_review.html remove button must not contain inline calculate_totals call."""
        template_path = Path(__file__).resolve().parents[2] / "templates" / "orders" / "cart_review.html"
        content = template_path.read_text()

        # Find the remove button line
        for line in content.splitlines():
            if "remove_from_cart" in line and "hx-post" in line:
                # Should have cartUpdated dispatch
                self.assertIn("cartUpdated", line)
                # Should NOT have inline calculate_totals (that's handled by the global listener)
                self.assertNotIn("calculate_totals", line)
                break
        else:
            self.fail("Remove button not found in cart_review.html")


# ---------------------------------------------------------------------------
# L5: VAT rate templates must not hardcode default:"21"
# ---------------------------------------------------------------------------


class TestVatRateNoHardcodedDefault(SimpleTestCase):
    """L5: Templates must use dynamic vat_rate_percent without hardcoded '21' default."""

    TEMPLATE_PATHS: ClassVar[list[str]] = [
        "templates/orders/order_confirmation.html",
        "templates/orders/checkout.html",
        "templates/orders/partials/cart_totals.html",
    ]

    def test_no_hardcoded_vat_default_in_templates(self) -> None:
        """No template should contain |default:"21" for vat_rate_percent."""
        portal_root = Path(__file__).resolve().parents[2]

        for rel_path in self.TEMPLATE_PATHS:
            template_path = portal_root / rel_path
            if template_path.exists():
                content = template_path.read_text()
                self.assertNotIn(
                    '|default:"21"',
                    content,
                    f'{rel_path} still contains hardcoded VAT default',
                )
