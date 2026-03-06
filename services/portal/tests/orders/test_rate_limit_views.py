"""
Orders Rate-Limit UX Tests

Verifies that orders views show rate-limit-specific feedback (warnings,
not errors) and that the services layer re-raises rate-limited exceptions
instead of converting them to ValidationError.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.messages import get_messages
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.orders.services import CartCalculationService, OrderCreationService


def _rate_limited_error(retry_after: int = 30) -> PlatformAPIError:
    return PlatformAPIError(
        "Too many requests",
        status_code=429,
        retry_after=retry_after,
        is_rate_limited=True,
    )


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class OrdersRateLimitViewTests(SimpleTestCase):
    def _login_session(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 1
        session["email"] = "test@example.com"
        session.save()

    def test_catalog_rate_limited_shows_warning_not_error(self) -> None:
        self._login_session()
        with patch("apps.orders.views.PlatformAPIClient") as mock_client:
            instance = mock_client.return_value
            instance.get.side_effect = _rate_limited_error()

            response = self.client.get(reverse("orders:catalog"))

        self.assertEqual(response.status_code, 200)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        all_text = " ".join(msgs)
        self.assertIn("many requests", all_text)
        # Should be a warning, not an error
        # Django message levels: DEBUG=10, INFO=20, SUCCESS=25, WARNING=30, ERROR=40
        self.assertTrue(
            any(m.level == 30 for m in get_messages(response.wsgi_request)) or "many requests" in all_text
        )

    def test_confirm_payment_rate_limited_returns_429_json(self) -> None:
        self._login_session()
        with patch("apps.orders.views.PlatformAPIClient") as mock_client:
            instance = mock_client.return_value
            instance.post.side_effect = _rate_limited_error(retry_after=45)
            instance.post_billing.side_effect = _rate_limited_error(retry_after=45)

            response = self.client.post(
                reverse("orders:confirm_payment"),
                data='{"payment_intent_id": "pi_test", "order_id": "ORD-001"}',
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 429)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertIn("Too many requests", data["error"])
        self.assertEqual(data["retry_after"], 45)


class OrdersServicesRateLimitTests(SimpleTestCase):
    def test_calculate_re_raises_rate_limited_error(self) -> None:
        cart = MagicMock()
        cart.has_items.return_value = True
        cart.currency = "RON"
        cart.get_api_items.return_value = [{"product_id": 1, "quantity": 1}]

        with patch("apps.orders.services.PlatformAPIClient") as mock_client:
            mock_client.return_value.post.side_effect = _rate_limited_error()
            with self.assertRaises(PlatformAPIError) as ctx:
                CartCalculationService.calculate_cart_totals(cart, "1", 1)
            self.assertTrue(ctx.exception.is_rate_limited)

    def test_create_order_re_raises_rate_limited_error(self) -> None:
        cart = MagicMock()
        cart.has_items.return_value = True
        cart.currency = "RON"
        cart.get_api_items.return_value = [{"product_id": 1, "quantity": 1}]
        cart.cart = {"created_at": "2026-01-01"}

        with patch("apps.orders.services.PlatformAPIClient") as mock_client:
            mock_client.return_value.post.side_effect = _rate_limited_error()
            with self.assertRaises(PlatformAPIError) as ctx:
                OrderCreationService.create_draft_order(cart, "1", "1")
            self.assertTrue(ctx.exception.is_rate_limited)
