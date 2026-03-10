"""
DoS hardening and idempotency tests for order creation and payment confirmation.

Covers:
  H5: _create_and_process_order must run OrderSecurityHardening checks
  H6: confirm_payment must use cache.add() idempotency guard

No database access — all tests use SimpleTestCase + locmem cache.
"""

import json
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

_CACHE_SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
}


def _make_product_data(slug: str = "shared-hosting-basic") -> dict:
    return {
        "id": "prod-uuid-001",
        "slug": slug,
        "name": "Shared Hosting Basic",
        "product_type": "hosting",
        "requires_domain": False,
        "is_active": True,
    }


def _auth_session_with_cart(client: Client) -> str:
    """Populate session with auth + one cart item; return cart version."""
    session = client.session
    session["customer_id"] = 42
    session["user_id"] = 7
    session.save()

    from apps.orders.services import GDPRCompliantCartSession  # noqa: PLC0415

    with patch("apps.orders.services.PlatformAPIClient") as mock_cls:
        mock_instance = MagicMock()
        mock_instance.get.return_value = _make_product_data()
        mock_cls.return_value = mock_instance
        cart = GDPRCompliantCartSession(session)
        cart.add_item(product_slug="shared-hosting-basic", quantity=1, billing_period="monthly")

    session.save()
    return cart.get_cart_version()


# ---------------------------------------------------------------------------
# H5: DoS hardening in _create_and_process_order
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestOrderCreationDoSHardening(SimpleTestCase):
    """_create_and_process_order must run security checks before processing."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def test_cache_failure_blocks_order_creation(self) -> None:
        """When cache is unavailable, order creation is blocked (fail closed)."""
        _auth_session_with_cart(self.client)

        with patch(
            "apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure"
        ) as mock_cache_check:
            mock_response = MagicMock()
            mock_response.status_code = 503
            mock_cache_check.return_value = mock_response

            response = self.client.post(
                "/order/create/",
                {"agree_terms": "on", "cart_version": "dummy"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Should redirect to checkout, not proceed with order creation
        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_oversized_request_blocks_order_creation(self) -> None:
        """Oversized requests are rejected before order processing."""
        _auth_session_with_cart(self.client)

        with patch(
            "apps.orders.views.OrderSecurityHardening.validate_request_size"
        ) as mock_size:
            mock_response = MagicMock()
            mock_response.status_code = 413
            mock_size.return_value = mock_response

            response = self.client.post(
                "/order/create/",
                {"agree_terms": "on", "cart_version": "dummy"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_suspicious_patterns_block_order_creation(self) -> None:
        """Suspicious field patterns are rejected before order processing."""
        _auth_session_with_cart(self.client)

        with patch(
            "apps.orders.views.OrderSecurityHardening.check_suspicious_patterns"
        ) as mock_patterns:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_patterns.return_value = mock_response

            response = self.client.post(
                "/order/create/",
                {"agree_terms": "on", "cart_version": "dummy"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/checkout/", response["Location"])

    def test_clean_request_proceeds_past_security(self) -> None:
        """When all security checks pass, order creation proceeds normally."""
        cart_version = _auth_session_with_cart(self.client)

        with (
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.OrderCreationService.preflight_order") as mock_pre,
            patch("apps.orders.views.OrderCreationService.create_draft_order") as mock_create,
        ):
            mock_pre.return_value = {"valid": True, "errors": [], "warnings": []}
            mock_create.return_value = {
                "order": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "order_number": "ORD-2026-42-0001",
                    "status": "pending",
                },
            }

            response = self.client.post(
                "/order/create/",
                {"agree_terms": "on", "cart_version": cart_version, "payment_method": "bank_transfer"},
                HTTP_X_FORWARDED_FOR="127.0.0.1",
            )

        # Should redirect to confirmation, not checkout (meaning security passed)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/order/confirmation/", response["Location"])


# ---------------------------------------------------------------------------
# H6: Idempotency guard in confirm_payment
# ---------------------------------------------------------------------------


@override_settings(**_CACHE_SETTINGS)
class TestConfirmPaymentIdempotency(SimpleTestCase):
    """confirm_payment must use cache.add() to prevent double-processing."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_duplicate_confirm_payment_returns_already_processing(self) -> None:
        """Second confirm_payment call with same PI returns idempotent response."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        # Pre-populate the idempotency cache key
        cache.set("confirm_payment:42:pi_test_123", "processing", timeout=300)

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_test_123",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "already_processing")

    @patch("apps.orders.views.PlatformAPIClient")
    def test_first_confirm_payment_proceeds(self, mock_api_class: object) -> None:
        """First confirm_payment call sets cache key and proceeds to API."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
        mock_api.post.return_value = {"success": True}

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_unique_456",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["success"])
        # Verify the idempotency key was set in cache
        self.assertEqual(cache.get("confirm_payment:42:pi_unique_456"), "processing")

    def test_different_payment_intents_not_blocked(self) -> None:
        """Different payment_intent_ids are processed independently."""
        self._set_session(active_customer_id=42, customer_id=42, user_id=7)

        # Pre-populate idempotency key for a different PI
        cache.set("confirm_payment:42:pi_other", "processing", timeout=300)

        with patch("apps.orders.views.PlatformAPIClient") as mock_api_class:
            mock_api = mock_api_class.return_value
            mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
            mock_api.post.return_value = {"success": True}

            response = self.client.post(
                "/order/confirm-payment/",
                data=json.dumps({
                    "payment_intent_id": "pi_different_789",
                    "order_id": "550e8400-e29b-41d4-a716-446655440000",
                }),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["success"])
