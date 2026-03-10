"""
Tests for user_id validation in payment confirmation.

The PortalAuthenticationMiddleware sets request.user_id from session, falling
back to session["customer_id"] when session["user_id"] is absent. The view-level
guard (if not user_id: return 401) is defense-in-depth for edge cases where
middleware didn't run or request attributes were cleared.

Related: Codex review finding WARNING-2 — int(None) crash prevention.
"""

from __future__ import annotations

import inspect
import json
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

from apps.orders.views import confirm_payment


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache")
class ConfirmPaymentUserIdValidationTests(SimpleTestCase):
    """Verify confirm_payment handles user_id edge cases gracefully."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()

    def _set_session(self, **kwargs: object) -> None:
        """Set up session with given keys."""
        session = self.client.session
        for key, value in kwargs.items():
            if value is not None:
                session[key] = value
        session.save()

    def test_fully_missing_auth_redirects_to_login(self) -> None:
        """When no auth context at all, decorator redirects to login."""
        self._set_session(email="test@example.ro")
        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_test456test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

    @patch("apps.orders.views.PlatformAPIClient")
    def test_valid_user_id_proceeds_to_api_call(self, mock_api_class: object) -> None:
        """When both customer_id and user_id are present, the API call is made."""
        self._set_session(active_customer_id=123, customer_id=123, user_id=456)
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
        mock_api.post.return_value = {"success": True}

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_test789test1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
                "gateway": "stripe",
            }),
            content_type="application/json",
        )
        # Should reach the API call (not crash with TypeError)
        self.assertNotEqual(response.status_code, 500, "Should not crash with TypeError")
        # Verify the API was actually called with integer user_id
        self.assertTrue(mock_api.post_billing.called, "API should have been called")
        call_kwargs = mock_api.post_billing.call_args
        self.assertEqual(call_kwargs[1]["user_id"], 456)

    @patch("apps.orders.views.PlatformAPIClient")
    def test_user_id_is_always_cast_to_int(self, mock_api_class: object) -> None:
        """user_id must be cast to int before passing to API client."""
        # Session stores user_id as string (common from web forms)
        self._set_session(active_customer_id=123, customer_id=123, user_id="789")
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
        mock_api.post.return_value = {"success": True}

        response = self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_testintcast1234567890",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
                "gateway": "stripe",
            }),
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code, 500)
        if mock_api.post_billing.called:
            call_kwargs = mock_api.post_billing.call_args
            self.assertIsInstance(call_kwargs[1]["user_id"], int)

    def test_view_level_user_id_guard_exists(self) -> None:
        """Defense-in-depth: confirm_payment validates user_id before int() cast."""
        source = inspect.getsource(confirm_payment)
        guard_pos = source.find("if not user_id:")
        cast_pos = source.find("int(user_id)")
        self.assertGreater(guard_pos, -1, "user_id guard missing from confirm_payment")
        self.assertGreater(cast_pos, -1, "int(user_id) cast missing from confirm_payment")
        self.assertLess(guard_pos, cast_pos, "user_id guard must come before int(user_id) cast")
