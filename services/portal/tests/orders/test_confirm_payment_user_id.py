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

    @patch("apps.orders.views.PlatformAPIClient")
    def test_confirm_payload_excludes_payment_status(self, mock_api_class: object) -> None:
        """#104 [H11]: the confirm POST body must not carry payment_status.

        The platform deliberately never reads it (it re-retrieves the PaymentIntent
        from Stripe), so sending our copy made the field look like a trusted input.
        This is the behavioral discriminator for the removal — asserted on the actual
        payload the API client receives, so re-adding the field fails HERE even
        though the platform would keep ignoring it.
        """
        self._set_session(active_customer_id=123, customer_id=123, user_id=456)
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "succeeded"}
        mock_api.post.return_value = {"success": True}

        self.client.post(
            "/order/confirm-payment/",
            data=json.dumps({
                "payment_intent_id": "pi_testNoStatus123456789",
                "order_id": "550e8400-e29b-41d4-a716-446655440000",
                "gateway": "stripe",
            }),
            content_type="application/json",
        )

        self.assertTrue(mock_api.post.called, "confirm call should have been made")
        confirm_path, confirm_payload = mock_api.post.call_args[0][0], mock_api.post.call_args[0][1]
        self.assertIn("/confirm/", confirm_path)
        self.assertIn("payment_intent_id", confirm_payload)  # anchor: right call inspected
        self.assertNotIn("payment_status", confirm_payload)

    def test_confirm_payment_source_never_sends_payment_status(self) -> None:
        """Source-level second layer for the same H11 property (see test above).

        confirm_payment is a plain Django view, so inspect.getsource works here —
        unlike the platform's DRF @api_view-wrapped receiver. Quoted-form matching
        skips the bare-identifier local variable that legitimately drives the
        portal's own success branch.
        """
        source = inspect.getsource(confirm_payment)
        self.assertNotIn('"payment_status"', source)
        self.assertNotIn("'payment_status'", source)

    def test_view_level_user_id_guard_exists(self) -> None:
        """Defense-in-depth: confirm_payment validates user_id before int() cast."""
        source = inspect.getsource(confirm_payment)
        guard_pos = source.find("if not user_id:")
        cast_pos = source.find("int(user_id)")
        self.assertGreater(guard_pos, -1, "user_id guard missing from confirm_payment")
        self.assertGreater(cast_pos, -1, "int(user_id) cast missing from confirm_payment")
        self.assertLess(guard_pos, cast_pos, "user_id guard must come before int(user_id) cast")


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache")
class ConfirmPaymentIdempotencyKeyCleanupTests(SimpleTestCase):
    """A surviving idempotency key means the customer cannot retry a payment that just failed.

    The key is cleared in a `finally` so a retry is possible, and the delete used to run under
    `contextlib.suppress(Exception)` — correctly preventing a cache error from masking the response,
    but silently. A key that outlives its failed payment blocks the customer for the full 300-second
    timeout with nothing in the logs to explain it.
    """

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()
        session = self.client.session
        for key, value in {"active_customer_id": 123, "customer_id": 123, "user_id": 456}.items():
            session[key] = value
        session.save()

    def _payload(self, intent: str) -> str:
        return json.dumps({
            "payment_intent_id": intent,
            "order_id": "550e8400-e29b-41d4-a716-446655440000",
            "gateway": "stripe",
        })

    @patch("apps.orders.views.PlatformAPIClient")
    def test_a_failed_cleanup_is_logged_rather_than_swallowed(self, mock_api_class: object) -> None:
        """Revert the fix and this fails: the suppression left no trace of a stuck customer."""
        mock_api = mock_api_class.return_value
        # A payment that did not complete: the view returns 400 and the `finally` clears the key.
        mock_api.post_billing.return_value = {"success": True, "status": "requires_payment_method"}
        mock_api.post.return_value = {"success": True}

        # Selective on purpose. This suite runs with the CACHE session backend, so a blanket patch of
        # `cache.delete` also breaks `session.flush()` in `apps/users/middleware.py` and the error
        # escapes from there instead of from the site under test.
        real_delete = cache.delete

        def fail_only_for_the_idempotency_key(key: str, *args: object, **kwargs: object) -> bool:
            if str(key).startswith("confirm_payment:"):
                raise RuntimeError("cache backend gone")
            return real_delete(key, *args, **kwargs)

        with (
            patch("apps.orders.views.cache.delete", side_effect=fail_only_for_the_idempotency_key),
            self.assertLogs("apps.orders.views", level="WARNING") as logs,
        ):
            response = self.client.post(
                "/order/confirm-payment/", data=self._payload("pi_cleanupfail12345678"),
                content_type="application/json",
            )

        self.assertTrue(
            any("Could not clear idempotency key" in line for line in logs.output),
            f"a failed cleanup must say the customer may be unable to retry; got {logs.output}",
        )
        # And the cache error must not have replaced the view's own answer.
        self.assertEqual(response.status_code, 400)

    @patch("apps.orders.views.PlatformAPIClient")
    def test_a_successful_cleanup_logs_no_warning_about_the_key(self, mock_api_class: object) -> None:
        """The other direction, so the assertion above cannot pass by always logging."""
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "requires_payment_method"}
        mock_api.post.return_value = {"success": True}

        response = self.client.post(
            "/order/confirm-payment/", data=self._payload("pi_cleanupok123456789"),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        # The key is gone, so an immediate retry is not blocked as a duplicate.
        self.assertIsNone(cache.get("confirm_payment:123:pi_cleanupok123456789"))
