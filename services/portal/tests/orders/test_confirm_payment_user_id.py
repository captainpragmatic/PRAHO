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
import time
from unittest.mock import patch

from django.core.cache import cache
from django.db import InterfaceError
from django.test import Client, TestCase, override_settings

from apps.common import counters
from apps.orders.views import confirm_payment


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache")
class ConfirmPaymentUserIdValidationTests(TestCase):
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
        if session.get("customer_id") and session.get("user_id"):
            session["user_memberships"] = [{"customer_id": session["customer_id"], "role": "owner"}]
            session["user_memberships_fetched_at"] = time.time()
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
class ConfirmPaymentIdempotencyKeyCleanupTests(TestCase):
    """A surviving idempotency claim means the customer cannot retry a payment that just failed.

    Retargeted at the mechanism master introduced. The claim used to be a cache key cleared with
    `cache.delete` under `contextlib.suppress(Exception)`, and this class existed to prove that a
    failure is LOGGED rather than silently stranding the customer for the full 300-second timeout.
    Master replaced the cache with the DB-backed counter store, so the original subject is gone - the
    property is not, and it is asserted against `counters.release` here.

    `TestCase`, not `SimpleTestCase`: the counter store is a real table. The merge left
    `SimpleTestCase` with no import for it, so this module did not even collect - which is how the
    obsolescence was noticed rather than quietly passing against code that no longer runs.

    The injected failure is deliberately an `InterfaceError`, which pins something easy to break:
    `apps/orders/views.py` imports `from django.db import Error as DatabaseError`, so its
    `except DatabaseError` is really `except django.db.Error` and DOES cover `InterfaceError`.
    `django.db.Error` has exactly two direct subclasses and `InterfaceError` is NOT one of
    `DatabaseError`'s, so "tidying" that import to the real `DatabaseError` would let a dropped
    connection escape from a `finally` and mask the view's response. This test fails if anyone does.
    """

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session.update({
            "active_customer_id": 123,
            "customer_id": 123,
            "user_id": 456,
            # Memberships too, or the role guard answers 403 before the view runs: `common/decorators.py`
            # returns "Role not found" on a cold membership cache. Without these the POST never reaches
            # the `finally` under test, and the first symptom is "no ERROR logs triggered" - a failure
            # that looks like the logging is broken rather than the request being rejected.
            "user_memberships": [{"customer_id": 123, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def _payload(self, intent: str) -> str:
        return json.dumps({
            "payment_intent_id": intent,
            "order_id": "550e8400-e29b-41d4-a716-446655440000",
            "gateway": "stripe",
        })

    def _failed_payment(self, mock_api_class: object) -> None:
        """A payment that did not complete: the view answers 400 and the `finally` releases."""
        mock_api = mock_api_class.return_value
        mock_api.post_billing.return_value = {"success": True, "status": "requires_payment_method"}
        mock_api.post.return_value = {"success": True}

    @patch("apps.orders.views.PlatformAPIClient")
    def test_a_failed_release_is_logged_and_does_not_mask_the_response(self, mock_api_class: object) -> None:
        """Both halves matter: the log, so a stuck customer is explainable, and the 400, because this
        runs in a `finally` and an escaping error would replace the view's own answer."""
        self._failed_payment(mock_api_class)

        with (
            patch("apps.orders.views.counters.release", side_effect=InterfaceError("connection already closed")),
            self.assertLogs("apps.orders.views", level="ERROR") as logs,
        ):
            response = self.client.post(
                "/order/confirm-payment/", data=self._payload("pi_relfail1234567890"),
                content_type="application/json",
            )

        self.assertTrue(
            any("Failed to release payment claim" in line for line in logs.output),
            f"a failed release must say so; got {logs.output}",
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.orders.views.PlatformAPIClient")
    def test_a_successful_release_frees_the_claim_for_a_retry(self, mock_api_class: object) -> None:
        """The other direction, so the assertion above cannot pass by always logging."""
        self._failed_payment(mock_api_class)

        with self.assertNoLogs("apps.orders.views", level="ERROR"):
            response = self.client.post(
                "/order/confirm-payment/", data=self._payload("pi_relok12345678901"),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 400)
        # The claim is gone, so an immediate retry is not rejected as a duplicate.
        self.assertTrue(
            counters.claim("confirm_payment:123:pi_relok12345678901", 300, "retry"),
            "a failed payment must leave the claim free for a retry",
        )
