"""An uncertain create response must not become a second purchase after repricing."""

import time
from copy import deepcopy
from unittest.mock import Mock, patch

from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.db import DatabaseError
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.orders.services import GDPRCompliantCartSession
from tests.orders.test_selling_currency import currency_changed, product, totals


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"],
)
class UncertainCheckoutRetryTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.api = Mock()
        self.api.get.return_value = product("RON", 1)
        self.api.post.side_effect = self.platform
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=self.api))
        self.enterContext(patch("apps.orders.views.PlatformAPIClient", return_value=self.api))
        counters = self.enterContext(patch("apps.orders.views.counters"))
        counters.lookup.return_value = None
        counters.claim.return_value = True
        counters.complete.return_value = True
        session = self.client.session
        session.update({
            "customer_id": 42, "user_id": 7,
            "user_memberships": [{"customer_id": 42, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        cart = GDPRCompliantCartSession(session)
        cart.add_item("basic-hosting", 1, "monthly")
        cart.set_coupon_codes(["ORIGINAL-OFFER"])
        session.save()
        self.form = {
            "cart_version": cart.get_cart_version(), "agree_terms": "on", "payment_method": "bank_transfer",
            "promotion_quote": "original-ron-quote", "notes": "Original purchase",
        }
        self.policy = ("RON", 1)
        self.remote_orders = {}
        self.create_requests = []
        self.events = []
        self.lose_next_response = True
        self.commit_before_timeout = True
        self.require_durable_attempt = False

    def platform(self, path, data, *, user_id):
        self.events.append(path)
        matches = (data["currency"], data["currency_revision"]) == self.policy
        if path == "orders/create/":
            if self.require_durable_attempt:
                self.assertTrue(self.client.session.get("order_checkout_attempts"), "Persist the attempt before API I/O")
            self.create_requests.append(deepcopy(data))
            key = data["idempotency_key"]
            if key in self.remote_orders:
                return {"success": True, "order": self.remote_orders[key], "duplicate": True}
            if not matches:
                raise currency_changed(*self.policy)
            order = {
                "id": "550e8400-e29b-41d4-a716-446655440099", "order_number": "ORIGINAL-ORDER",
                "status": "awaiting_payment", "currency_code": data["currency"], "total_cents": 12100,
            }
            if not self.lose_next_response or self.commit_before_timeout:
                self.remote_orders[key] = order
            if self.lose_next_response:
                self.lose_next_response = False
                raise PlatformAPIError("Lost create response", status_code=503)
            return {"success": True, "order": order}
        if not matches:
            raise currency_changed(*self.policy)
        if path == "orders/preflight/":
            return {"success": True, "errors": [], "warnings": []}
        if path == "orders/calculate/":
            return totals(*self.policy)
        raise AssertionError(f"Unexpected endpoint {path}")

    def submit(self):
        return self.client.post(reverse("orders:create_order"), self.form)

    def reprice(self):
        self.policy = ("EUR", 2)
        response = self.client.get(reverse("orders:cart_review"))
        self.assertEqual(response.status_code, 200)
        displayed_totals = self.client.post(reverse("orders:calculate_totals"), HTTP_HX_REQUEST="true")
        self.assertContains(displayed_totals, "EUR")
        cart = GDPRCompliantCartSession(self.client.session)
        self.assertEqual((cart.currency, cart.currency_revision), self.policy)
        return cart

    def test_accepted_order_is_recovered_before_preflight_after_currency_switch(self):
        self.assertEqual(self.submit().status_code, 302)
        self.assertEqual(len(self.remote_orders), 1)
        original = deepcopy(self.create_requests[0])
        repriced_cart = self.reprice()
        self.form.update(cart_version=repriced_cart.get_cart_version(), notes="Changed form", payment_method="card")
        self.events.clear()

        response = self.submit()

        self.assertEqual(len(self.remote_orders), 1, "Recover the accepted order instead of buying it again")
        self.assertEqual(response["Location"], "/order/confirmation/550e8400-e29b-41d4-a716-446655440099/")
        self.assertEqual(self.events, ["orders/create/"])
        self.assertEqual(self.create_requests, [original, original])
        self.assertEqual(len(self.remote_orders), 1)
        self.api.post_billing.assert_not_called()  # The original purchase chose bank transfer.

    def test_uncertain_request_is_persisted_before_create_transport(self):
        self.require_durable_attempt = True
        self.assertEqual(self.submit().status_code, 302)
        self.assertEqual(len(self.remote_orders), 1)
        self.assertTrue(self.client.session.get("order_checkout_attempts"))

    def test_policy_rejection_without_an_order_requires_a_separate_reviewed_submission(self):
        self.commit_before_timeout = False
        self.submit()
        original = deepcopy(self.create_requests[0])
        self.policy = ("EUR", 2)
        self.events.clear()

        rejected = self.submit()

        self.assertEqual(rejected["Location"], reverse("orders:checkout"))
        self.assertEqual(self.events, ["orders/create/"])
        self.assertEqual(self.create_requests, [original, original])
        self.assertFalse(self.remote_orders)
        self.assertFalse(self.client.session.get("order_checkout_attempts"))
        current_cart = self.reprice()
        self.form.update(cart_version=current_cart.get_cart_version(), promotion_quote="fresh-promotion-quote")
        accepted = self.submit()
        self.assertIn("/confirmation/", accepted["Location"])
        self.assertEqual(len(self.remote_orders), 1)
        self.assertNotEqual(self.create_requests[-1]["idempotency_key"], original["idempotency_key"])
        self.assertEqual(self.create_requests[-1]["currency"], "EUR")

    def test_an_unavailable_recovery_keeps_original_payload_for_the_next_retry(self):
        self.submit()
        original = deepcopy(self.create_requests[0])
        self.reprice()
        self.api.post.side_effect = PlatformAPIError("Still unavailable", status_code=503)
        self.submit()
        self.api.post.side_effect = self.platform
        recovered = self.submit()
        self.assertIn("/confirmation/", recovered["Location"])
        self.assertEqual(self.create_requests, [original, original])
        self.assertEqual(len(self.remote_orders), 1)

    def test_session_persistence_failure_cannot_send_an_unrecoverable_create(self):
        original_save = SessionStore.save
        failed = False

        def fail_first_attempt_save(session, *args, **kwargs):
            nonlocal failed
            if session.get("order_checkout_attempts") and not failed:
                failed = True
                raise DatabaseError("Session unavailable")
            return original_save(session, *args, **kwargs)

        with patch.object(SessionStore, "save", fail_first_attempt_save):
            response = self.submit()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(failed)
        self.assertEqual(self.events, ["orders/preflight/"])
        self.assertFalse(self.remote_orders)

    def test_other_session_user_cannot_replay_the_original_buyers_attempt(self):
        self.submit()
        session = self.client.session
        session["user_id"] = 8
        session.save()
        self.policy = ("EUR", 2)
        self.events.clear()
        self.submit()
        self.assertEqual(self.events, ["orders/preflight/"])
        self.assertEqual(len(self.create_requests), 1)
        session = self.client.session
        session["user_id"] = 7
        session.save()
        self.assertIn("/confirmation/", self.submit()["Location"])
        self.assertEqual(len(self.remote_orders), 1)

    def test_unknown_rejection_does_not_discard_a_possibly_accepted_purchase(self):
        self.submit()
        original = deepcopy(self.create_requests[0])
        for status in (400, 403, 429, 503):
            with self.subTest(status=status):
                self.api.post.side_effect = PlatformAPIError("Request blocked", status_code=status)
                self.submit()
                self.assertTrue(self.client.session.get("order_checkout_attempts"))
        self.api.post.side_effect = self.platform
        self.assertIn("/confirmation/", self.submit()["Location"])
        self.assertEqual(self.create_requests, [original, original])

    def test_pending_checkout_offers_recovery_even_when_current_catalog_is_unavailable(self):
        self.submit()
        self.api.post.reset_mock()
        self.api.post.side_effect = PlatformAPIError("Current catalog unavailable", status_code=503)
        response = self.client.get(reverse("orders:checkout"))
        self.assertContains(response, "Check previous order")
        self.assertContains(response, 'action="/order/create/"')
        self.assertContains(response, "RON")
        self.api.post.assert_not_called()
