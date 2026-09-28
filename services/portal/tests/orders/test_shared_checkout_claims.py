"""Checkout results and failed claims survive worker changes."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.core.cache import cache
from django.db import connections
from django.http import HttpResponse
from django.test import Client, TransactionTestCase, override_settings
from requests import Response

from apps.common import counters
from apps.orders.services import GDPRCompliantCartSession


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "shared-checkout-claims",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class SharedCheckoutClaimTests(TransactionTestCase):
    order_id = "550e8400-e29b-41d4-a716-446655440099"
    key = "orders:idempotency:42:checkout-retry"

    def setUp(self) -> None:
        self.enterContext(override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True))
        cache.clear()
        self.addCleanup(cache.clear)
        self.reject_preflight = False
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        cart = GDPRCompliantCartSession(session)
        cart.add_item("shared-hosting", 1, "monthly")
        session.save()
        self.payload = {
            "cart_version": cart.get_cart_version(),
            "agree_terms": "on",
            "payment_method": "bank_transfer",
            "idempotency_key": "checkout-retry",
        }

    def platform(self, **kwargs: object) -> Response:
        url = str(kwargs["url"])
        if "/products/" in url:
            body: dict[str, object] = {"slug": "shared-hosting", "is_active": True, "requires_domain": False}
        elif url.endswith("/preflight/"):
            body = {"success": not self.reject_preflight, "errors": ["Unavailable"] if self.reject_preflight else []}
        elif url.endswith("/create/"):
            body = {"order": {"id": self.order_id, "order_number": "ORD-42", "status": "draft"}}
        else:
            raise AssertionError(f"Unexpected Platform request: {url}")
        response = Response()
        response.status_code = 200
        response._content = json.dumps(body).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    def submit(self) -> HttpResponse:
        return self.client.post("/order/create/", self.payload, HTTP_HX_REQUEST="true")

    def test_second_connection_replays_completed_order_after_cart_is_cleared(self) -> None:
        first = self.submit()
        self.assertEqual(first.status_code, 302)
        self.assertIn(self.order_id, first["Location"])
        self.assertFalse(GDPRCompliantCartSession(self.client.session).has_items())
        cookies = self.client.cookies.copy()

        def retry() -> tuple[int, str]:
            try:
                client = Client()
                client.cookies = cookies
                response = client.post("/order/create/", self.payload)
                return response.status_code, response["Location"]
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            status, location = pool.submit(retry).result(timeout=10)
        self.assertEqual((status, location), (302, first["Location"]))
        self.assertEqual(counters.lookup(self.key), self.order_id)

    def test_immediate_retry_after_preflight_failure_is_admitted(self) -> None:
        self.reject_preflight = True
        self.assertEqual(self.submit().status_code, 302)
        self.assertTrue(counters.claim(self.key, 300, "probe"))
        self.assertTrue(counters.release(self.key, "probe"))
        self.reject_preflight = False
        response = self.submit()
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.order_id, response["Location"])
        self.assertEqual(counters.lookup(self.key), self.order_id)

    def test_loser_cannot_release_or_complete_another_workers_claim(self) -> None:
        self.assertTrue(counters.claim(self.key, 300, "winner"))
        response = self.submit()
        self.assertEqual(response.status_code, 409)
        self.assertFalse(counters.release(self.key, "loser"))
        self.assertFalse(counters.complete(self.key, "loser", self.order_id))
        self.assertIsNone(counters.lookup(self.key))
        self.assertTrue(counters.complete(self.key, "winner", self.order_id))
        self.assertEqual(self.submit()["Location"], f"/order/confirmation/{self.order_id}/")
