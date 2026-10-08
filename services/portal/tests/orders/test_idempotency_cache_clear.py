"""Coverage additions: LocMem eviction cannot erase payment or checkout idempotency."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from requests import Response

from apps.common import counters

ORDER_ID = "550e8400-e29b-41d4-a716-446655440707"
PRODUCTION_MIDDLEWARE = tuple(
    middleware for middleware in settings.MIDDLEWARE if not middleware.startswith("debug_toolbar.")
)


@override_settings(
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="django.contrib.sessions.backends.db",
    RATE_LIMITING_ENABLED=False,
    LANGUAGE_CODE="en",
)
class IdempotencyCacheClearTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("apps.api_client.services.portal_request", side_effect=self.platform))
        session = self.client.session
        now = timezone.now()
        session.update(
            {
                "user_id": 7,
                "customer_id": 42,
                "active_customer_id": 42,
                "session_auth_hash": "current",
                "authenticated_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(hours=1)).isoformat(),
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def platform(self, **kwargs: object) -> Response:
        self.assertTrue(str(kwargs["url"]).endswith("/localisation/"), kwargs["url"])
        response = Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(
            {
                "success": True,
                "localisation": {
                    "default_language": "en",
                    "default_country": "RO",
                    "timezone": "Europe/Bucharest",
                    "customer_date_format": "%d.%m.%Y",
                },
                "company": {
                    "legal_name": "PragmaticHost SRL",
                    "email_support": "support@pragmatichost.com",
                    "email_privacy": "privacy@pragmatichost.com",
                    "email_finance": "",
                    "phone": "",
                },
            }
        ).encode()
        return response

    def test_payment_duplicate_stays_already_processing_after_cache_clear(self) -> None:
        payment_id = "pi_cacheclear707"
        self.assertTrue(counters.claim(f"confirm_payment:42:{payment_id}", 300, "payment-owner"))
        body = json.dumps({"payment_intent_id": payment_id, "order_id": ORDER_ID})
        for clear in (False, True):
            if clear:
                cache.clear()
            response = self.client.post("/order/confirm-payment/", body, content_type="application/json")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "already_processing")
            self.assertTrue(response.json()["success"])
        self.assertFalse(counters.claim(f"confirm_payment:42:{payment_id}", 300, "duplicate"))

    def test_checkout_replays_completed_order_after_cache_clear(self) -> None:
        key = "orders:idempotency:42:cache-clear-checkout"
        self.assertTrue(counters.claim(key, 300, "checkout-owner"))
        self.assertTrue(counters.complete(key, "checkout-owner", ORDER_ID))
        payload = {"cart_version": "submitted-version", "idempotency_key": "cache-clear-checkout"}
        for clear in (False, True):
            if clear:
                cache.clear()
            response = self.client.post("/order/create/", payload)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], f"/order/confirmation/{ORDER_ID}/")
        self.assertEqual(counters.lookup(key), ORDER_ID)
        self.assertFalse(counters.claim(key, 300, "duplicate"))
