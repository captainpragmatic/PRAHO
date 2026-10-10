"""A checkout whose mid-request session save gives up is a 503, not a "please try again" redirect (ADR-0055).

The checkout saves the session before calling Platform. If that save gives up under contention, the
session middleware answers the portal's 503 with Retry-After; the checkout's own catch-all must not
turn it into a redirect that drops the purchase attempt silently.
"""

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
from apps.common.session_store import SessionSaveContended
from apps.orders.views import CheckoutContext

PRODUCTION_MIDDLEWARE = tuple(
    middleware for middleware in settings.MIDDLEWARE if not middleware.startswith("debug_toolbar.")
)


@override_settings(
    DEBUG=False,
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="apps.common.session_store",
    RATE_LIMITING_ENABLED=False,
    LANGUAGE_CODE="en",
)
class CheckoutSessionContentionTests(TestCase):
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

    def test_a_contended_save_before_the_platform_call_is_a_503(self) -> None:
        checkout = CheckoutContext(
            cart=object(),
            customer_id="42",
            user_id="7",
            payment_method="bank_transfer",
            cart_version="v1",
            notes="",
            idempotency_key="contended-checkout",
            agree_terms=True,
        )
        with (
            patch("apps.orders.views._validate_checkout_request", return_value=checkout),
            patch(
                "apps.orders.views.OrderCreationService.preflight_order",
                side_effect=SessionSaveContended("gave up"),
            ),
        ):
            response = self.client.post("/order/create/", {"idempotency_key": "contended-checkout"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("Retry-After", response)
        # The checkout claim was released, so the customer's retry is not refused as a duplicate.
        self.assertTrue(counters.claim("orders:idempotency:42:contended-checkout", 300, "retry"))
