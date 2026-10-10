"""HMAC requests are refused, as an outage, when a shared store is unavailable.

The rate-limit counter and the nonce claim live in the shared counter store. When it fails the
request is still denied (fail closed), but answered 503: the portal reads a 401 as "the secret or
the clock is wrong" and raises a critical alert, and reads a 429 as "this customer is throttled".
"""

import json
import time
from unittest.mock import patch

from django.core.cache import cache
from django.db import OperationalError
from django.http import HttpResponse
from django.test import TestCase, override_settings

from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PROBE = "/api/window-probe/"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_WINDOW=60,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "hmac-store-error"}},
)
class HMACStoreFaultTests(HMACTestMixin, TestCase):
    def _signed_post(self, nonce: str, timestamp: str | None = None) -> HttpResponse:
        body = json.dumps({"timestamp": time.time()}).encode()
        headers = hmac_headers("POST", PROBE, body, portal_id=self.portal_id, nonce=nonce, timestamp=timestamp)
        return self.client.post(PROBE, body, content_type="application/json", **headers)

    def _assert_outage(self, response: HttpResponse) -> None:
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)["error"], "Platform temporarily unavailable")
        self.assertIn("Retry-After", response)

    def test_an_unavailable_rate_limit_store_is_an_outage_not_a_throttle(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("Counter store unavailable")):
            response = self.portal_post(PROBE, {})
        self._assert_outage(response)

    def test_an_unavailable_nonce_store_is_an_outage_not_a_forgery(self) -> None:
        with patch("apps.common.counters.claim", side_effect=OperationalError("Counter store unavailable")):
            response = self.portal_post(PROBE, {})
        self._assert_outage(response)

    def test_a_replayed_nonce_is_still_refused_as_authentication(self) -> None:
        nonce = "replayed-nonce-0123456789abcdef0123"
        self._signed_post(nonce)
        response = self._signed_post(nonce)
        self.assertEqual(response.status_code, 401)

    def test_a_claimed_nonce_survives_the_cache_being_cleared(self) -> None:
        # Claims live in the counter table, not the cache, so eviction cannot reopen a replay.
        nonce = "evicted-nonce-0123456789abcdef01234"
        self._signed_post(nonce)
        cache.clear()
        response = self._signed_post(nonce)
        self.assertEqual(response.status_code, 401)

    def test_an_unexpected_error_is_not_reported_as_an_outage(self) -> None:
        # Only a failing store is an outage; a bug elsewhere must not turn forgeries into 503s.
        with patch("apps.common.portal_hmac.get_mode", side_effect=ValueError("bug")):
            response = self.portal_post(PROBE, {})
        self.assertEqual(response.status_code, 401)

    def test_an_infinite_timestamp_is_a_format_error(self) -> None:
        with self.assertLogs("apps.common.middleware", level="WARNING") as logs:
            response = self._signed_post("infinite-timestamp-0123456789abcdef", timestamp="1e400")
        self.assertEqual(response.status_code, 401)
        self.assertTrue(any("Invalid timestamp format" in line for line in logs.output), logs.output)
