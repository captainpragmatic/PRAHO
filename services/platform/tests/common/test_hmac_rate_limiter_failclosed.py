"""HMAC requests are denied when the shared counter store is unavailable."""

from unittest.mock import patch

from django.db import OperationalError
from django.test import TestCase, override_settings

from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_WINDOW=60,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "hmac-store-error"}},
)
class HMACRateLimiterFailClosedTests(HMACTestMixin, TestCase):
    def test_cache_unreachable_denies_request(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("Counter store unavailable")):
            response = self.portal_post("/api/window-probe/", {})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "60")
        self.assertEqual(response.json()["error"], "Too many requests")
