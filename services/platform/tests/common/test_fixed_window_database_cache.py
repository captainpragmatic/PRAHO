"""Fixed windows must roll independently of DatabaseCache increment expiry."""

from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.common.performance.rate_limiting import fixed_window_limited
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_WINDOW=60,
    HMAC_RATE_LIMIT_MAX_CALLS=2,
    HMAC_RATE_LIMIT_MAX_AUTH_CALLS=2,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "test_rate_limit_cache",
            "TIMEOUT": 300,
        }
    },
)
class FixedWindowDatabaseCacheTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        call_command("createcachetable", verbosity=0)
        cache.clear()
        self.addCleanup(cache.clear)

    def test_fixed_window_rolls_on_database_cache(self) -> None:
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1_800_000_001.0):
            self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))
            self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))
            self.assertEqual(fixed_window_limited("k", "2/minute"), (True, 59))
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1_800_000_061.0):
            self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))

    def test_hmac_general_and_auth_windows_roll_on_database_cache(self) -> None:
        for path, allowed_status in (("/api/window-probe/", 404), ("/api/users/login/", 400)):
            with self.subTest(path=path):
                cache.clear()
                with patch("apps.common.middleware.time.time", return_value=1_800_000_001.0):
                    for _ in range(2):
                        response = self.portal_post(path, {})
                        self.assertEqual(response.status_code, allowed_status, response.content)
                    response = self.portal_post(path, {})
                    self.assertEqual(response.status_code, 429, response.content)
                    self.assertEqual(response["Retry-After"], "59")
                with patch("apps.common.middleware.time.time", return_value=1_800_000_061.0):
                    response = self.portal_post(path, {})
                    self.assertEqual(response.status_code, allowed_status, response.content)
