from __future__ import annotations

import time
from unittest.mock import patch

from django.core.cache import cache
from django.db import OperationalError
from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from rest_framework.parsers import JSONParser
from rest_framework.request import Request

from apps.common import counters
from apps.common.models import Counter
from apps.common.performance.rate_limiting import (
    LoginClientIPThrottle,
    ResetClientIPThrottle,
    fixed_window_limited,
    forwarded_client_ip,
)


class ForwardedClientIPTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request(self, data: dict[str, str], *, authenticated: bool = True) -> HttpRequest:
        request = self.factory.post("/api/users/login/", data, content_type="application/json")
        if authenticated:
            request._portal_authenticated = True  # middleware contract
        return request

    def test_forwarded_client_ip_returns_authenticated_ipv4(self) -> None:
        self.assertEqual(forwarded_client_ip(self._request({"client_ip": "203.0.113.10"})), "203.0.113.10")

    def test_forwarded_client_ip_ignores_forged_body(self) -> None:
        request = self._request({"client_ip": "203.0.113.10"}, authenticated=False)
        self.assertIsNone(forwarded_client_ip(request))

    def test_forwarded_client_ip_rejects_invalid_ip(self) -> None:
        self.assertIsNone(forwarded_client_ip(self._request({"client_ip": "not-an-ip"})))

    def test_forwarded_client_ip_requires_body_key(self) -> None:
        self.assertIsNone(forwarded_client_ip(self._request({})))

    def test_forwarded_client_ip_rejects_non_json_body(self) -> None:
        request = self.factory.post("/api/users/login/", "not-json", content_type="text/plain")
        request._portal_authenticated = True  # middleware contract
        self.assertIsNone(forwarded_client_ip(request))

    def test_forwarded_client_ip_canonicalises_ipv6(self) -> None:
        self.assertEqual(forwarded_client_ip(self._request({"client_ip": "2001:DB8::1"})), "2001:db8::1")

    def test_forwarded_client_ip_reads_drf_data(self) -> None:
        request = Request(self._request({"client_ip": "203.0.113.10"}), parsers=[JSONParser()])
        self.assertEqual(forwarded_client_ip(request), "203.0.113.10")

    def test_login_throttle_has_no_key_without_forwarded_ip(self) -> None:
        for data, authenticated in (({}, True), ({"client_ip": "203.0.113.10"}, False)):
            with self.subTest(data=data, authenticated=authenticated):
                request = Request(self._request(data, authenticated=authenticated), parsers=[JSONParser()])
                self.assertIsNone(LoginClientIPThrottle().get_cache_key(request, None))

    def test_login_throttle_keys_on_forwarded_ip(self) -> None:
        request = Request(self._request({"client_ip": "203.0.113.10"}), parsers=[JSONParser()])
        key = LoginClientIPThrottle().get_cache_key(request, None)
        self.assertEqual(key, "throttle_endpoint_auth_login_ip_client_203.0.113.10")

    def test_reset_throttle_uses_a_separate_scope(self) -> None:
        request = Request(self._request({"client_ip": "203.0.113.10"}), parsers=[JSONParser()])
        self.assertEqual(
            ResetClientIPThrottle().get_cache_key(request, None),
            "throttle_endpoint_auth_reset_ip_client_203.0.113.10",
        )


@override_settings(
    RATE_LIMITING_ENABLED=True,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "forwarded-client-ip-fixed-window-tests",
        }
    },
)
class FixedWindowLimitTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_fixed_window_limits_after_configured_count(self) -> None:
        self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))
        self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))
        limited, retry_after = fixed_window_limited("k", "2/minute")
        self.assertTrue(limited)
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 60)

    def test_fixed_window_returns_remaining_seconds(self) -> None:
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1000.0):
            self.assertEqual(fixed_window_limited("k", "1/minute"), (False, 0))
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1005.0):
            self.assertEqual(fixed_window_limited("k", "1/minute"), (True, 15))
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1061.0):
            self.assertEqual(fixed_window_limited("k", "1/minute"), (False, 0))

    @override_settings(RATE_LIMITING_ENABLED=False)
    def test_disabled_fixed_window_never_charges_cache(self) -> None:
        with patch("apps.common.performance.rate_limiting.time.time", return_value=1000.0):
            for _ in range(3):
                self.assertEqual(fixed_window_limited("k", "2/minute"), (False, 0))
                self.assertEqual(fixed_window_limited("k", "2/minute", charge=False), (False, 0))
            self.assertEqual(Counter.objects.count(), 0)

    def test_fixed_window_fails_closed_on_cache_errors(self) -> None:
        for operation in ("increment", "peek"):
            with self.subTest(operation=operation):
                counters.reset(f"k:{int(time.time() // 60)}")
                self.assertEqual(fixed_window_limited("k", "1/minute"), (False, 0))
                with patch(
                    f"apps.common.counters.{operation}",
                    side_effect=OperationalError("Counter store unavailable"),
                ):
                    self.assertEqual(
                        fixed_window_limited("k", "1/minute", charge=operation != "peek"),
                        (True, 60),
                    )
