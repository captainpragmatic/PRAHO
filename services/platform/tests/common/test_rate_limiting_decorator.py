"""Unit tests for the custom @rate_limit decorator (apps.common.rate_limiting).

Tests use Django's LocMemCache to avoid external dependencies.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from django.core.cache import caches
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase, override_settings

from apps.common.rate_limiting import ALL, rate_limit

LOCMEM_TEST_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "rate-limit-test",
    }
}


def _make_request(
    method: str = "POST",
    ip: str = "127.0.0.1",
    post_data: dict | None = None,
    user: object | None = None,
) -> HttpRequest:
    """Build a minimal HttpRequest for testing."""
    request = HttpRequest()
    request.method = method
    request.META["REMOTE_ADDR"] = ip
    if post_data:
        request.POST = post_data  # type: ignore[assignment]  # test helper: inject dict as QueryDict
    if user:
        request.user = user  # type: ignore[attr-defined]  # test helper: inject mock user
    else:
        request.user = MagicMock(is_authenticated=False)  # type: ignore[attr-defined]  # test helper: anonymous user
    return request


def _dummy_view(request: HttpRequest) -> HttpResponse:
    """Trivial view used as the decorated target."""
    return HttpResponse("ok")


@override_settings(CACHES=LOCMEM_TEST_CACHE, RATE_LIMITING_ENABLED=True)
class TestRateLimitDecorator(SimpleTestCase):
    """Core decorator behaviour."""

    def setUp(self) -> None:
        # Flush the test cache between tests
        caches["default"].clear()

    def test_allows_under_limit(self) -> None:
        """Requests at or below the limit should not set request.limited."""
        wrapped = rate_limit(key="ip", rate="5/m", method=ALL)(_dummy_view)

        for _ in range(5):
            request = _make_request()
            response = wrapped(request)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(getattr(request, "limited", False))

    def test_marks_limited_over_limit(self) -> None:
        """The 6th request should set request.limited = True."""
        wrapped = rate_limit(key="ip", rate="5/m", method=ALL)(_dummy_view)

        for _ in range(5):
            wrapped(_make_request())

        sixth = _make_request()
        response = wrapped(sixth)
        self.assertEqual(response.status_code, 200)  # block=False by default
        self.assertTrue(getattr(sixth, "limited", False))

    def test_block_returns_429(self) -> None:
        """When block=True, exceeding the limit should return HTTP 429."""
        wrapped = rate_limit(key="ip", rate="2/m", method=ALL, block=True)(_dummy_view)

        for _ in range(2):
            wrapped(_make_request())

        third = _make_request()
        response = wrapped(third)
        self.assertEqual(response.status_code, 429)

    @override_settings(RATE_LIMITING_ENABLED=False)
    def test_disabled_setting_skips_limiting(self) -> None:
        """When RATE_LIMITING_ENABLED=False, no limiting occurs."""
        wrapped = rate_limit(key="ip", rate="1/m", method=ALL)(_dummy_view)

        for _ in range(10):
            request = _make_request()
            response = wrapped(request)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(getattr(request, "limited", False))

    def test_user_key_authenticated(self) -> None:
        """Authenticated users are keyed by user PK, not IP."""
        user_a = MagicMock(is_authenticated=True, pk=42)
        user_b = MagicMock(is_authenticated=True, pk=99)

        wrapped = rate_limit(key="user", rate="2/m", method=ALL)(_dummy_view)

        # Exhaust limit for user A
        for _ in range(2):
            wrapped(_make_request(user=user_a))

        # User A is now limited
        req_a = _make_request(user=user_a)
        wrapped(req_a)
        self.assertTrue(getattr(req_a, "limited", False))

        # User B should still be allowed (separate key)
        req_b = _make_request(user=user_b)
        wrapped(req_b)
        self.assertFalse(getattr(req_b, "limited", False))

    def test_ip_key_isolation(self) -> None:
        """Different IPs have independent rate limit counters."""
        wrapped = rate_limit(key="ip", rate="2/m", method=ALL)(_dummy_view)

        # Exhaust limit for IP 1.2.3.4
        for _ in range(2):
            wrapped(_make_request(ip="1.2.3.4"))

        # IP 1.2.3.4 is limited
        req_limited = _make_request(ip="1.2.3.4")
        wrapped(req_limited)
        self.assertTrue(getattr(req_limited, "limited", False))

        # IP 5.6.7.8 is not
        req_ok = _make_request(ip="5.6.7.8")
        wrapped(req_ok)
        self.assertFalse(getattr(req_ok, "limited", False))

    def test_post_field_key(self) -> None:
        """``post:<field>`` extracts the field value from POST data."""
        wrapped = rate_limit(key="post:email", rate="2/m", method="POST")(_dummy_view)

        # Exhaust limit for email A
        for _ in range(2):
            wrapped(_make_request(post_data={"email": "a@example.com"}))

        # Email A is limited
        req_limited = _make_request(post_data={"email": "a@example.com"})
        wrapped(req_limited)
        self.assertTrue(getattr(req_limited, "limited", False))

        # Email B is not
        req_ok = _make_request(post_data={"email": "b@example.com"})
        wrapped(req_ok)
        self.assertFalse(getattr(req_ok, "limited", False))

    def test_callable_key(self) -> None:
        """A callable key function receives (group, request)."""

        def custom_key(group: str, request: HttpRequest) -> str:
            return f"custom:{request.META.get('REMOTE_ADDR', '')}"

        wrapped = rate_limit(key=custom_key, rate="2/m", method=ALL)(_dummy_view)

        for _ in range(2):
            wrapped(_make_request())

        req = _make_request()
        wrapped(req)
        self.assertTrue(getattr(req, "limited", False))

    def test_method_filter_post_only(self) -> None:
        """POST-only rate limit should not affect GET requests."""
        wrapped = rate_limit(key="ip", rate="1/m", method="POST")(_dummy_view)

        # Exhaust POST limit
        wrapped(_make_request(method="POST"))

        # Second POST is limited
        req_post = _make_request(method="POST")
        wrapped(req_post)
        self.assertTrue(getattr(req_post, "limited", False))

        # GET is unaffected
        req_get = _make_request(method="GET")
        wrapped(req_get)
        self.assertFalse(getattr(req_get, "limited", False))
