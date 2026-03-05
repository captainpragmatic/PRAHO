from __future__ import annotations

import time

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase
from django.test.client import RequestFactory

from apps.api_client.services import PlatformAPIError
from apps.common.rate_limit_feedback import (
    RATE_LIMIT_BANNER_UNTIL_KEY,
    consume_rate_limit_banner,
    get_rate_limit_message,
    get_retry_after_from_error,
    is_rate_limited_error,
    record_rate_limit_banner,
)


def _request(path: str = "/dashboard/"):
    request = RequestFactory().get(path)
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    return request


class RateLimitFeedbackTests(SimpleTestCase):
    def test_rate_limit_message_with_retry_after(self) -> None:
        message = get_rate_limit_message(12)
        self.assertIn("12", message)

    def test_record_and_consume_banner(self) -> None:
        request = _request()

        record_rate_limit_banner(request, retry_after=8)
        banner = consume_rate_limit_banner(request)

        assert banner is not None
        self.assertEqual(banner["severity"], "warning")
        self.assertIn("Try again", banner["cta_text"])
        self.assertIn("requests", banner["message"])

    def test_consume_banner_clears_expired_value(self) -> None:
        request = _request()
        request.session[RATE_LIMIT_BANNER_UNTIL_KEY] = int(time.time()) - 1

        banner = consume_rate_limit_banner(request)

        self.assertIsNone(banner)
        self.assertNotIn(RATE_LIMIT_BANNER_UNTIL_KEY, request.session)

    def test_rate_limit_error_helpers(self) -> None:
        rate_limited = PlatformAPIError("Too many requests", status_code=429, retry_after=6, is_rate_limited=True)
        not_rate_limited = PlatformAPIError("Server error", status_code=500, is_rate_limited=False)

        self.assertTrue(is_rate_limited_error(rate_limited))
        self.assertFalse(is_rate_limited_error(not_rate_limited))
        self.assertEqual(get_retry_after_from_error(rate_limited), 6)
        self.assertIsNone(get_retry_after_from_error(not_rate_limited))
