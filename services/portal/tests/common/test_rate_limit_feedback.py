from __future__ import annotations

import logging

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase
from django.test.client import RequestFactory

from apps.api_client.services import PlatformAPIError
from apps.common.rate_limit_feedback import (
    build_rate_limited_context,
    get_rate_limit_message,
    get_retry_after_from_error,
    handle_platform_error,
    is_rate_limited_error,
    record_rate_limit_banner,
)


def _request(path: str = "/dashboard/"):
    request = RequestFactory().get(path)
    session_middleware = SessionMiddleware(lambda r: None)
    session_middleware.process_request(request)
    request._messages = FallbackStorage(request)
    return request


class RateLimitFeedbackTests(SimpleTestCase):
    def test_rate_limit_message_with_retry_after(self) -> None:
        message = get_rate_limit_message(12)
        self.assertIn("12", message)

    def test_record_rate_limit_banner_queues_warning_message(self) -> None:
        request = _request()

        record_rate_limit_banner(request, retry_after=8)

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 1)
        self.assertIn("try again in 8 seconds", str(queued[0]).lower())
        self.assertIn("warning", queued[0].tags)
        self.assertIn("rate-limit", queued[0].tags)

    def test_record_rate_limit_banner_is_idempotent_per_request(self) -> None:
        request = _request()

        record_rate_limit_banner(request, retry_after=6)
        record_rate_limit_banner(request, retry_after=6)

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 1)

    def test_build_rate_limited_context_includes_retry_metadata(self) -> None:
        request = _request("/services/")
        error = PlatformAPIError("Too many requests", status_code=429, retry_after=11, is_rate_limited=True)

        context = build_rate_limited_context(request, error)

        self.assertTrue(context["rate_limited"])
        self.assertEqual(context["rate_limit_retry_after"], 11)
        self.assertEqual(context["rate_limit_retry_url"], "/services/")

    def test_rate_limit_error_helpers(self) -> None:
        rate_limited = PlatformAPIError("Too many requests", status_code=429, retry_after=6, is_rate_limited=True)
        not_rate_limited = PlatformAPIError("Server error", status_code=500, is_rate_limited=False)

        self.assertTrue(is_rate_limited_error(rate_limited))
        self.assertFalse(is_rate_limited_error(not_rate_limited))
        self.assertEqual(get_retry_after_from_error(rate_limited), 6)
        self.assertIsNone(get_retry_after_from_error(not_rate_limited))

    def test_build_rate_limited_context_no_duplicate_toast(self) -> None:
        """build_rate_limited_context should NOT queue a Django message (inline alert only)."""
        request = _request("/billing/")
        error = PlatformAPIError("Too many requests", status_code=429, retry_after=5, is_rate_limited=True)

        build_rate_limited_context(request, error)

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 0)


class HandlePlatformErrorTests(SimpleTestCase):
    def setUp(self) -> None:
        self.test_logger = logging.getLogger("test.rate_limit")

    def test_rate_limited_error_returns_context_with_rate_limited_true(self) -> None:
        request = _request("/services/")
        error = PlatformAPIError("Too many requests", status_code=429, retry_after=11, is_rate_limited=True)

        result = handle_platform_error(request, error, self.test_logger)

        self.assertTrue(result["rate_limited"])
        self.assertEqual(result["rate_limit_retry_after"], 11)
        self.assertEqual(result["rate_limit_retry_url"], "/services/")

    def test_rate_limited_error_does_not_add_django_message(self) -> None:
        request = _request("/billing/")
        error = PlatformAPIError("Too many requests", status_code=429, retry_after=5, is_rate_limited=True)

        handle_platform_error(request, error, self.test_logger)

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 0)

    def test_non_rate_limited_error_returns_empty_dict(self) -> None:
        request = _request("/tickets/")
        error = PlatformAPIError("Server error", status_code=500, is_rate_limited=False)

        result = handle_platform_error(
            request, error, self.test_logger, fallback_message="Something went wrong."
        )

        self.assertEqual(result, {})

    def test_non_rate_limited_error_adds_django_message(self) -> None:
        request = _request("/tickets/")
        error = PlatformAPIError("Server error", status_code=500, is_rate_limited=False)

        handle_platform_error(request, error, self.test_logger, fallback_message="Something went wrong.")

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 1)
        self.assertIn("Something went wrong", str(queued[0]))

    def test_non_rate_limited_without_fallback_no_message(self) -> None:
        request = _request("/tickets/")
        error = PlatformAPIError("Server error", status_code=500, is_rate_limited=False)

        handle_platform_error(request, error, self.test_logger)

        queued = list(get_messages(request))
        self.assertEqual(len(queued), 0)

    def test_generic_exception_treated_as_non_rate_limited(self) -> None:
        request = _request("/dashboard/")
        error = ValueError("Unexpected error")

        result = handle_platform_error(
            request, error, self.test_logger, fallback_message="Oops."
        )

        self.assertEqual(result, {})
        queued = list(get_messages(request))
        self.assertEqual(len(queued), 1)
