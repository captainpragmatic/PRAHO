"""Transport failures must reach the existing degraded-state handlers."""

from collections.abc import Callable
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


@override_settings(PLATFORM_API_BASE_URL="https://platform.example.test/api")
class PlatformReachabilityTests(SimpleTestCase):
    def test_only_reachability_failures_are_unavailable_on_all_transports(self) -> None:
        client = PlatformAPIClient()
        calls: tuple[Callable[[], object], ...] = (
            lambda: client._make_request("POST", "/test/"),
            lambda: client._make_binary_request("POST", "/test/"),
            lambda: client._make_binary_request_with_headers("POST", "/test/"),
        )
        for call in calls:
            for failure in (
                requests.exceptions.ConnectionError("connection refused"),
                requests.exceptions.Timeout("timed out"),
                requests.exceptions.InvalidURL("invalid URL"),
                requests.exceptions.MissingSchema("missing scheme"),
            ):
                with (
                    self.subTest(call=call, failure=type(failure).__name__),
                    patch("apps.common.outbound_http._session.request", side_effect=failure),
                    self.assertRaises(PlatformAPIError) as raised,
                ):
                    call()
                error = raised.exception
                expected = isinstance(failure, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))
                self.assertEqual(error.is_unavailable, expected)
                self.assertEqual(error.is_degraded, expected)
                self.assertFalse(error.is_maintenance)
                self.assertIsNone(error.status_code)
                self.assertIs(error.__cause__, failure)

        with override_settings(DEBUG=False, PLATFORM_API_BASE_URL="ftp://platform.example.test/api"):
            refused = PlatformAPIClient()
            with self.assertRaises(PlatformAPIError) as raised:
                refused._make_request("POST", "/test/")
            self.assertFalse(raised.exception.is_unavailable)
            self.assertFalse(raised.exception.is_degraded)

    def test_exhausted_hmac_fallback_without_a_response_is_unavailable(self) -> None:
        response = requests.Response()
        response.status_code = 401
        response._content = b'{"error": "HMAC validation failed"}'
        response.headers["Content-Type"] = "application/json"
        with (
            patch("apps.common.outbound_http._session.request", return_value=response),
            self.assertRaises(PlatformAPIError) as raised,
        ):
            PlatformAPIClient()._make_request("POST", "/test/", max_retries=0)
        self.assertTrue(raised.exception.is_unavailable)
        self.assertTrue(raised.exception.is_degraded)
        self.assertFalse(raised.exception.is_maintenance)
        self.assertEqual(str(raised.exception), "Request failed: no response after retries")
