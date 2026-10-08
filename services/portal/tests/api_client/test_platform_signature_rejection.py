"""Platform refusing the Portal's request authentication is an outage, not a wrong password.

Platform answers every HMAC failure with one uniform body (`PortalServiceHMACMiddleware`). Before,
the Portal read that 401 on the login endpoint as bad credentials, so a secret mismatch or a
skewed clock told every customer their password was wrong and spent their attempt budget.
"""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import requests
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from apps.api_client import services
from apps.api_client.services import PLATFORM_SIGNATURE_REJECTED, PlatformAPIClient, PlatformAPIError
from apps.common import counters

PLATFORM_REJECTION = b'{"error": "HMAC authentication failed"}'
SECRET = "signature-rejection-test-secret-0123456789"


def _response(status: int, body: bytes, content_type: str = "application/json") -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = body
    response.headers["Content-Type"] = content_type
    return response


class _ResetLogGate:
    def setUp(self) -> None:
        super().setUp()
        services._signature_rejection_log_gate.last_logged_at = None


@override_settings(PLATFORM_API_BASE_URL="https://platform.example.test/api", PLATFORM_API_SECRET=SECRET)
class SignatureRejectionClassificationTests(_ResetLogGate, SimpleTestCase):
    def _transport(self, response: requests.Response) -> MagicMock:
        transport = patch("apps.api_client.services.portal_request", return_value=response)
        mock = transport.start()
        self.addCleanup(transport.stop)
        return mock

    def test_the_marker_is_platforms_exact_rejection_text(self) -> None:
        self.assertEqual(PLATFORM_SIGNATURE_REJECTED, "HMAC authentication failed")

    def test_a_rejected_json_request_is_unavailable_and_keeps_platforms_answer(self) -> None:
        transport = self._transport(_response(401, PLATFORM_REJECTION))
        with self.assertRaises(PlatformAPIError) as raised:
            PlatformAPIClient()._make_request("POST", "/test/")
        error = raised.exception
        self.assertTrue(error.is_unavailable)
        self.assertTrue(error.is_degraded)
        self.assertFalse(error.is_maintenance)
        self.assertFalse(error.is_rate_limited)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(error.response_data, {"error": "HMAC authentication failed"})
        self.assertEqual(transport.call_count, 1)

    def test_a_rejected_login_raises_instead_of_reporting_bad_credentials(self) -> None:
        transport = self._transport(_response(401, PLATFORM_REJECTION))
        with self.assertRaises(PlatformAPIError) as raised:
            PlatformAPIClient().authenticate_customer("customer@example.test", "correct-password")
        self.assertTrue(raised.exception.is_unavailable)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(transport.call_count, 1)

    def test_real_credential_rejections_still_mean_invalid_credentials(self) -> None:
        for body in (
            b'{"success": false, "error": "Invalid email or password"}',
            b'{"success": false, "error": "Invalid authentication code"}',
        ):
            with self.subTest(body=body):
                self._transport(_response(401, body))
                self.assertIsNone(PlatformAPIClient().authenticate_customer("customer@example.test", "wrong"))

    def test_only_the_exact_platform_rejection_is_classified(self) -> None:
        # The residual: these are not Platform's HMAC answer, so a misconfigured Platform that
        # sent one would still read as bad credentials on the login endpoint.
        not_the_marker = (
            (401, b"not json"),
            (401, b'["HMAC authentication failed"]'),
            (401, b'{"detail": "HMAC authentication failed"}'),
            (401, b'{"error": "HMAC authentication failed: signature mismatch"}'),
            (401, b'{"error": "hmac authentication failed"}'),
            (401, b'{"error": "Access denied"}'),
            (401, b'{"error": "Authentication required"}'),
            (403, PLATFORM_REJECTION),
        )
        for status, body in not_the_marker:
            with self.subTest(status=status, body=body):
                self._transport(_response(status, body))
                with self.assertRaises(PlatformAPIError) as raised:
                    PlatformAPIClient()._make_request("POST", "/test/")
                self.assertFalse(raised.exception.is_unavailable)
                self.assertEqual(raised.exception.status_code, status)
                self.assertIsNone(PlatformAPIClient().authenticate_customer("customer@example.test", "pw"))

    def test_both_binary_transports_classify_the_rejection(self) -> None:
        calls: tuple[Callable[[PlatformAPIClient], object], ...] = (
            lambda client: client._make_binary_request("POST", "/billing/invoices/INV-1/pdf/"),
            lambda client: client._make_binary_request_with_headers("POST", "/tickets/1/attachments/2/download/"),
        )
        for call in calls:
            with self.subTest(call=call):
                self._transport(_response(401, PLATFORM_REJECTION))
                with self.assertRaises(PlatformAPIError) as raised:
                    call(PlatformAPIClient())
                self.assertTrue(raised.exception.is_unavailable)
                self.assertEqual(raised.exception.status_code, 401)

    def test_a_successful_binary_body_is_never_parsed(self) -> None:
        pdf = _response(200, b"%PDF-1.7 binary", content_type="application/pdf")
        self._transport(pdf)
        with patch.object(requests.Response, "json", side_effect=AssertionError("parsed a binary body")):
            self.assertEqual(PlatformAPIClient()._make_binary_request("GET", "/billing/x/pdf/"), b"%PDF-1.7 binary")

    def test_the_rejection_is_logged_as_critical_with_where_to_look_and_no_secret(self) -> None:
        self._transport(_response(401, PLATFORM_REJECTION))
        with self.assertLogs("apps.api_client.services", level="CRITICAL") as logs, self.assertRaises(PlatformAPIError):
            PlatformAPIClient()._make_request("POST", "/test/")
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        for expected in ("[HMAC Auth] Authentication failed", "secret", "clock", "/test/"):
            self.assertIn(expected, message)
        self.assertNotIn(SECRET, message)

    def test_a_burst_of_rejections_logs_once_per_window(self) -> None:
        self._transport(_response(401, PLATFORM_REJECTION))
        clock = patch("apps.api_client.services.time.monotonic", return_value=1000.0)
        monotonic = clock.start()
        self.addCleanup(clock.stop)
        with self.assertLogs("apps.api_client.services", level="CRITICAL") as logs:
            for _ in range(5):
                with self.assertRaises(PlatformAPIError):
                    PlatformAPIClient()._make_request("POST", "/test/")
            self.assertEqual(len([r for r in logs.records if r.levelname == "CRITICAL"]), 1)
            monotonic.return_value = 1000.0 + services.SIGNATURE_REJECTION_LOG_INTERVAL_SECONDS
            with self.assertRaises(PlatformAPIError):
                PlatformAPIClient()._make_request("POST", "/test/")
        self.assertEqual(len([r for r in logs.records if r.levelname == "CRITICAL"]), 2)


@override_settings(
    PLATFORM_API_BASE_URL="https://platform.example.test/api",
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "signature-login"}},
)
class SignatureRejectionLoginViewTests(_ResetLogGate, TestCase):
    """The view, the real client and the real limiter; only the network is replaced."""

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.email = "login@example.com"
        self.credentials = {"email": self.email, "password": "test-password"}
        self.ip_key = "auth_ip_attempts_127.0.0.1"
        self.account_key = f"auth_account_attempts_{self.email}"

    def _post_six_times(self, body: bytes) -> tuple[MagicMock, list[Any]]:
        with patch("apps.api_client.services.portal_request", return_value=_response(401, body)) as transport:
            responses = [self.client.post(reverse("users:login"), self.credentials) for _ in range(6)]
        return transport, responses

    def test_a_signature_rejection_shows_the_outage_and_spends_no_attempts(self) -> None:
        transport, responses = self._post_six_times(PLATFORM_REJECTION)
        self.assertEqual(transport.call_count, 6)  # the sixth was not throttled
        self.assertEqual(counters.peek(self.ip_key), 0)
        self.assertEqual(counters.peek(self.account_key), 0)
        for response in responses:
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "Authentication service is temporarily unavailable")
            self.assertNotContains(response, "Invalid email address or password")

    def test_control_wrong_passwords_are_counted_and_the_sixth_is_throttled(self) -> None:
        transport, responses = self._post_six_times(b'{"success": false, "error": "Invalid email or password"}')
        self.assertEqual(transport.call_count, 5)
        self.assertEqual(counters.peek(self.ip_key), 5)
        self.assertEqual(counters.peek(self.account_key), 5)
        last = responses[-1]
        self.assertEqual(last.status_code, 302)
        self.assertIn(
            "Too many authentication attempts",
            " ".join(str(message) for message in get_messages(last.wsgi_request)),
        )
