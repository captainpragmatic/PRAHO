from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


def _response(status_code: int, payload: object, headers: dict[str, str] | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    if isinstance(payload, Exception):
        response.json.side_effect = payload
    else:
        response.json.return_value = payload
    return response


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
)
class PlatformAPIClientRateLimitRetryTests(SimpleTestCase):
    def setUp(self) -> None:
        self.client = PlatformAPIClient()

    def test_handle_api_response_parses_detail_and_retry_after(self) -> None:
        response = _response(429, {"detail": "Slow down"}, headers={"Retry-After": "7"})

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._handle_api_response(response, "/tickets/summary/")

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.retry_after, 7)
        self.assertTrue(ctx.exception.is_rate_limited)
        self.assertIn("Slow down", str(ctx.exception))

    def test_handle_api_response_never_returns_unknown_error(self) -> None:
        response = _response(429, ["throttled"])

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._handle_api_response(response, "/services/summary/")

        self.assertNotIn("Unknown error", str(ctx.exception))
        self.assertIn("throttled", str(ctx.exception))

    @patch("apps.api_client.services.portal_request")
    def test_make_request_does_not_retry_idempotent_post_on_429(self, mock_portal_request: MagicMock) -> None:
        mock_portal_request.return_value = _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "1"})

        with self.assertRaises(PlatformAPIError):
            self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertEqual(mock_portal_request.call_count, 1)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_retries_idempotent_post_on_503(self, mock_portal_request: MagicMock, _mock_sleep: MagicMock) -> None:
        mock_portal_request.side_effect = [
            _response(503, {"error": "Service unavailable"}),
            _response(200, {"success": True, "data": {"summary": {}}}),
        ]

        data = self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertTrue(data["success"])
        self.assertEqual(mock_portal_request.call_count, 2)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_regenerates_headers_for_each_retry(
        self, mock_portal_request: MagicMock, _mock_sleep: MagicMock
    ) -> None:
        mock_portal_request.side_effect = [
            _response(503, {"error": "Service unavailable"}),
            _response(200, {"success": True}),
        ]

        with patch.object(
            self.client,
            "_prepare_request_headers",
            side_effect=[
                {"X-Nonce": "nonce-1", "X-Timestamp": "1", "X-Signature": "a", "Content-Type": "application/json"},
                {"X-Nonce": "nonce-2", "X-Timestamp": "2", "X-Signature": "b", "Content-Type": "application/json"},
            ],
        ) as mock_prepare_headers:
            data = self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertTrue(data["success"])
        self.assertEqual(mock_prepare_headers.call_count, 2)
        first_headers = mock_portal_request.call_args_list[0].kwargs["headers"]
        second_headers = mock_portal_request.call_args_list[1].kwargs["headers"]
        self.assertNotEqual(first_headers["X-Nonce"], second_headers["X-Nonce"])

    @patch("apps.api_client.services.portal_request")
    def test_make_request_does_not_retry_write_post_on_429(self, mock_portal_request: MagicMock) -> None:
        mock_portal_request.return_value = _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "1"})

        with self.assertRaises(PlatformAPIError):
            self.client._make_request("POST", "/tickets/create/", data={"customer_id": 1, "user_id": 2})

        self.assertEqual(mock_portal_request.call_count, 1)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_retries_get_on_503(self, mock_portal_request: MagicMock, _mock_sleep: MagicMock) -> None:
        mock_portal_request.side_effect = [
            _response(503, {"error": "Service unavailable"}),
            _response(200, {"success": True}),
        ]

        data = self.client._make_request("GET", "/status/")

        self.assertTrue(data["success"])
        self.assertEqual(mock_portal_request.call_count, 2)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_raises_after_retry_exhaustion_on_503(
        self, mock_portal_request: MagicMock, _mock_sleep: MagicMock
    ) -> None:
        mock_portal_request.side_effect = [
            _response(503, {"error": "Service unavailable"}),
            _response(503, {"error": "Service unavailable"}),
            _response(503, {"error": "Service unavailable"}),
        ]

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertFalse(ctx.exception.is_rate_limited)
        self.assertEqual(mock_portal_request.call_count, 3)

    def test_compute_retry_delay_honors_retry_after_with_cap(self) -> None:
        response = _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "30"})

        delay = self.client._compute_retry_delay(response, attempt=0)

        self.assertEqual(delay, self.client.max_retry_wait_seconds)

    def test_get_retry_after_seconds_supports_http_date_header(self) -> None:
        retry_date = format_datetime(datetime.now(UTC) + timedelta(seconds=8), usegmt=True)
        response = _response(429, {"detail": "Too many requests"}, headers={"Retry-After": retry_date})

        retry_after = self.client._get_retry_after_seconds(response)

        self.assertIsNotNone(retry_after)
        self.assertGreaterEqual(retry_after or 0, 1)

    def test_binary_error_uses_detail_message_and_retry_metadata(self) -> None:
        response = _response(429, {"detail": "Wait please", "retry_after": 9})

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._handle_binary_response(response, "/billing/invoices/INV-1/pdf/")

        self.assertTrue(ctx.exception.is_rate_limited)
        self.assertEqual(ctx.exception.retry_after, 9)
        self.assertIn("Wait please", str(ctx.exception))

    def test_normalize_endpoint_handles_api_prefix_and_slashes(self) -> None:
        self.assertEqual(self.client._normalize_endpoint("/api/tickets/"), "/tickets/")
        self.assertEqual(self.client._normalize_endpoint("tickets/summary"), "/tickets/summary/")
        self.assertEqual(self.client._normalize_endpoint("///services/"), "/services/")

    def test_idempotent_false_post_is_not_retryable(self) -> None:
        self.assertFalse(self.client._is_read_retry_candidate("POST", "/tickets/create/"))
        self.assertFalse(self.client._is_read_retry_candidate("POST", "/orders/create/"))

    def test_idempotent_true_post_is_retryable(self) -> None:
        self.assertTrue(self.client._is_read_retry_candidate("POST", "/tickets/summary/", idempotent=True))
        self.assertTrue(self.client._is_read_retry_candidate("POST", "/orders/calculate/", idempotent=True))

    def test_safe_parse_json_malformed_body(self) -> None:
        response = _response(429, ValueError("No JSON"))
        result = self.client._safe_parse_json(response)
        self.assertEqual(result, {})

    def test_safe_parse_json_list_body(self) -> None:
        response = _response(429, ["throttled"])
        result = self.client._safe_parse_json(response)
        self.assertEqual(result, {"_raw": ["throttled"]})

    def test_safe_parse_json_dict_body(self) -> None:
        response = _response(429, {"detail": "Too many requests"})
        result = self.client._safe_parse_json(response)
        self.assertEqual(result, {"detail": "Too many requests"})

    @patch("apps.api_client.services.portal_request")
    def test_login_429_malformed_json(self, mock_portal_request: MagicMock) -> None:
        resp = _response(429, ValueError("No JSON"), headers={"Retry-After": "5", "content-type": "application/json"})
        mock_portal_request.return_value = resp

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._make_request("POST", "/users/login/", data={"email": "a@b.com", "password": "x"})

        self.assertTrue(ctx.exception.is_rate_limited)
        self.assertEqual(ctx.exception.retry_after, 5)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_retry_respects_large_retry_after(self, mock_portal_request: MagicMock, _mock_sleep: MagicMock) -> None:
        """503 with Retry-After: 60 -> no retry, raises with retry_after=60"""
        mock_portal_request.return_value = _response(503, {"error": "Service unavailable"}, headers={"Retry-After": "60"})

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.retry_after, 60)
        # Should NOT have retried - only 1 call
        self.assertEqual(mock_portal_request.call_count, 1)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_retry_503_small_retry_after(self, mock_portal_request: MagicMock, _mock_sleep: MagicMock) -> None:
        """503 with Retry-After: 1 -> still retries normally"""
        mock_portal_request.side_effect = [
            _response(503, {"error": "Service unavailable"}, headers={"Retry-After": "1"}),
            _response(200, {"success": True, "data": {"summary": {}}}),
        ]

        data = self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2}, idempotent=True)

        self.assertTrue(data["success"])
        self.assertEqual(mock_portal_request.call_count, 2)
