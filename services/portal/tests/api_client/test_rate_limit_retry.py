from __future__ import annotations

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

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_retries_allowlisted_read_post_on_429(self, mock_portal_request: MagicMock, _mock_sleep: MagicMock) -> None:
        mock_portal_request.side_effect = [
            _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "1"}),
            _response(200, {"success": True, "data": {"summary": {}}}),
        ]

        data = self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2})

        self.assertTrue(data["success"])
        self.assertEqual(mock_portal_request.call_count, 2)

    @patch("apps.api_client.services.time.sleep")
    @patch("apps.api_client.services.portal_request")
    def test_make_request_regenerates_headers_for_each_retry(
        self, mock_portal_request: MagicMock, _mock_sleep: MagicMock
    ) -> None:
        mock_portal_request.side_effect = [
            _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "1"}),
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
            data = self.client._make_request("POST", "/tickets/summary/", data={"customer_id": 1, "user_id": 2})

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

    def test_compute_retry_delay_honors_retry_after_with_cap(self) -> None:
        response = _response(429, {"detail": "Too many requests"}, headers={"Retry-After": "30"})

        delay = self.client._compute_retry_delay(response, attempt=0)

        self.assertEqual(delay, self.client.max_retry_wait_seconds)

    def test_binary_error_uses_detail_message_and_retry_metadata(self) -> None:
        response = _response(429, {"detail": "Wait please", "retry_after": 9})

        with self.assertRaises(PlatformAPIError) as ctx:
            self.client._handle_binary_response(response, "/billing/invoices/INV-1/pdf/")

        self.assertTrue(ctx.exception.is_rate_limited)
        self.assertEqual(ctx.exception.retry_after, 9)
        self.assertIn("Wait please", str(ctx.exception))
