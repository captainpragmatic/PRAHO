"""
Thread safety tests for PlatformAPIClient.

Verifies that concurrent requests don't cross-contaminate headers
via shared mutable state on the singleton instance.
"""

from __future__ import annotations

import concurrent.futures
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient


def _response(status_code: int, payload: object) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.headers = {}
    response.json.return_value = payload
    return response


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
)
class PlatformAPIClientThreadSafetyTests(SimpleTestCase):
    def test_concurrent_requests_do_not_share_headers(self) -> None:
        """Each thread should see its own last_request_headers, not another thread's."""
        client = PlatformAPIClient()
        captured_headers: dict[int, dict[str, str]] = {}

        def make_request_and_capture(thread_id: int) -> None:
            mock_resp = _response(200, {"success": True, "user": {"id": thread_id, "customer_id": 1}})
            with patch("apps.api_client.services.portal_request", return_value=mock_resp):
                client._make_request("GET", f"/test/{thread_id}/")
                headers = getattr(client._thread_local, "last_request_headers", {})
                captured_headers[thread_id] = dict(headers)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(make_request_and_capture, i) for i in range(4)]
            for f in futures:
                f.result()

        # Each thread should have captured headers — they should all have nonces
        for thread_id, headers in captured_headers.items():
            self.assertIn("X-Nonce", headers, f"Thread {thread_id} missing X-Nonce")

        # All nonces should be unique (not shared across threads)
        nonces = [h["X-Nonce"] for h in captured_headers.values()]
        self.assertEqual(len(set(nonces)), len(nonces), "Nonce collision detected across threads")
