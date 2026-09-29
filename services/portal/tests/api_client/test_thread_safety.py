"""
Thread safety tests for PlatformAPIClient.

Verifies that concurrent requests don't cross-contaminate headers
via shared mutable state on the singleton instance.
"""

from __future__ import annotations

import concurrent.futures
import threading
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client import services as api_client_services
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
        sent_headers: dict[int, dict[str, str]] = {}
        original_transport = api_client_services.portal_request
        requests_finished = threading.Barrier(4)

        def mock_request(*, url: str, headers: dict[str, str], **_: object) -> MagicMock:
            thread_id = int(url.rstrip("/").rsplit("/", 1)[-1])
            sent_headers[thread_id] = dict(headers)
            return _response(200, {"success": True, "user": {"id": thread_id, "customer_id": 1}})

        def make_request_and_capture(thread_id: int) -> None:
            result = client._make_request("GET", f"/test/{thread_id}/")
            # All threads must finish writing their headers before any reads them.
            requests_finished.wait(timeout=5)
            self.assertEqual(result["user"]["id"], thread_id)
            headers = getattr(client._thread_local, "last_request_headers", {})
            captured_headers[thread_id] = dict(headers)

        # One patch covers the entire pool lifetime. Per-thread patches of the
        # same global can restore out of order and leak mocks into later tests.
        with (
            patch("apps.api_client.services.portal_request", side_effect=mock_request),
            concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor,
        ):
            futures = [executor.submit(make_request_and_capture, i) for i in range(4)]
            for f in futures:
                f.result()

        self.assertIs(api_client_services.portal_request, original_transport)
        self.assertEqual(len(captured_headers), 4)
        self.assertEqual(captured_headers, sent_headers)
        # Each thread should have captured headers — they should all have nonces
        for thread_id, headers in captured_headers.items():
            self.assertIn("X-Nonce", headers, f"Thread {thread_id} missing X-Nonce")

        # All nonces should be unique (not shared across threads)
        nonces = [h["X-Nonce"] for h in captured_headers.values()]
        self.assertEqual(len(set(nonces)), len(nonces), "Nonce collision detected across threads")
