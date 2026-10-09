"""
Thread safety tests for PlatformAPIClient.

Concurrent calls from one shared client, through the real ``portal_request``, to a local
server that verifies every HMAC signature the way Platform does. Each call's signature must
cover exactly the body that arrived with it, and each caller must get its own answer: nothing
one thread signs or receives may end up on another thread's call.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import hmac
import http.server
import json
import threading
import urllib.parse
from typing import Any

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient

SECRET = "test-secret-for-thread-safety-0123456789"
PORTAL_ID = "portal-001"
THREADS = 8
CALLS_PER_THREAD = 5


def _signature_is_genuine(method: str, path: str, headers: Any, body: bytes) -> bool:
    """Recompute the canonical-string signature from what actually arrived."""
    parsed = urllib.parse.urlsplit(path)
    query = sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    normalized = parsed.path + ("?" + urllib.parse.urlencode(query) if query else "")
    body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    canonical = "\n".join(
        [method, normalized, "application/json", body_hash, headers["X-Portal-Id"], headers["X-Nonce"], headers["X-Timestamp"]]
    )
    expected = hmac.new(SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return headers["X-Body-Hash"] == body_hash and hmac.compare_digest(expected, headers["X-Signature"])


class _VerifyingPlatform(http.server.BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        caller = int(self.path.rstrip("/").rsplit("/", 1)[-1])
        genuine = _signature_is_genuine("GET", self.path, self.headers, body)
        with self.server.lock:
            self.server.verdicts.append(genuine)
            self.server.nonces.append(self.headers["X-Nonce"])
        payload = json.dumps({"success": True, "user": {"id": caller}}).encode()
        self.send_response(200 if genuine else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: Any) -> None:
        pass


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _VerifyingPlatform)
        self.lock = threading.Lock()
        self.verdicts: list[bool] = []
        self.nonces: list[str] = []


class PlatformAPIClientThreadSafetyTests(SimpleTestCase):
    def test_concurrent_calls_each_carry_their_own_signature_and_get_their_own_answer(self) -> None:
        platform = _Server()
        serving = threading.Thread(target=platform.serve_forever, daemon=True)
        serving.start()
        self.addCleanup(platform.server_close)
        self.addCleanup(platform.shutdown)
        base_url = f"http://127.0.0.1:{platform.server_address[1]}/api"

        with override_settings(
            PLATFORM_API_BASE_URL=base_url,
            PLATFORM_API_SECRET=SECRET,
            PLATFORM_API_ALLOW_INSECURE_HTTP=True,
            PLATFORM_API_TIMEOUT=5,
            PORTAL_ID=PORTAL_ID,
        ):
            client = PlatformAPIClient()  # one client shared by every thread, as in production

            def caller(caller_id: int) -> list[int]:
                return [client._make_request("GET", f"/test/{caller_id}/")["user"]["id"] for _ in range(CALLS_PER_THREAD)]

            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
                answers = dict(zip(range(THREADS), pool.map(caller, range(THREADS)), strict=True))

        self.assertEqual(answers, {caller_id: [caller_id] * CALLS_PER_THREAD for caller_id in range(THREADS)})
        self.assertEqual(len(platform.verdicts), THREADS * CALLS_PER_THREAD)
        self.assertTrue(all(platform.verdicts), "a signature did not match the body it arrived with")
        self.assertEqual(len(set(platform.nonces)), len(platform.nonces), "a nonce was reused across calls")
