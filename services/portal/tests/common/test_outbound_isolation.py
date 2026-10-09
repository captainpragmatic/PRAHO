"""A Platform call carries no cookie, and nothing one thread's call receives can ride on another's.

These run the real ``portal_request`` against a real local HTTP server, so what is tested is
``requests``' own cookie handling, not a mock of it. Under threaded workers two customers'
requests share a process; a cookie a Platform response set while serving one of them must
never be sent on the other's call.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import requests.sessions
from django.test import SimpleTestCase, override_settings

from apps.common import outbound_http
from apps.common.outbound_http import OutboundSecurityError, portal_request

HOLD_SECONDS = 5


class _PlatformStub(http.server.BaseHTTPRequestHandler):
    """Answers every GET; `/set...` paths also set a session cookie, as a misbehaving Platform might."""

    server: _RecordingServer

    def do_GET(self) -> None:
        self.server.seen.append((self.path, self.headers.get("Cookie")))
        self.send_response(200)
        if self.path.startswith("/set"):
            self.send_header("Set-Cookie", "sessionid=customer-x; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


class _RecordingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _PlatformStub)
        self.seen: list[tuple[str, str | None]] = []

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}{path}"

    def cookie_sent_on(self, path: str) -> str | None:
        return dict(self.seen)[path]


@contextmanager
def _platform() -> Iterator[_RecordingServer]:
    server = _RecordingServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@override_settings(PLATFORM_API_ALLOW_INSECURE_HTTP=True)
class OutboundIsolationTests(SimpleTestCase):
    def test_a_cookie_one_call_received_never_rides_on_another_threads_call(self) -> None:
        # Thread A (customer X) is held right after requests has stored its response's cookies,
        # before any clean-up runs; customer Y's call is made in that window.
        stored, release = threading.Event(), threading.Event()
        store_cookies = requests.sessions.extract_cookies_to_jar

        def store_then_hold(jar: Any, request: Any, response: Any) -> None:
            store_cookies(jar, request, response)
            if threading.current_thread().name == "customer-x":
                stored.set()
                release.wait(HOLD_SECONDS)

        with _platform() as platform, patch("requests.sessions.extract_cookies_to_jar", side_effect=store_then_hold):
            customer_x = threading.Thread(target=portal_request, args=("GET", platform.url("/set")), name="customer-x")
            customer_x.start()
            self.assertTrue(stored.wait(HOLD_SECONDS), "customer X's call never reached the cookie store")
            try:
                portal_request("GET", platform.url("/next"))  # customer Y, on this thread
            finally:
                release.set()
                customer_x.join(HOLD_SECONDS)

        self.assertIsNone(platform.cookie_sent_on("/next"))

    def test_the_session_never_stores_a_cookie_a_platform_response_sets(self) -> None:
        # Checked inside the store, before portal_request's own clean-up could hide it.
        jar_sizes: list[int] = []
        store_cookies = requests.sessions.extract_cookies_to_jar

        def store_and_measure(jar: Any, request: Any, response: Any) -> None:
            store_cookies(jar, request, response)
            jar_sizes.append(len(jar))

        with _platform() as platform, patch("requests.sessions.extract_cookies_to_jar", side_effect=store_and_measure):
            portal_request("GET", platform.url("/set"))
            portal_request("GET", platform.url("/after"))

        self.assertEqual(jar_sizes, [0, 0])
        self.assertIsNone(platform.cookie_sent_on("/after"))

    def test_each_thread_has_its_own_session(self) -> None:
        mine = outbound_http._get_session()
        self.assertIs(outbound_http._get_session(), mine)  # stable within a thread
        theirs: list[object] = []
        other = threading.Thread(target=lambda: theirs.append(outbound_http._get_session()))
        other.start()
        other.join(HOLD_SECONDS)
        self.assertEqual(len(theirs), 1)
        self.assertIsNot(theirs[0], mine)

    def test_a_caller_supplied_cookie_header_is_refused(self) -> None:
        with _platform() as platform:
            for name in ("Cookie", "cookie", "COOKIE"):
                with self.subTest(header=name), self.assertRaises(OutboundSecurityError):
                    portal_request("GET", platform.url("/refused"), headers={name: "sessionid=customer-x"})
        self.assertEqual(platform.seen, [])

    def test_a_timeout_that_is_not_positive_is_refused_not_replaced_by_the_default(self) -> None:
        # `timeout or default` turned a computed 0 into the 30 s default.
        with _platform() as platform:
            for timeout in (0, 0.0, -1):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    portal_request("GET", platform.url("/zero"), timeout=timeout)
        self.assertEqual(platform.seen, [])

    def test_a_forked_worker_starts_with_fresh_sessions(self) -> None:
        before = outbound_http._get_session()
        outbound_http.reset_after_fork()
        after = outbound_http._get_session()
        self.assertIsNot(after, before)
        with _platform() as platform:
            portal_request("GET", platform.url("/set"))
            portal_request("GET", platform.url("/after-fork"))
        self.assertIsNone(platform.cookie_sent_on("/after-fork"))
