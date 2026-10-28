"""safe_urlopen must never follow a redirect: the pinned, validated target is the only target."""

from __future__ import annotations

import threading
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, ResolvedTarget, safe_urlopen

_REDIRECT_CODES = (301, 302, 303, 307, 308)
_LOOPBACK = "127.0.0.1"


class _RedirectingHandler(BaseHTTPRequestHandler):
    """302s ``/start`` to ``/landed``; ``/landed`` answers 200. Records every path served."""

    redirect_code: int = 302
    served: list[str]

    def do_GET(self) -> None:
        self.served.append(self.path)
        if self.path == "/start":
            self.send_response(self.redirect_code)
            self.send_header("Location", "/landed")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


@contextmanager
def _redirecting_server(code: int) -> Iterator[tuple[HTTPServer, list[str]]]:
    served: list[str] = []
    handler = type("Handler", (_RedirectingHandler,), {"redirect_code": code, "served": served})
    server = HTTPServer((_LOOPBACK, 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, served
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class SafeUrlopenRedirectTests(SimpleTestCase):
    def _policy(self) -> OutboundPolicy:
        return OutboundPolicy(
            name="redirect_probe",
            require_https=False,
            allowed_schemes=frozenset({"http"}),
            blocked_ports=frozenset(),
            check_dns=False,
            timeout_seconds=5.0,
        )

    def _target(self, port: int) -> ResolvedTarget:
        return ResolvedTarget(
            original_url=f"http://redirect.example.test:{port}/start",
            scheme="http",
            hostname="redirect.example.test",
            port=port,
            pinned_ips=[_LOOPBACK],
            path="/start",
        )

    def test_redirect_is_refused_after_one_request(self) -> None:
        for code in _REDIRECT_CODES:
            with self.subTest(code=code), _redirecting_server(code) as (server, served):
                port = server.server_address[1]
                with (
                    patch("apps.common.outbound_http.validate_and_resolve", return_value=self._target(port)),
                    self.assertRaises(urllib.error.HTTPError) as raised,
                ):
                    safe_urlopen(f"http://redirect.example.test:{port}/start", policy=self._policy())
                raised.exception.close()
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(served, ["/start"], "the redirect target must never be requested")

    def test_policy_that_asks_for_redirects_is_refused_before_any_dns(self) -> None:
        policy = OutboundPolicy(name="wants_redirects", allow_redirects=True, max_redirects=2)
        with (
            patch("apps.common.outbound_http.socket.getaddrinfo") as resolver,
            self.assertRaises(OutboundSecurityError),
        ):
            safe_urlopen("https://example.com/", policy=policy)
        resolver.assert_not_called()
