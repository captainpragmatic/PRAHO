"""
Mock Virtualmin HTTP server for testing the real gateway's HTTP layer.

Mimics Virtualmin's remote.cgi endpoint using stdlib http.server.
Reuses MockVirtualminGateway for state management and response generation.

Usage:
    # Start from command line
    python -m tests.mocks.virtualmin_mock_server --port 10000

    # Use in tests
    from tests.mocks.virtualmin_mock_server import VirtualminMockServer
    server = VirtualminMockServer(port=10000)
    server.start()
    # ... run tests against http://localhost:10000/virtual-server/remote.cgi ...
    server.stop()
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# Lazy import to allow standalone usage without Django
_mock_gateway = None


def _get_mock_gateway() -> Any:
    global _mock_gateway
    if _mock_gateway is None:
        from tests.mocks.virtualmin_mock import MockVirtualminGateway

        _mock_gateway = MockVirtualminGateway(server_hostname="localhost")
    return _mock_gateway


class VirtualminRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler mimicking Virtualmin's remote.cgi endpoint."""

    server: VirtualminHTTPServer  # type: ignore[assignment]

    def do_GET(self) -> None:
        """Handle GET requests to remote.cgi."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Flatten single-value params
        flat_params: dict[str, str] = {k: v[0] if len(v) == 1 else v for k, v in params.items()}  # type: ignore[misc]

        # Extract program name
        program = flat_params.pop("program", "")
        if not program:
            self._send_error(400, "Missing 'program' parameter")
            return

        # Check basic auth
        auth = self.headers.get("Authorization")
        if auth is None and not self.server.allow_anonymous:
            self._send_error(401, "Authentication required")
            return

        # Delegate to mock gateway
        gateway = self.server.gateway
        result = gateway.call(program, flat_params)

        if result.is_ok():
            response = result.unwrap()
            response_data = {
                "command": program,
                "status": "success" if response.success else "failure",
                "data": response.data,
            }
            if not response.success:
                response_data["error"] = response.data.get("error", "")
            self._send_json(200, response_data)
        else:
            error = result.unwrap_err()
            self._send_json(400, {
                "command": program,
                "status": "failure",
                "error": str(error),
            })

    def do_POST(self) -> None:
        """Handle POST requests (same as GET for Virtualmin)."""
        self.do_GET()

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"status": "failure", "error": message})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stderr logging in tests."""
        logger.debug(format, *args)


class VirtualminHTTPServer(HTTPServer):
    """HTTPServer subclass that holds reference to the mock gateway."""

    def __init__(
        self,
        server_address: tuple[str, int],
        gateway: Any,
        allow_anonymous: bool = False,
    ) -> None:
        self.gateway = gateway
        self.allow_anonymous = allow_anonymous
        super().__init__(server_address, VirtualminRequestHandler)


class VirtualminMockServer:
    """
    Convenience wrapper for starting/stopping the mock HTTP server.

    Thread-safe: runs the server in a daemon thread.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 10000,
        gateway: Any | None = None,
        allow_anonymous: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.gateway = gateway or _get_mock_gateway()
        self.allow_anonymous = allow_anonymous
        self._server: VirtualminHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def remote_cgi_url(self) -> str:
        return f"{self.base_url}/virtual-server/remote.cgi"

    def start(self) -> None:
        """Start the mock server in a background thread."""
        self._server = VirtualminHTTPServer(
            (self.host, self.port),
            self.gateway,
            allow_anonymous=self.allow_anonymous,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"🚀 [MockVirtualmin] Server started at {self.base_url}")

    def stop(self) -> None:
        """Stop the mock server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("✅ [MockVirtualmin] Server stopped")


if __name__ == "__main__":
    import argparse
    import os
    import sys

    # Set up Django before importing mock gateway
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

    import django

    django.setup()

    parser = argparse.ArgumentParser(description="Virtualmin Mock HTTP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=10000, help="Port number")
    args = parser.parse_args()

    from tests.mocks.virtualmin_mock import MockVirtualminGateway

    gateway = MockVirtualminGateway(server_hostname=f"{args.host}:{args.port}")
    # Seed some domains for manual testing
    gateway.seed_domain("example.com", disk_usage_mb=150, bandwidth_usage_mb=500)
    gateway.seed_domain("test.ro", disk_usage_mb=50, bandwidth_usage_mb=100)

    server = VirtualminMockServer(
        host=args.host,
        port=args.port,
        gateway=gateway,
        allow_anonymous=True,
    )
    server.start()
    print(f"Virtualmin mock server running at {server.base_url}")
    print(f"Remote CGI endpoint: {server.remote_cgi_url}")
    print("Press Ctrl+C to stop")

    try:
        server._thread.join()
    except KeyboardInterrupt:
        server.stop()
        print("\nServer stopped.")
