"""Integration tests use disposable media even when they select development settings."""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from services.platform.tests.media import isolated_media


@pytest.fixture(scope="session", autouse=True)
def isolated_test_media() -> Iterator[None]:
    with isolated_media():
        yield


@dataclass(frozen=True)
class _Route:
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...]


class LocalSite:
    """A throwaway HTTP site on 127.0.0.1 whose answers a test sets per path.

    A path with a query string is looked up as written first, then without its query. Anything
    unrouted answers 404. Nothing is cached, so a test can load the same URL twice.
    """

    def __init__(self) -> None:
        routes: dict[str, _Route] = {}
        self._routes = routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature
                pass

            def _answer(self) -> None:
                route = routes.get(self.path) or routes.get(self.path.split("?", 1)[0])
                if route is None:
                    route = _Route(404, "text/plain", b"", ())
                self.send_response(route.status)
                self.send_header("Content-Type", route.content_type)
                self.send_header("Content-Length", str(len(route.body)))
                self.send_header("Cache-Control", "no-store")
                for name, value in route.headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(route.body)

            def do_GET(self) -> None:
                self._answer()

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self._answer()

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def route(
        self,
        path: str,
        body: str | bytes = "",
        *,
        status: int = 200,
        content_type: str = "text/html",
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = body.encode() if isinstance(body, str) else body
        self._routes[path] = _Route(status, content_type, raw, tuple((headers or {}).items()))

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self._server.server_port}{path}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def local_site() -> Iterator[LocalSite]:
    site = LocalSite()
    yield site
    site.close()
