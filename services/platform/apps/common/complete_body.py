"""Refuse a request body that ends before its Content-Length, instead of handing on a shorter one.

The reverse proxy forwards what it has when a client stops sending: a body slower than Caddy's
read_body limit, or a client that gave up. gunicorn then returns end-of-input early, and Django
would parse the cut-off body as the whole request, saving a ticket reply without its attachment
while the browser shows an error and the customer resends it. Reading past the end of a body that
was shorter than declared raises OSError, which Django reports as UnreadablePostError, so the view
never sees a partial request.

This module and its tests (tests/common/test_complete_body.py) are identical in both services.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, BinaryIO

WSGIApp = Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]


class BodyEndedEarly(OSError):  # noqa: N818  # names what happened; Django reads OSError as unreadable
    """The request body ended before the length its Content-Length declared."""


class CompleteBodyInput:
    """A wsgi.input that raises when the body ends before ``length`` bytes."""

    def __init__(self, stream: BinaryIO, length: int) -> None:
        self._stream = stream
        self._remaining = length

    def _ended_early(self) -> BodyEndedEarly:
        return BodyEndedEarly(f"request body ended {self._remaining} bytes before its declared length")

    def read(self, size: int = -1) -> bytes:
        """Exactly ``size`` bytes (or the rest of the body); a body that ends sooner raises."""
        wanted = self._remaining if size is None or size < 0 else min(size, self._remaining)
        chunks: list[bytes] = []
        got = 0
        while got < wanted:
            chunk = self._stream.read(wanted - got)
            if not chunk:
                raise self._ended_early()
            chunks.append(chunk)
            got += len(chunk)
            self._remaining -= len(chunk)
        return b"".join(chunks)

    def readline(self, size: int = -1) -> bytes:
        """One line, as the stream returns it; a body that ends before its length raises."""
        wanted = self._remaining if size is None or size < 0 else min(size, self._remaining)
        if wanted <= 0:
            return b""
        line = self._stream.readline(wanted)
        self._remaining -= len(line)
        if not line or (len(line) < wanted and not line.endswith(b"\n")):
            raise self._ended_early()
        return line


def require_complete_bodies(app: WSGIApp) -> WSGIApp:
    """Wrap a WSGI application so a request body shorter than its Content-Length is an error."""

    def guarded(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > 0:
            environ["wsgi.input"] = CompleteBodyInput(environ["wsgi.input"], length)
        return app(environ, start_response)

    return guarded
