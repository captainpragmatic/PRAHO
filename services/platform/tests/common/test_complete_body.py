"""A request body that ends before its Content-Length is an error, never a shorter request.

Caddy forwards what it has when a client stops sending (a body slower than its read_body limit, or a
client that gave up), and Django would otherwise parse the cut-off body as the whole request: a
ticket reply saved without its attachment, while the browser shows an error and the customer
resends it. This test file and apps/common/complete_body.py are identical in both services.
"""

from __future__ import annotations

import io
from typing import Any
from unittest.mock import patch

from django.core.handlers.wsgi import WSGIRequest
from django.http import UnreadablePostError
from django.test import RequestFactory, SimpleTestCase

from apps.common.complete_body import CompleteBodyInput, require_complete_bodies

BOUNDARY = "BoUnDaRy"
MULTIPART = (
    f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="reply"\r\n\r\nhello\r\n'
    f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="attachment"; filename="a.txt"\r\n'
    f"Content-Type: text/plain\r\n\r\n{'x' * 4000}\r\n--{BOUNDARY}--\r\n"
).encode()


def _request(body: bytes, declared: int) -> WSGIRequest:
    environ: dict[str, Any] = RequestFactory().post("/").environ
    environ.update(
        {
            "CONTENT_TYPE": f"multipart/form-data; boundary={BOUNDARY}",
            "CONTENT_LENGTH": str(declared),
            "wsgi.input": io.BytesIO(body),
        }
    )
    seen: dict[str, Any] = {}

    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        seen["environ"] = environ
        return []

    require_complete_bodies(app)(environ, lambda *args: None)
    return WSGIRequest(seen["environ"])


class CompleteBodyTests(SimpleTestCase):
    def test_a_complete_multipart_body_parses_as_before(self) -> None:
        request = _request(MULTIPART, len(MULTIPART))
        self.assertEqual(request.POST["reply"], "hello")
        self.assertEqual(request.FILES["attachment"].read(), b"x" * 4000)

    def test_a_cut_off_body_is_unreadable_not_a_shorter_request(self) -> None:
        cut = MULTIPART[: len(MULTIPART) // 2]  # inside the attachment
        request = _request(cut, len(MULTIPART))
        with self.assertRaises(UnreadablePostError):
            request.POST  # noqa: B018 -- reading it is the point

    def test_reading_the_raw_body_of_a_cut_off_request_fails_too(self) -> None:
        request = _request(b'{"a": 1', 20)
        with self.assertRaises(UnreadablePostError):
            request.body  # noqa: B018 -- reading it is the point

    def test_reads_past_the_declared_length_are_not_errors(self) -> None:
        stream = CompleteBodyInput(io.BytesIO(b"abcdef"), 6)
        self.assertEqual(stream.read(4), b"abcd")
        self.assertEqual(stream.read(), b"ef")
        self.assertEqual(stream.read(10), b"")
        self.assertEqual(stream.readline(), b"")

    def test_a_short_line_read_fails(self) -> None:
        stream = CompleteBodyInput(io.BytesIO(b"ab\n"), 10)
        self.assertEqual(stream.readline(), b"ab\n")
        with self.assertRaises(OSError):
            stream.readline()

    def test_requests_without_a_body_are_untouched(self) -> None:
        environ: dict[str, Any] = RequestFactory().get("/").environ
        original = environ["wsgi.input"]
        require_complete_bodies(lambda environ, start_response: [])(environ, lambda *args: None)
        self.assertIs(environ["wsgi.input"], original)


class DeployedApplicationTests(SimpleTestCase):
    def test_the_deployed_application_guards_request_bodies(self) -> None:
        from config import wsgi  # noqa: PLC0415 -- the module gunicorn loads

        environ: dict[str, Any] = RequestFactory().post("/", data=b"x" * 10, content_type="text/plain").environ
        seen: dict[str, Any] = {}

        def handler(_handler: Any, environ: dict[str, Any], start_response: Any) -> list[bytes]:
            seen["input"] = environ["wsgi.input"]
            return []

        with patch("django.core.handlers.wsgi.WSGIHandler.__call__", handler):
            wsgi.application(environ, lambda *args: None)
        self.assertIsInstance(seen["input"], CompleteBodyInput)
