"""H7: API exception responses must not leak internal details in non-DEBUG mode."""
import json
from unittest.mock import MagicMock

from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase, override_settings

from apps.common.middleware import JSONResponseMiddleware


def _make_api_request(path: str = "/api/test/") -> HttpRequest:
    req = HttpRequest()
    req.path = path
    req.method = "GET"
    req.META["SERVER_NAME"] = "testserver"
    req.META["SERVER_PORT"] = "80"
    req.user = MagicMock(is_authenticated=False, id=None)
    return req


class APIExceptionLeakTests(SimpleTestCase):
    """H7: process_exception must return generic message when DEBUG=False."""

    def setUp(self) -> None:
        self.middleware = JSONResponseMiddleware(lambda r: HttpResponse("ok"))

    @override_settings(DEBUG=False)
    def test_non_debug_returns_generic_message(self) -> None:
        request = _make_api_request()
        exc = ValueError("secret DB column xyz_password not found")
        response = self.middleware.process_exception(request, exc)
        data = json.loads(response.content)
        self.assertEqual(data["message"], "Internal server error")
        self.assertNotIn("type", data)
        self.assertNotIn("secret", response.content.decode())
        self.assertNotIn("traceback", data)

    @override_settings(DEBUG=True)
    def test_debug_returns_full_details(self) -> None:
        request = _make_api_request()
        exc = ValueError("secret detail")
        response = self.middleware.process_exception(request, exc)
        data = json.loads(response.content)
        self.assertIn("secret detail", data["message"])
        self.assertEqual(data["type"], "ValueError")
