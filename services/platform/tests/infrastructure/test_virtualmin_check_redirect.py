"""The Virtualmin reachability check must treat a redirect as proof the HTTPS listener answered.

safe_urlopen no longer follows redirects, so a Webmin that redirects the HEAD request (for
example to its login page) surfaces as an HTTPError 3xx. The listener answered, so the
check passes; the Location header is never followed or echoed into the result.
"""

from __future__ import annotations

import io
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.infrastructure.validation_service import NodeValidationService

_REDIRECT_CODES = (301, 302, 303, 307, 308)


def _http_error(code: int, reason: str = "Redirect") -> urllib.error.HTTPError:
    headers = Message()
    headers["Location"] = "https://attacker.example.net/secret"
    return urllib.error.HTTPError("https://203.0.113.10:10000/", code, reason, headers, io.BytesIO(b""))


class VirtualminCheckRedirectTests(SimpleTestCase):
    def _check(self, error: Exception):
        deployment = MagicMock()
        deployment.ipv4_address = "203.0.113.10"
        service = NodeValidationService(timeout=5)
        with patch("apps.infrastructure.validation_service.safe_urlopen", side_effect=error):
            return service._check_virtualmin(deployment)

    def test_redirect_answers_count_as_a_live_listener(self) -> None:
        for code in _REDIRECT_CODES:
            with self.subTest(code=code):
                result = self._check(_http_error(code))
                self.assertTrue(result.passed, result.message)
                self.assertEqual(result.message, "HTTPS listener answered with a redirect")
                self.assertNotIn("attacker.example.net", result.message)
                self.assertNotIn("attacker.example.net", str(result.details))

    def test_server_error_still_fails(self) -> None:
        result = self._check(_http_error(500, "Internal Server Error"))
        self.assertFalse(result.passed)
        self.assertIn("500", result.message)

    def test_auth_required_still_passes(self) -> None:
        result = self._check(_http_error(401, "Unauthorized"))
        self.assertTrue(result.passed)
