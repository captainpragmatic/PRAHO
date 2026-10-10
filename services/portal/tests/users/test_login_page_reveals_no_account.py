"""The portal's login page answers a refused login identically whichever email was typed.

Platform gives every non-MFA failure the same 401 (pinned on Platform by
tests/users/test_login_reveals_no_account.py). This pins the portal side: the same Platform
answer produces the same page, headers, cookies and attempt accounting for any email, once
per-request randomness (CSRF token, CSP nonce, request id) and the echoed email are normalised.
"""

import re
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.common import counters

REFUSAL = b'{"success": false, "error": "Invalid email or password"}'
# Content-Length follows the echoed email's length; the body itself is compared normalised.
# Date and Expires carry the request's time, which can tick between the two requests.
VOLATILE_HEADERS = {
    "Date",
    "Expires",
    "X-Request-ID",
    "Content-Length",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
}


def _refusal() -> requests.Response:
    response = requests.Response()
    response.status_code = 401
    response._content = REFUSAL
    response.headers["Content-Type"] = "application/json"
    return response


def _normalised(response, email: str) -> tuple[int, str, tuple, tuple]:
    body = response.content.decode()
    body = body.replace(email, "<email>")
    body = re.sub(r'(name="csrfmiddlewaretoken" value=")[^"]+', r"\1<csrf>", body)
    body = re.sub(r'nonce="[^"]+"', 'nonce="<nonce>"', body)
    headers = tuple(sorted((k, v) for k, v in response.headers.items() if k not in VOLATILE_HEADERS))
    cookies = tuple(
        sorted(
            (name, tuple(sorted((k, str(v)) for k, v in morsel.items() if v and k != "expires")))
            for name, morsel in response.cookies.items()
        )
    )
    return response.status_code, body, headers, cookies


@override_settings(
    RATE_LIMITING_ENABLED=True,
    IPWARE_TRUSTED_PROXY_LIST=["127.0.0.1/32"],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "page-reveals"}},
    PLATFORM_API_AUTH_MIN_DURATION_SECONDS=0,
)
class LoginPageRevealsNoAccountTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def _fresh_client_budget(self) -> None:
        # The per-IP budgets are database counters, shared by both emails from one test client.
        cache.clear()
        for key in ("auth_ip_attempts_127.0.0.1", "auth_volume_ip_127.0.0.1"):
            counters.reset(key)

    def _post(self, email: str):
        self.client.cookies.clear()
        with patch("apps.api_client.services.portal_request", return_value=_refusal()):
            return self.client.post(reverse("users:login"), {"email": email, "password": "Wrong-password-9"})

    def test_two_emails_get_the_same_page_headers_and_cookies(self) -> None:
        first = _normalised(self._post("someone-real@example.ro"), "someone-real@example.ro")
        self._fresh_client_budget()
        second = _normalised(self._post("nobody-at-all@example.ro"), "nobody-at-all@example.ro")
        self.assertEqual(first, second)
        self.assertEqual(first[0], 200)
        self.assertIn("Invalid email address or password", first[1])

    def test_attempt_accounting_is_the_same_for_any_email(self) -> None:
        outcomes = {}
        for email in ("someone-real@example.ro", "nobody-at-all@example.ro"):
            self._fresh_client_budget()
            statuses = [self._post(email).status_code for _ in range(6)]
            outcomes[email] = (statuses, counters.peek(f"auth_account_attempts_{email}"))
        self.assertEqual(
            outcomes["someone-real@example.ro"], outcomes["nobody-at-all@example.ro"], outcomes
        )
        statuses, attempts = outcomes["someone-real@example.ro"]
        self.assertEqual(statuses[:5], [200] * 5)
        self.assertNotEqual(statuses[5], 200)  # the sixth is throttled, the same way for both
        self.assertEqual(attempts, 5)
