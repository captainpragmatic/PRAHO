"""Failed login pages must never redisplay submitted credentials."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse


@override_settings(
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
)
class LoginSecretRenderingTests(SimpleTestCase):
    password = "SuperSecret123!"
    mfa_token = "654321"

    def _post_login(
        self, error: Exception | None = None, *, email: str = "someone@example.com"
    ) -> _MonkeyPatchedWSGIResponse:
        with patch("apps.users.views.api_client.authenticate_customer", return_value=None, side_effect=error):
            return self.client.post(
                reverse("users:login"),
                {"email": email, "password": self.password, "mfa_token": self.mfa_token},
            )

    def _assert_secrets_not_rendered(self, response: _MonkeyPatchedWSGIResponse) -> None:
        self.assertContains(response, 'id="login-form"')
        for name in ("password", "mfa_token"):
            field = re.search(rf'<input\b[^>]*\bname="{name}"[^>]*>', response.content.decode())
            self.assertIsNotNone(field, f"Missing login input: {name}")
            assert field is not None
            # Neither secret is ever written back into the page.
            self.assertNotRegex(field.group(), r'\bvalue\s*=\s*"[^"]+"')
            # The password stays masked; the one-time code stays visible while typing.
            self.assertIn('type="password"' if name == "password" else 'type="text"', field.group())
        self.assertNotContains(response, self.password)
        self.assertNotContains(response, self.mfa_token)

    def test_wrong_credentials_do_not_echo_secrets(self) -> None:
        response = self._post_login()
        self.assertContains(response, "Invalid email address or password")
        self.assertNotContains(response, self.password)
        self._assert_secrets_not_rendered(response)

    def test_generic_errors_do_not_echo_secrets(self) -> None:
        for error, message in (
            (PlatformAPIError("authentication failed"), "Authentication service is temporarily unavailable"),
            (RuntimeError("authentication failed"), "An unexpected error occurred"),
        ):
            with self.subTest(error=type(error).__name__):
                response = self._post_login(error)
                self.assertContains(response, message)
                self.assertNotContains(response, self.password)
                self._assert_secrets_not_rendered(response)

    def test_outages_omit_secret_values_without_mutating_bound_data(self) -> None:
        for error in (
            PlatformAPIError("offline", is_unavailable=True),
            PlatformAPIError("maintenance", status_code=503, response_data={"error": "maintenance"}),
        ):
            with self.subTest(error=error):
                response = self._post_login(error)
                self.assertContains(response, "Authentication service is temporarily unavailable")
                self._assert_secrets_not_rendered(response)
                self.assertEqual(response.context["form"].data["password"], self.password)
                self.assertEqual(response.context["form"].data["mfa_token"], self.mfa_token)

    def test_rate_limited_login_does_not_echo_secrets(self) -> None:
        response = self._post_login(
            PlatformAPIError("throttled", status_code=429, is_rate_limited=True, retry_after=30)
        )
        self.assertContains(response, "Too many login attempts")
        self.assertNotContains(response, self.password)
        self._assert_secrets_not_rendered(response)

    def test_invalid_form_does_not_echo_secrets(self) -> None:
        response = self._post_login(email="invalid-email")
        self.assertIn("email", response.context["form"].errors)
        self.assertNotContains(response, self.password)
        self._assert_secrets_not_rendered(response)
