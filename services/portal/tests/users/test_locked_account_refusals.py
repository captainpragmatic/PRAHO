"""A locked account, or 2FA that is off, is said so and spends no attempt.

Platform answers both before it checks the password (codes `account_locked` and
`mfa_not_enabled`). The pages read every other refusal as a wrong credential: they told the
customer to check their password and charged the "reauth" budget, while the right password could
not pass until the lock ran out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.users.forms import TOTPSetupForm
from apps.users.views import _setup_refusal

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

ACCOUNT_LOCKED = PlatformAPIError(
    "Account temporarily locked", status_code=400, response_data={"success": False, "code": "account_locked"}
)
MFA_NOT_ENABLED = PlatformAPIError(
    "Two-factor authentication is not enabled",
    status_code=400,
    response_data={"success": False, "code": "mfa_not_enabled"},
)
LOCKED_MESSAGE = "Too many attempts. Please wait and try again."
WRONG = PlatformAPIError("The password or the code is incorrect.", status_code=400, response_data={"success": False})


@override_settings(
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
)
class LockedAccountRefusalTests(SimpleTestCase):
    form: ClassVar[dict[str, str]] = {"password": "Original-secure123!", "token": "12345678"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com"})
        session.save()

    def post(self, view: str, error: PlatformAPIError) -> _MonkeyPatchedWSGIResponse:
        platform_call = "regenerate_backup_codes" if view == "users:mfa_backup_codes" else "disable_mfa"
        with (
            patch(
                "apps.users.views.api_client.get_customer_profile",
                return_value={"mfa_enabled": True, "backup_codes_count": 5},
            ),
            patch(f"apps.users.views.api_client.{platform_call}", side_effect=error),
        ):
            return self.client.post(reverse(view), self.form)

    def charged(self, response: _MonkeyPatchedWSGIResponse) -> bool:
        return getattr(response.wsgi_request, "_portal_auth_outcome", None) == "failure"

    def test_a_locked_account_is_said_so_and_spends_no_attempt(self) -> None:
        for view in ("users:mfa_backup_codes", "users:mfa_disable"):
            with self.subTest(view=view):
                response = self.post(view, ACCOUNT_LOCKED)
                self.assertContains(response, LOCKED_MESSAGE)
                self.assertNotContains(response, "Check your password")
                self.assertFalse(self.charged(response))

    def test_2fa_that_is_off_sends_the_customer_to_the_2fa_page_and_spends_no_attempt(self) -> None:
        for view in ("users:mfa_backup_codes", "users:mfa_disable"):
            with self.subTest(view=view):
                response = self.post(view, MFA_NOT_ENABLED)
                self.assertRedirects(response, reverse("users:mfa_management"), fetch_redirect_response=False)
                self.assertFalse(self.charged(response))

    def test_control_a_wrong_credential_still_counts(self) -> None:
        for view in ("users:mfa_backup_codes", "users:mfa_disable"):
            with self.subTest(view=view):
                response = self.post(view, WRONG)
                self.assertContains(response, "Check your password")
                self.assertTrue(self.charged(response))

    def test_a_locked_account_on_the_password_change_page_is_said_so(self) -> None:
        data = {
            "current_password": "Original-secure123!",
            "new_password": "Another-secure123!",
            "confirm_password": "Another-secure123!",
            "token": "",
        }
        with patch("apps.users.views.api_client.update_customer_password", side_effect=ACCOUNT_LOCKED):
            response = self.client.post(reverse("users:change_password"), data)
        self.assertContains(response, LOCKED_MESSAGE)

    def test_a_locked_account_confirming_2fa_setup_is_said_so_and_spends_no_attempt(self) -> None:
        request = RequestFactory().post("/mfa/setup/")
        form = TOTPSetupForm(data={"token": "123456", "password": "Original-secure123!"})
        form.is_valid()
        self.assertIsNone(_setup_refusal(request, ACCOUNT_LOCKED, form))
        self.assertIn(LOCKED_MESSAGE, form.non_field_errors())
        self.assertNotEqual(getattr(request, "_portal_auth_outcome", None), "failure")
