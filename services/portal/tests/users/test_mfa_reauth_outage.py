"""An outage during MFA re-authentication is not a wrong password and spends no attempt.

`mfa_backup_codes_view` and `mfa_disable_view` read every PlatformAPIError as a credential
failure: they told the customer to check their password and marked a "reauth" failure, so five
tries during an outage, or while Platform refused the portal's signature, locked them out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

SIGNATURE_REFUSED = PlatformAPIError(
    "Platform refused the portal's request authentication",
    status_code=401,
    response_data={"error": "HMAC authentication failed"},
    is_unavailable=True,
)
CREDENTIALS_REJECTED = PlatformAPIError("Rejected credentials", status_code=403)


@override_settings(
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
)
class MFAReauthenticationOutageTests(SimpleTestCase):
    form: ClassVar[dict[str, str]] = {"password": "Original-secure123!", "token": "12345678"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com"})
        session.save()

    def _post(self, view: str, error: PlatformAPIError) -> _MonkeyPatchedWSGIResponse:
        platform_call = "regenerate_backup_codes" if view == "users:mfa_backup_codes" else "disable_mfa"
        with (
            patch(
                "apps.users.views.api_client.get_customer_profile",
                return_value={"mfa_enabled": True, "backup_codes_count": 5},
            ),
            patch(f"apps.users.views.api_client.{platform_call}", side_effect=error),
        ):
            return self.client.post(reverse(view), self.form)

    def test_an_outage_is_reported_as_one_and_counts_no_attempt(self) -> None:
        for view in ("users:mfa_backup_codes", "users:mfa_disable"):
            with self.subTest(view=view):
                response = self._post(view, SIGNATURE_REFUSED)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "Check your password")
                self.assertContains(response, "temporarily unavailable")
                self.assertNotEqual(getattr(response.wsgi_request, "_portal_auth_outcome", None), "failure")

    def test_control_a_rejected_credential_still_counts(self) -> None:
        for view in ("users:mfa_backup_codes", "users:mfa_disable"):
            with self.subTest(view=view):
                response = self._post(view, CREDENTIALS_REJECTED)
                self.assertContains(response, "Check your password")
                self.assertEqual(getattr(response.wsgi_request, "_portal_auth_outcome", None), "failure")
