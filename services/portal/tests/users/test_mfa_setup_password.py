"""Setting up an authenticator in the Portal needs the current password, and keeps the scanned code (#689).

- The setup form posted only the code, so a hijacked Portal session could enrol its own app.
- Every error sent the browser back to the setup page, which asked Platform for a new secret,
  so one mistyped code broke the authenticator the customer had just scanned. Errors now show
  on the same page with the same secret, which Platform keeps in a pending enrolment.
- New recovery codes waited in the session; they are now shown once, in the response.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIClient

PASSWORD = "Original-secure123!"  # test fixture, not a credential
SETUP_DATA = {
    "success": True,
    "setup_data": {"qr_code_svg": "<svg></svg>", "manual_entry_key": "PENDINGSECRETABC", "provisioning_uri": "x"},
}


def _transport(payload: dict[str, object], status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.headers = {"content-type": "application/json"}
    response.json.return_value = payload
    response.content = json.dumps(payload).encode()
    return response


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="mfa-setup-test-secret",
    PORTAL_HMAC_SECRET="mfa-setup-test-secret",
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "portal-mfa-setup"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class PortalTOTPSetupTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        production_settings = override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True)
        production_settings.enable()
        self.addCleanup(production_settings.disable)
        cache.clear()
        self.addCleanup(cache.clear)
        client_patch = patch("apps.users.views.api_client", PlatformAPIClient())
        client_patch.start()
        self.addCleanup(client_patch.stop)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com", "session_auth_hash": "original"})
        session.save()

    def post_setup(self, data: dict[str, str], *answers: MagicMock) -> tuple[Any, MagicMock]:
        with patch("apps.api_client.services.portal_request", side_effect=list(answers)) as transport:
            response = self.client.post(reverse("users:mfa_setup_totp"), data, HTTP_USER_AGENT="CustomerBrowser/2.0")
        return response, transport

    @staticmethod
    def sent_body(transport: MagicMock, call: int = 0) -> dict[str, Any]:
        return dict(json.loads(transport.call_args_list[call].kwargs["data"]))

    def test_the_setup_page_asks_for_the_current_password(self) -> None:
        with patch("apps.api_client.services.portal_request", return_value=_transport(SETUP_DATA)):
            page = self.client.get(reverse("users:mfa_setup_totp"))
        self.assertContains(page, 'name="password"')
        self.assertContains(page, 'autocomplete="current-password"')

    def test_the_password_and_the_browser_are_sent_with_the_code(self) -> None:
        enabled = _transport({"success": True, "session_auth_hash": "enabled", "backup_codes": ["12345678"] * 8})
        response, transport = self.post_setup({"token": "123456", "password": PASSWORD}, enabled)
        body = self.sent_body(transport)
        self.assertEqual((body["token"], body["password"]), ("123456", PASSWORD))
        self.assertEqual(body["client_user_agent"], "CustomerBrowser/2.0")
        self.assertEqual(response.status_code, 200)

    def test_new_codes_are_shown_in_the_response_and_kept_nowhere(self) -> None:
        codes = [f"{n:08d}" for n in range(8)]
        enabled = _transport({"success": True, "session_auth_hash": "enabled", "backup_codes": codes})
        response, _transport_mock = self.post_setup({"token": "123456", "password": PASSWORD}, enabled)
        self.assertEqual(response.status_code, 200)
        for code in codes:
            self.assertContains(response, code)
        self.assertNotIn("new_mfa_backup_codes", self.client.session)
        self.assertEqual(self.client.session["session_auth_hash"], "enabled")
        self.assertIn("no-store", response["Cache-Control"])
        # The page's regeneration form posts to the regeneration page, not back to setup.
        self.assertContains(response, f'action="{reverse("users:mfa_backup_codes")}"')

    def test_a_wrong_code_keeps_the_page_and_its_secret(self) -> None:
        refused = _transport(
            {"success": False, "code": "mfa_incorrect", "error": "The password or the code is incorrect."}, 400
        )
        with patch("apps.users.views.mark_auth_failure") as charge:
            response, transport = self.post_setup(
                {"token": "000000", "password": PASSWORD}, refused, _transport(SETUP_DATA)
            )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The password or the code is incorrect.", count=1)
        self.assertContains(response, "PENDINGSECRETABC")
        self.assertEqual(charge.call_count, 1)
        self.assertEqual(transport.call_count, 2)  # the code, then the same pending secret again

    def test_without_a_password_nothing_is_sent(self) -> None:
        response, transport = self.post_setup({"token": "123456"}, _transport(SETUP_DATA))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("/users/mfa/verify/", str(transport.call_args_list))

    def test_an_account_already_enrolled_is_not_charged_as_a_wrong_guess(self) -> None:
        already = _transport({"success": False, "code": "mfa_already_enabled", "error": "Already enabled."}, 400)
        with patch("apps.users.views.mark_auth_failure") as charge:
            response, _ = self.post_setup({"token": "123456", "password": PASSWORD}, already)
        self.assertRedirects(response, reverse("users:mfa_management"), fetch_redirect_response=False)
        charge.assert_not_called()

    def test_too_many_attempts_is_said_plainly_and_not_charged_again(self) -> None:
        throttled = _transport({"detail": "Request was throttled."}, 429)
        with patch("apps.users.views.mark_auth_failure") as charge:
            response, _ = self.post_setup({"token": "123456", "password": PASSWORD}, throttled, _transport(SETUP_DATA))
        self.assertContains(response, "Too many attempts")
        charge.assert_not_called()


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="mfa-setup-test-secret",
    PORTAL_HMAC_SECRET="mfa-setup-test-secret",
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "portal-mfa-codes"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class PortalBackupCodeRegenerationTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        production_settings = override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True)
        production_settings.enable()
        self.addCleanup(production_settings.disable)
        cache.clear()
        self.addCleanup(cache.clear)
        client_patch = patch("apps.users.views.api_client", PlatformAPIClient())
        client_patch.start()
        self.addCleanup(client_patch.stop)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com", "session_auth_hash": "original"})
        session.save()

    def test_regenerated_codes_are_shown_in_the_response_and_kept_nowhere(self) -> None:
        profile = _transport({"success": True, "profile": {"mfa_enabled": True, "backup_codes_count": 2}})
        codes = [f"9{n:07d}" for n in range(8)]
        regenerated = _transport({"success": True, "backup_codes": codes})
        with patch("apps.api_client.services.portal_request", side_effect=[profile, regenerated]) as transport:
            response = self.client.post(
                reverse("users:mfa_backup_codes"),
                {"password": PASSWORD, "token": "123456"},
                HTTP_USER_AGENT="CustomerBrowser/2.0",
            )
        self.assertEqual(response.status_code, 200)
        for code in codes:
            self.assertContains(response, code)
        self.assertNotIn("new_mfa_backup_codes", self.client.session)
        sent = json.loads(transport.call_args_list[1].kwargs["data"])
        self.assertEqual(sent["client_user_agent"], "CustomerBrowser/2.0")
