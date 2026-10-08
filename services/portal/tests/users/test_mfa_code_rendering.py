"""Failed account-security POSTs must not redisplay authentication codes."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from unittest.mock import patch

from django.core.cache import cache
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
class MFACodeRenderingTests(SimpleTestCase):
    token = "12345678"
    password = "Original-secure123!"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        session = self.client.session
        session.update({"user_id": 42, "customer_id": 7, "email": "user@example.com"})
        session.save()

    def _assert_code_not_rendered(self, response: _MonkeyPatchedWSGIResponse) -> None:
        self.assertContains(response, 'name="token"')
        self.assertEqual(response.context["form"].data["token"], self.token)
        field = re.search(r'<input\b[^>]*\bname="token"[^>]*>', response.content.decode())
        self.assertIsNotNone(field)
        assert field is not None
        self.assertIn('type="text"', field.group())
        self.assertNotContains(response, self.token)
        self.assertNotRegex(field.group(), r'\bvalue\s*=\s*"[^"]+"')

    def test_failed_password_change_does_not_echo_code(self) -> None:
        with patch("apps.users.views.api_client.update_customer_password", return_value={"success": False}):
            response = self.client.post(
                reverse("users:change_password"),
                {
                    "current_password": self.password,
                    "new_password": "Replacement-secure123!",
                    "confirm_password": "Replacement-secure123!",
                    "token": self.token,
                },
            )
        self.assertContains(response, "Password change failed.")
        self.assertEqual(response.context["form"].cleaned_data["token"], self.token)
        self._assert_code_not_rendered(response)

    def test_failed_mfa_disable_does_not_echo_code(self) -> None:
        with patch("apps.users.views.api_client.disable_mfa", return_value={"success": False}):
            response = self.client.post(
                reverse("users:mfa_disable"),
                {"password": self.password, "token": self.token},
            )
        self.assertContains(response, "Could not disable MFA.")
        self.assertEqual(response.context["form"].cleaned_data["token"], self.token)
        self._assert_code_not_rendered(response)

    def test_failed_backup_code_regeneration_does_not_echo_code(self) -> None:
        with (
            patch(
                "apps.users.views.api_client.get_customer_profile",
                return_value={"mfa_enabled": True, "backup_codes_count": 5},
            ),
            patch(
                "apps.users.views.api_client.regenerate_backup_codes",
                side_effect=PlatformAPIError("Rejected credentials", status_code=403),
            ),
        ):
            response = self.client.post(
                reverse("users:mfa_backup_codes"),
                {"password": self.password, "token": self.token},
            )
        self.assertContains(response, "Could not regenerate codes.")
        self.assertEqual(response.context["form"].cleaned_data["token"], self.token)
        self._assert_code_not_rendered(response)

    def test_invalid_posts_do_not_echo_code_in_any_account_security_view(self) -> None:
        for route in ("change_password", "mfa_disable", "mfa_backup_codes"):
            with (
                self.subTest(route=route),
                patch(
                    "apps.users.views.api_client.get_customer_profile",
                    return_value={"mfa_enabled": True, "backup_codes_count": 5},
                ),
            ):
                response = self.client.post(reverse(f"users:{route}"), {"token": self.token})
                form = response.context["form"]
                self.assertTrue(form.errors)
                self.assertIn("current_password" if route == "change_password" else "password", form.errors)
                self._assert_code_not_rendered(response)
