"""MFA enrollment and removal preserve the acting Portal session binding."""

from unittest.mock import MagicMock, patch

from django.contrib.messages import get_messages
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIClient


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="mfa-session-test-secret",
    PORTAL_HMAC_SECRET="mfa-session-test-secret",
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-mfa-session-binding",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class MFASessionBindingTests(SimpleTestCase):
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
        session.update(
            {"user_id": 42, "customer_id": 7, "email": "user@example.com", "session_auth_hash": "original"}
        )
        session.save()
        self.old_key = session.session_key

    @staticmethod
    def transport_response(payload: dict[str, object], status_code: int = 200) -> MagicMock:
        response = MagicMock()
        response.status_code = status_code
        response.headers = {"content-type": "application/json"}
        response.json.return_value = payload
        return response

    def assert_rotated_binding(self, expected_hash: str) -> None:
        session = self.client.session
        self.assertEqual(session["user_id"], 42)
        self.assertEqual(session["session_auth_hash"], expected_hash)
        self.assertNotEqual(session.session_key, self.old_key)
        self.assertEqual(SessionStore(session_key=self.old_key).load(), {})

    def test_verify_stores_returned_hash_before_rotation(self) -> None:
        success = self.transport_response(
            {"success": True, "session_auth_hash": "enabled", "backup_codes": ["12345678"]}
        )
        original_cycle = SessionStore.cycle_key
        binding_at_rotation: list[str] = []

        def rotate(session: SessionStore) -> None:
            binding_at_rotation.append(session["session_auth_hash"])
            original_cycle(session)

        with (
            patch("apps.api_client.services.portal_request", return_value=success),
            patch.object(SessionStore, "cycle_key", rotate),
        ):
            response = self.client.post(reverse("users:mfa_setup_totp"), {"token": "123456"})
        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.assertEqual(binding_at_rotation, ["enabled"])
        self.assert_rotated_binding("enabled")
        self.assertEqual(self.client.session["new_mfa_backup_codes"], ["12345678"])

    def test_verify_without_returned_binding_keeps_the_current_one(self) -> None:
        """An old Platform worker answers without the field; the binding it still accepts must survive."""
        success = self.transport_response({"success": True, "backup_codes": ["12345678"]})
        with patch("apps.api_client.services.portal_request", return_value=success):
            response = self.client.post(reverse("users:mfa_setup_totp"), {"token": "123456"})
        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.assert_rotated_binding("original")

    def test_verify_tolerates_missing_backup_codes(self) -> None:
        success = self.transport_response({"success": True, "session_auth_hash": "enabled"})
        with patch("apps.api_client.services.portal_request", return_value=success):
            response = self.client.post(reverse("users:mfa_setup_totp"), {"token": "123456"})
        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.assert_rotated_binding("enabled")
        self.assertEqual(self.client.session["new_mfa_backup_codes"], [])

    def test_disable_stores_returned_hash_before_rotation(self) -> None:
        session = self.client.session
        session["new_mfa_backup_codes"] = ["12345678"]
        session.save()
        success = self.transport_response({"success": True, "session_auth_hash": "disabled"})
        original_cycle = SessionStore.cycle_key
        binding_at_rotation: list[str] = []

        def rotate(session: SessionStore) -> None:
            binding_at_rotation.append(session["session_auth_hash"])
            original_cycle(session)

        with (
            patch("apps.api_client.services.portal_request", return_value=success),
            patch.object(SessionStore, "cycle_key", rotate),
        ):
            response = self.client.post(
                reverse("users:mfa_disable"), {"password": "Original-secure123!", "token": "123456"}
            )
        self.assertRedirects(response, reverse("users:mfa_management"), fetch_redirect_response=False)
        self.assertEqual(binding_at_rotation, ["disabled"])
        self.assert_rotated_binding("disabled")
        self.assertNotIn("new_mfa_backup_codes", self.client.session)

    def test_disable_false_at_http_200_is_an_error(self) -> None:
        failure = self.transport_response({"success": False})
        with patch("apps.api_client.services.portal_request", return_value=failure):
            response = self.client.post(
                reverse("users:mfa_disable"), {"password": "Original-secure123!", "token": "123456"}
            )
        self.assertContains(response, "Could not disable MFA.")
        self.assertEqual(self.client.session.session_key, self.old_key)
        self.assertEqual(self.client.session["session_auth_hash"], "original")

    def test_disable_caller_rejects_a_false_success_dictionary(self) -> None:
        with patch("apps.users.views.api_client") as platform:
            platform.disable_mfa.return_value = {"success": False, "session_auth_hash": "invalid"}
            response = self.client.post(
                reverse("users:mfa_disable"), {"password": "Original-secure123!", "token": "123456"}
            )
        self.assertContains(response, "Could not disable MFA.")
        self.assertEqual(self.client.session.session_key, self.old_key)
        self.assertEqual(self.client.session["session_auth_hash"], "original")

    def test_eight_digit_setup_code_shows_specific_error_without_rotation(self) -> None:
        legacy_success = self.transport_response({"success": True, "backup_codes_remaining": 7})
        with patch("apps.api_client.services.portal_request", return_value=legacy_success):
            response = self.client.post(reverse("users:mfa_setup_totp"), {"token": "12345678"})
        self.assertRedirects(response, reverse("users:mfa_setup_totp"), fetch_redirect_response=False)
        errors = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertIn("Finish setup with the 6-digit code.", errors)
        self.assertEqual(self.client.session.session_key, self.old_key)
        self.assertEqual(self.client.session["session_auth_hash"], "original")
