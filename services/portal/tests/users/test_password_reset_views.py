"""Exercise anonymous password recovery through the Portal views."""

from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from requests import Response

from apps.api_client.services import PlatformAPIError
from apps.users.forms import PasswordResetConfirmForm


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "password-reset-view-tests",
        }
    },
)
class PasswordResetViewTests(SimpleTestCase):
    password = "Recovered-River-947!Quartz"
    neutral_message = "If an account with that email exists, you will receive password reset instructions."

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        transport_response = Response()
        transport_response.status_code = 200
        transport_response._content = b'{"success": false}'
        transport = patch("apps.api_client.services.portal_request", return_value=transport_response)
        transport.start()
        self.addCleanup(transport.stop)
        platform = patch("apps.users.views.api_client")
        self.platform = platform.start()
        self.addCleanup(platform.stop)
        self.platform.request_password_reset.return_value = {"success": True}
        self.platform.confirm_password_reset.return_value = {"success": True}
        self.request_url = reverse("users:password_reset")
        self.confirm_url = reverse("users:password_reset_confirm", kwargs={"uidb64": "MQ", "token": "reset-token"})
        self.body = {"new_password": self.password, "confirm_password": self.password}

    def test_request_calls_platform_and_redirects_with_neutral_message(self) -> None:
        response = self.client.post(self.request_url, {"email": "reset@example.com"})
        self.platform.request_password_reset.assert_called_with("reset@example.com", client_ip="127.0.0.1")
        self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
        self.assertEqual([str(message) for message in get_messages(response.wsgi_request)], [self.neutral_message])

    def test_request_error_preserves_neutral_message(self) -> None:
        self.platform.request_password_reset.side_effect = PlatformAPIError("Unavailable", status_code=500)
        response = self.client.post(self.request_url, {"email": "reset@example.com"})
        self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
        self.assertEqual([str(message) for message in get_messages(response.wsgi_request)], [self.neutral_message])

    def test_confirm_get_renders_form(self) -> None:
        response = self.client.get(self.confirm_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/password_reset_confirm.html")
        self.assertIsInstance(response.context["form"], PasswordResetConfirmForm)
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        self.assertContains(response, 'name="new_password"')
        self.assertContains(response, 'name="confirm_password"')

    def test_confirm_mismatch_does_not_call_platform(self) -> None:
        response = self.client.post(self.confirm_url, {**self.body, "confirm_password": "Different-Meadow-631!"})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], None, "New password and confirmation don't match.")
        self.platform.confirm_password_reset.assert_not_called()

    def test_confirm_valid_password_redirects_to_login(self) -> None:
        response = self.client.post(self.confirm_url, self.body)
        self.platform.confirm_password_reset.assert_called_with(
            "MQ", "reset-token", self.password, self.password, client_ip="127.0.0.1"
        )
        self.assertRedirects(response, reverse("users:login"), fetch_redirect_response=False)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Password reset successfully. You can now log in with your new password."],
        )

    def test_confirm_rejected_by_platform_shows_form_error(self) -> None:
        self.platform.confirm_password_reset.side_effect = PlatformAPIError("Rejected", status_code=400)
        response = self.client.post(self.confirm_url, self.body)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response.context["form"],
            None,
            "This reset link is invalid or has expired, or the password was rejected.",
        )
        self.assertEqual(getattr(response.wsgi_request, "_portal_auth_outcome", None), "failure")

    def test_confirm_password_policy_errors_are_shown_on_field(self) -> None:
        self.platform.confirm_password_reset.side_effect = PlatformAPIError(
            "Rejected", status_code=400, response_data={"errors": {"new_password": ["This password is too common."]}}
        )
        response = self.client.post(self.confirm_url, self.body)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "new_password", "This password is too common.")

    def test_request_rate_limit_shows_retry_seconds(self) -> None:
        self.platform.request_password_reset.side_effect = PlatformAPIError(
            "Throttled", status_code=429, retry_after=45
        )
        response = self.client.post(self.request_url, {"email": "reset@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Too many attempts. Please try again in 45 seconds."],
        )

    def test_confirm_rate_limit_shows_retry_seconds(self) -> None:
        self.platform.confirm_password_reset.side_effect = PlatformAPIError(
            "Throttled", status_code=429, retry_after=45
        )
        response = self.client.post(self.confirm_url, self.body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Too many attempts. Please try again in 45 seconds."],
        )
        self.assertIsNone(getattr(response.wsgi_request, "_portal_auth_outcome", None))

    def test_confirm_service_error_is_generic(self) -> None:
        self.platform.confirm_password_reset.side_effect = PlatformAPIError("Unavailable", status_code=503)
        response = self.client.post(self.confirm_url, self.body)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], None, "Password reset failed. Please try again.")
        self.assertIsNone(getattr(response.wsgi_request, "_portal_auth_outcome", None))
