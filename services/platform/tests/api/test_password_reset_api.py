"""Exercise customer password recovery through the signed API endpoints."""

from datetime import timedelta

from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives
from django.test import TestCase, override_settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.settings.models import SystemSetting
from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "password-reset-api-tests",
        }
    },
)
class PasswordResetAPITests(HMACTestMixin, TestCase):
    request_path = "/api/users/password/reset/"
    confirm_path = "/api/users/password/reset/confirm/"
    new_password = "Recovered-River-947!Quartz"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key="portal.public_base_url").delete()
        self.user = User.objects.create_user(
            email="reset@example.com", password="Original-Cedar-283!Stone", first_name="Alex"
        )
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        mail.outbox.clear()

    def configure_portal_url(self, value: str = "https://portal.example.com") -> None:
        SystemSetting.objects.update_or_create(
            key="portal.public_base_url",
            defaults={
                "name": "Customer portal URL",
                "description": "Public customer portal URL",
                "category": "platform",
                "data_type": "string",
                "value": value,
                "default_value": "",
            },
        )
        cache.clear()

    def confirm_body(self, token: str | None = None, password: str | None = None) -> dict[str, str]:
        replacement = self.new_password if password is None else password
        return {
            "uid": self.uid,
            "token": default_token_generator.make_token(self.user) if token is None else token,
            "new_password": replacement,
            "new_password_confirm": replacement,
        }

    def test_request_sends_one_email_with_the_portal_confirm_link(self) -> None:
        self.configure_portal_url("  https://portal.example.com///  ")
        response = self.portal_post(self.request_path, {"email": self.user.email})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIs(response.json()["success"], True)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        prefix = f"https://portal.example.com/password-reset/confirm/{self.uid}/"
        links = [line.strip() for line in message.body.splitlines() if line.strip().startswith(prefix)]
        self.assertEqual(len(links), 1)
        reset_url = links[0]
        self.assertTrue(reset_url.endswith("/"))
        token = reset_url[len(prefix) : -1]
        self.assertTrue(default_token_generator.check_token(self.user, token))
        self.assertIsInstance(message, EmailMultiAlternatives)
        assert isinstance(message, EmailMultiAlternatives)  # narrow for mypy
        self.assertIn(f'href="{reset_url}"', str(message.alternatives[0][0]))

    def test_unknown_email_is_neutral_and_sends_nothing(self) -> None:
        self.configure_portal_url()
        response = self.portal_post(self.request_path, {"email": "unknown@example.com"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(), {"success": True, "message":
                "If an eligible account exists and email delivery is available, "
                "you will receive password reset instructions."}
        )
        self.assertEqual(len(mail.outbox), 0)

    def test_unconfigured_portal_url_is_private_and_account_independent(self) -> None:
        with self.assertLogs("apps.api.users.views", level="ERROR") as diagnostics:
            known = self.portal_post(self.request_path, {"email": self.user.email})
        unknown = self.portal_post(self.request_path, {"email": "unknown@example.com"})
        self.assertEqual(known.status_code, 200, known.content)
        self.assertEqual((known.status_code, known.json()), (unknown.status_code, unknown.json()))
        self.assertTrue(any("portal.public_base_url" in entry for entry in diagnostics.output))
        self.assertEqual(len(mail.outbox), 0)

    def test_invalid_portal_url_is_private_and_never_sends(self) -> None:
        for base in ("portal.example.com", "ftp://portal.example.com", "https://", "https://[invalid"):
            with self.subTest(base=base):
                self.configure_portal_url(base)
                response = self.portal_post(self.request_path, {"email": self.user.email})
                self.assertEqual(response.status_code, 200, response.content)
                self.assertIn("email delivery is available", response.json()["message"])
                self.assertEqual(len(mail.outbox), 0)

    def test_confirm_with_valid_token_sets_password_and_clears_lockout(self) -> None:
        self.user.failed_login_attempts = 5
        self.user.account_locked_until = timezone.now() + timedelta(minutes=15)
        self.user.two_factor_secret = "JBSWY3DPEHPK3PXP"
        self.user.save(update_fields=["failed_login_attempts", "account_locked_until", "_two_factor_secret"])
        response = self.portal_post(self.confirm_path, self.confirm_body())
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertIsNone(self.user.account_locked_until)
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertEqual(self.user.two_factor_secret, "")

    def test_bad_token_is_400_not_500(self) -> None:
        original_password = self.user.password
        response = self.portal_post(self.confirm_path, self.confirm_body(token="invalid-token"))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["errors"]["token"], ["Invalid or expired reset link."])
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, original_password)

    def test_reused_token_is_400(self) -> None:
        token = default_token_generator.make_token(self.user)
        response = self.portal_post(self.confirm_path, self.confirm_body(token=token))
        self.assertEqual(response.status_code, 200, response.content)
        response = self.portal_post(
            self.confirm_path, self.confirm_body(token=token, password="Another-Meadow-631!Quartz")
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertTrue(response.json()["errors"]["token"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))

    def test_weak_password_is_400_with_policy_errors(self) -> None:
        original_password = self.user.password
        response = self.portal_post(self.confirm_path, self.confirm_body(password="password1234"))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertTrue(response.json()["errors"]["new_password"])
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, original_password)

    def test_unsigned_confirm_is_rejected(self) -> None:
        original_password = self.user.password
        response = self.client.post(self.confirm_path, self.confirm_body(), content_type="application/json")
        self.assertEqual(response.status_code, 401, response.content)
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, original_password)
