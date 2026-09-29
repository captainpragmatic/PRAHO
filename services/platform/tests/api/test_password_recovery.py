"""Public Portal recovery uses Platform tokens and a trusted Portal email link."""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.api.users.serializers import InvalidPasswordResetLink, MFADisableSerializer, PasswordResetConfirmSerializer
from apps.audit.models import AuditEvent
from apps.settings.models import SystemSetting
from apps.users.forms import LoginForm
from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PasswordRecoveryAPITests(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        SystemSetting.objects.update_or_create(
            key="portal.public_base_url",
            defaults={"name": "Portal URL", "category": "platform", "data_type": "string",
                      "value": "https://customers.example.test", "default_value": ""},
        )
        self.user = User.objects.create_user(email="recovery@example.test", password="Original-password-827!")
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def confirm(self, **overrides):
        return self.portal_post("/api/users/password/reset/confirm/", {
            "uid": self.uid,
            "token": self.token,
            "new_password": " Replacement-password-529! ",
            "new_password_confirm": " Replacement-password-529! ",
            **overrides,
        })

    def test_request_sends_real_templates_with_public_portal_url(self):
        response = self.portal_post("/api/users/password/reset/", {"email": self.user.email})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertIn(f"https://customers.example.test/password-reset/confirm/{self.uid}/", message.body)
        self.assertNotIn("localhost:8700", message.body)
        self.assertIn("can only be used once", message.body)
        self.assertTrue(message.alternatives)
        self.assertIn("https://customers.example.test/password-reset/confirm/", message.alternatives[0].content)

    def test_unknown_and_inactive_accounts_match_known_response(self):
        known = self.portal_post("/api/users/password/reset/", {"email": self.user.email})
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        for email in (self.user.email, "unknown@example.test"):
            with self.subTest(email=email):
                result = self.portal_post("/api/users/password/reset/", {"email": email})
                self.assertEqual(result.status_code, known.status_code)
                self.assertEqual(result.json(), known.json())
        self.assertEqual(len(mail.outbox), 1)

    def test_password_is_changed_exactly_and_token_cannot_be_reused(self):
        response = self.confirm()
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(" Replacement-password-529! "))
        self.assertFalse(self.user.check_password("Original-password-827!"))
        self.assertFalse(self.user.check_password("Replacement-password-529!"))
        login = self.portal_post("/api/users/login/", {"email": self.user.email, "password": " Replacement-password-529! "})
        self.assertEqual(login.status_code, 200, login.content)
        self.assertTrue(login.json()["success"], login.content)
        self.assertEqual(AuditEvent.objects.filter(action="password_reset_completed", metadata__user_id=self.user.pk).count(), 1)
        response = self.confirm()
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["code"], "invalid_reset_link")
        self.assertEqual(AuditEvent.objects.filter(action="password_reset_completed", metadata__user_id=self.user.pk).count(), 1)

    def test_bad_and_expired_tokens_are_controlled_client_errors(self):
        for overrides in ({"uid": "not-a-uid"}, {"token": "invalid"}):
            with self.subTest(overrides=overrides):
                response = self.confirm(**overrides)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json()["code"], "invalid_reset_link")
        future = default_token_generator._now() + timedelta(seconds=7201)
        with patch.object(default_token_generator, "_now", return_value=future):
            response = self.confirm()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_reset_link")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Original-password-827!"))

    def test_weak_and_mismatched_passwords_do_not_consume_token(self):
        for password, confirmation in (("123456789012", "123456789012"), ("Longer-Password-827!", "Different-Password-529!")):
            with self.subTest(password=password):
                response = self.confirm(new_password=password, new_password_confirm=confirmation)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json()["code"], "validation_failed")
                self.user.refresh_from_db()
                self.assertTrue(default_token_generator.check_token(self.user, self.token))
        self.assertEqual(self.confirm().status_code, 200)

    def test_enrolled_mfa_is_preserved(self):
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = "JBSWY3DPEHPK3PXP"
        self.user.backup_tokens = ["hashed-recovery-code"]
        self.user.save()
        self.token = default_token_generator.make_token(self.user)
        self.assertEqual(self.confirm().status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(self.user.backup_tokens, ["hashed-recovery-code"])

    def test_successful_reset_clears_lockout_and_incomplete_mfa(self):
        self.user.failed_login_attempts = 8
        self.user.account_locked_until = timezone.now() + timedelta(hours=1)
        self.user.two_factor_secret = "JBSWY3DPEHPK3PXP"
        self.user.save()
        self.token = default_token_generator.make_token(self.user)
        self.assertEqual(self.confirm(token="invalid").status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 8)
        self.assertIsNotNone(self.user.account_locked_until)
        self.assertEqual(self.confirm().status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertIsNone(self.user.account_locked_until)
        self.assertEqual(self.user.two_factor_secret, "")

    def test_token_is_rechecked_against_current_user_at_save(self):
        serializer = PasswordResetConfirmSerializer(data={
            "uid": self.uid, "token": self.token,
            "new_password": "Another-password-582!", "new_password_confirm": "Another-password-582!",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.user.set_password("Already-recovered-password-29!")
        self.user.save(update_fields=["password"])
        with self.assertRaises(InvalidPasswordResetLink):
            serializer.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Already-recovered-password-29!"))

    def test_delivery_failure_returns_unavailable(self):
        with patch("apps.api.users.serializers.send_mail", side_effect=OSError("SMTP unavailable")):
            response = self.portal_post("/api/users/password/reset/", {"email": self.user.email})
        self.assertEqual(response.status_code, 503, response.content)
        self.assertFalse(response.json()["success"])

    def test_zero_messages_sent_is_not_reported_as_success(self):
        with patch("apps.api.users.serializers.send_mail", return_value=0):
            response = self.portal_post("/api/users/password/reset/", {"email": self.user.email})
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(len(mail.outbox), 0)
    def test_malformed_portal_origin_is_rejected_without_sending(self):
        SystemSetting.objects.filter(key="portal.public_base_url").update(
            value="https://attacker.example@customers.example.test/path"
        )
        cache.clear()
        response = self.portal_post("/api/users/password/reset/", {"email": self.user.email})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(mail.outbox), 0)


class PasswordRecoveryCredentialTests(SimpleTestCase):
    def test_platform_login_form_preserves_recovered_password(self):
        password = " Replacement-password-529! "
        form = LoginForm(data={"email": "owner@example.test", "password": password})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["password"], password)

    def test_mfa_password_validation_preserves_recovered_password(self):
        password = " Replacement-password-529! "
        self.assertEqual(MFADisableSerializer().fields["password"].run_validation(password), password)
