"""Web routes must not let a single factor strip or reset the second one (#595).

A web password reset cleared the TOTP secret and backup codes, so a reset link alone
led to a login with no second factor. The web 2FA disable asked only for the password,
and backup-code regeneration asked for nothing. Their API counterparts already required
the password and a current code, and the API reset already kept enrolled MFA.
"""

from __future__ import annotations

from typing import Any

import pyotp
from django.contrib.auth.tokens import default_token_generator
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.users.mfa import TOTPService
from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
NEW_PASSWORD = "Another-Long-Passphrase-2026"  # test fixture, not a credential


class EnrolledStaffTestCase(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="mfa-changes@example.ro", password=PASSWORD, is_staff=True, staff_role="support"
        )
        self.secret = TOTPService.generate_secret()
        self.user.two_factor_secret = self.secret
        self.user.two_factor_enabled = True
        self.user.save()
        self.codes = self.user.generate_backup_codes()

    def totp(self) -> str:
        return pyotp.TOTP(self.secret).now()


class WebPasswordResetKeepsMFATests(EnrolledStaffTestCase):
    def reset_password(self) -> None:
        url = reverse(
            "users:password_reset_confirm",
            kwargs={
                "uidb64": urlsafe_base64_encode(force_bytes(self.user.pk)),
                "token": default_token_generator.make_token(self.user),
            },
        )
        client = Client()
        set_password_url = client.get(url)["Location"]
        response = client.post(set_password_url, {"new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD})
        self.assertRedirects(response, reverse("users:password_reset_complete"), fetch_redirect_response=False)

    def test_reset_keeps_the_second_factor(self) -> None:
        tokens_before = list(self.user.backup_tokens)
        self.reset_password()
        fresh = User.objects.get(pk=self.user.pk)
        self.assertTrue(fresh.check_password(NEW_PASSWORD))
        self.assertTrue(fresh.two_factor_enabled, "the reset link disabled 2FA")
        self.assertEqual(fresh.two_factor_secret, self.secret)
        self.assertEqual(fresh.backup_tokens, tokens_before)

    def test_login_after_a_reset_still_asks_for_the_second_factor(self) -> None:
        self.reset_password()
        client = Client()
        response = client.post(reverse("users:login"), {"email": self.user.email, "password": NEW_PASSWORD})
        self.assertEqual(response["Location"], reverse("users:mfa_verify"))
        self.assertNotIn("_auth_user_id", client.session)

    def test_regression_guard_reset_clears_a_stray_secret_when_2fa_is_off(self) -> None:
        """Matches the API reset: a leftover secret without enrolment is dropped."""
        User.objects.filter(pk=self.user.pk).update(two_factor_enabled=False)
        self.reset_password()
        fresh = User.objects.get(pk=self.user.pk)
        self.assertFalse(fresh.two_factor_enabled)
        self.assertEqual(fresh.two_factor_secret, "")


class WebMFADisableTests(EnrolledStaffTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.user)

    def disable(self, **data: str) -> Any:
        return self.client.post(reverse("users:mfa_disable"), data)

    def assert_still_enrolled(self) -> None:
        fresh = User.objects.get(pk=self.user.pk)
        self.assertTrue(fresh.two_factor_enabled, "2FA was disabled without both factors")
        self.assertEqual(fresh.two_factor_secret, self.secret)

    def test_password_alone_does_not_disable(self) -> None:
        response = self.disable(password=PASSWORD)
        self.assertEqual(response.status_code, 200)
        self.assert_still_enrolled()

    def test_wrong_code_does_not_disable(self) -> None:
        self.disable(password=PASSWORD, token="000000")
        self.assert_still_enrolled()

    def test_regression_guard_wrong_password_with_a_valid_code_does_not_disable(self) -> None:
        self.disable(password="not-the-password", token=self.totp())
        self.assert_still_enrolled()

    def test_password_and_a_current_code_disable(self) -> None:
        """Positive path, a guard that the fix still lets the owner disable 2FA."""
        response = self.disable(password=PASSWORD, token=self.totp())
        self.assertRedirects(response, reverse("users:user_profile"), fetch_redirect_response=False)
        self.assertFalse(User.objects.get(pk=self.user.pk).two_factor_enabled)

    def test_password_and_a_backup_code_disable(self) -> None:
        """Positive path, a guard that an 8-digit backup code is accepted here."""
        self.disable(password=PASSWORD, token=self.codes[0])
        self.assertFalse(User.objects.get(pk=self.user.pk).two_factor_enabled)

    def test_page_accepts_eight_digit_backup_codes(self) -> None:
        page = self.client.get(reverse("users:mfa_disable"))
        self.assertContains(page, 'name="token" maxlength="8"')
        self.assertNotContains(page, "substring(0, 6)")


class WebBackupCodeRegenerationTests(EnrolledStaffTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.user)
        self.tokens_before = list(User.objects.get(pk=self.user.pk).backup_tokens)

    def regenerate(self, **data: str) -> Any:
        return self.client.post(reverse("users:mfa_regenerate_backup_codes"), data)

    def assert_codes_unchanged(self) -> None:
        self.assertEqual(User.objects.get(pk=self.user.pk).backup_tokens, self.tokens_before)
        self.assertNotIn("new_backup_codes", self.client.session)

    def test_empty_post_does_not_regenerate(self) -> None:
        self.assertEqual(self.regenerate().status_code, 200)
        self.assert_codes_unchanged()

    def test_password_alone_does_not_regenerate(self) -> None:
        self.regenerate(password=PASSWORD)
        self.assert_codes_unchanged()

    def test_wrong_password_with_a_valid_code_does_not_regenerate(self) -> None:
        self.regenerate(password="not-the-password", token=self.totp())
        self.assert_codes_unchanged()

    def test_password_and_a_current_code_regenerate(self) -> None:
        """Positive path, a guard that the fix still lets the owner regenerate."""
        response = self.regenerate(password=PASSWORD, token=self.totp())
        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.assertNotEqual(User.objects.get(pk=self.user.pk).backup_tokens, self.tokens_before)
        self.assertEqual(len(self.client.session["new_backup_codes"]), 8)

    def test_page_asks_for_the_password_and_takes_backup_codes(self) -> None:
        page = self.client.get(reverse("users:mfa_regenerate_backup_codes"))
        self.assertContains(page, 'name="password"')
        self.assertNotContains(page, "substring(0, 6)")
