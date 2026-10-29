"""Changing or resetting a password writes the password, under a lock, and nothing else (#689).

Both views saved the whole user row from the instance loaded at the start of the request:
- an administrator's 2FA reset landing meanwhile was written back, re-enabling 2FA;
- a full save also re-saved the cached profile, reverting a concurrent profile change;
- the old password (or the reset link) was checked on that instance, so a password changed by
  another request in between was overwritten by one whose authority it had already lost.
The write now locks the row, re-checks the authority on it, and saves only the password.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pyotp
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.users.forms import LockedPasswordChangeForm
from apps.users.mfa import MFAService, TOTPService
from apps.users.models import User, UserProfile
from apps.users.pending_totp import PendingTOTPEnrolment, get_or_create_pending

OLD = "Old-password-123!"  # test fixtures, not credentials
NEW = "Brand-new-password-456!"
CONCURRENT = "Someone-else-789!"


def _change(client: Any) -> Any:
    return client.post(
        reverse("users:password_change"), {"old_password": OLD, "new_password1": NEW, "new_password2": NEW}
    )


class PasswordChangeWriteTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="changer@example.ro", password=OLD, staff_role="support")
        self.user.two_factor_secret = TOTPService.generate_secret()
        self.user.two_factor_enabled = True
        self.user.save()
        self.client.force_login(self.user)

    def _as_stale(self, stale: User) -> Any:
        return patch("django.contrib.auth.middleware.get_user", return_value=stale)

    def test_a_2fa_reset_landing_meanwhile_is_not_written_back(self) -> None:
        stale = User.objects.get(pk=self.user.pk)
        MFAService.apply_state_change(self.user, action="disable")

        with self._as_stale(stale):
            _change(self.client)

        fresh = User.objects.get(pk=self.user.pk)
        self.assertTrue(fresh.check_password(NEW))
        self.assertFalse(fresh.two_factor_enabled)
        self.assertEqual(fresh.two_factor_secret, "")

    def test_a_profile_change_landing_meanwhile_is_not_reverted(self) -> None:
        stale = User.objects.get(pk=self.user.pk)
        stale_profile = stale.profile  # cached on the instance, as the request's user would hold it
        self.assertIsNotNone(stale_profile)
        UserProfile.objects.filter(user=self.user).update(timezone="America/New_York")

        with self._as_stale(stale):
            _change(self.client)

        self.assertEqual(UserProfile.objects.get(user=self.user).timezone, "America/New_York")

    def test_a_password_changed_meanwhile_is_not_overwritten(self) -> None:
        # The form's own old-password check, which the page runs (it adds the lockout to Django's).
        real_clean = LockedPasswordChangeForm.clean_old_password

        def checked_then_changed_elsewhere(form: LockedPasswordChangeForm) -> str:
            value = real_clean(form)
            other = User.objects.get(pk=form.user.pk)
            other.set_password(CONCURRENT)
            other.save(update_fields=["password"])
            return str(value)

        with patch.object(LockedPasswordChangeForm, "clean_old_password", checked_then_changed_elsewhere):
            response = _change(self.client)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.get(pk=self.user.pk).check_password(CONCURRENT))

    def test_the_person_who_changed_it_stays_signed_in(self) -> None:
        response = _change(self.client)
        self.assertRedirects(response, reverse("users:user_profile"), fetch_redirect_response=False)
        self.assertEqual(self.client.get(reverse("users:user_profile")).status_code, 200)

    def test_a_pending_authenticator_setup_is_dropped(self) -> None:
        enrolling = User.objects.create_user(email="enrolling@example.ro", password=OLD, staff_role="support")
        get_or_create_pending(enrolling)
        self.client.force_login(enrolling)
        self.client.post(
            reverse("users:password_change"), {"old_password": OLD, "new_password1": NEW, "new_password2": NEW}
        )
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=enrolling).exists())


class PasswordResetWriteTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="resetter@example.ro", password=OLD, staff_role="support")
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.two_factor_enabled = True
        self.user.save()

    def _set_password_url(self) -> str:
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        landing = self.client.get(reverse("users:password_reset_confirm", kwargs={"uidb64": uid, "token": token}))
        self.assertEqual(landing.status_code, 302)  # Django swaps the token for a session marker
        return str(landing["Location"])

    def test_a_password_changed_after_the_link_was_opened_is_not_overwritten(self) -> None:
        url = self._set_password_url()
        real_clean = SetPasswordForm.clean

        def checked_then_changed_elsewhere(form: SetPasswordForm) -> Any:
            cleaned = real_clean(form)
            other = User.objects.get(pk=form.user.pk)
            other.set_password(CONCURRENT)
            other.save(update_fields=["password"])
            return cleaned

        with patch.object(SetPasswordForm, "clean", checked_then_changed_elsewhere):
            self.client.post(url, {"new_password1": NEW, "new_password2": NEW})

        self.assertTrue(User.objects.get(pk=self.user.pk).check_password(CONCURRENT))

    def test_a_reset_writes_the_password_and_keeps_enrolled_2fa(self) -> None:
        url = self._set_password_url()
        self.client.post(url, {"new_password1": NEW, "new_password2": NEW})
        fresh = User.objects.get(pk=self.user.pk)
        self.assertTrue(fresh.check_password(NEW))
        self.assertTrue(fresh.two_factor_enabled)
