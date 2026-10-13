"""A TOTP secret waiting to be confirmed lives in its own row, not on the user or in the session (#689).

The staff web setup kept it in the session and the API kept it on the user row, and the API
made a new one on every call, so one mistyped code broke the authenticator a customer had
just scanned. Both paths now share one pending enrolment: reused while it is fresh, its
expiry extended each time it is shown, and consumed by the enrolment that confirms it.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.test import RequestFactory, TestCase
from django.utils import timezone

from apps.common.encryption import DecryptionError
from apps.settings.services import SettingsService
from apps.users.mfa import MFAService
from apps.users.models import User
from apps.users.pending_totp import (
    PendingTOTPEnrolment,
    complete_enrolment,
    discard,
    get_or_create_pending,
    restart,
)

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class PendingTOTPEnrolmentTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="enrolling@example.ro", password=PASSWORD)
        self.request = RequestFactory().post("/")

    def _later(self, minutes: int) -> object:
        return patch("apps.users.pending_totp.timezone.now", return_value=timezone.now() + timedelta(minutes=minutes))

    def test_the_same_secret_is_offered_while_it_is_fresh(self) -> None:
        first = get_or_create_pending(self.user)
        with self._later(10):
            self.assertEqual(get_or_create_pending(self.user), first)
        self.assertEqual(PendingTOTPEnrolment.objects.filter(user=self.user).count(), 1)

    def test_showing_it_again_extends_its_life(self) -> None:
        first = get_or_create_pending(self.user)
        with self._later(10):
            get_or_create_pending(self.user)
        # 20 minutes after the first showing, but only 10 after the last one.
        with self._later(20):
            self.assertEqual(get_or_create_pending(self.user), first)

    def test_an_expired_enrolment_is_replaced(self) -> None:
        first = get_or_create_pending(self.user)
        with self._later(16):
            self.assertNotEqual(get_or_create_pending(self.user), first)
        self.assertEqual(PendingTOTPEnrolment.objects.filter(user=self.user).count(), 1)

    def test_the_lifetime_setting_decides_when_an_enrolment_expires(self) -> None:
        self.assertTrue(SettingsService.update_setting("users.totp_enrolment_ttl_minutes", 5).is_ok())
        first = get_or_create_pending(self.user)
        with self._later(4):
            self.assertEqual(get_or_create_pending(self.user), first)
        # Four minutes after its last showing it was still fresh; ten after, past a 5-minute life.
        with self._later(10):
            self.assertNotEqual(get_or_create_pending(self.user), first)

    def test_restart_issues_a_new_secret(self) -> None:
        first = get_or_create_pending(self.user)
        self.assertNotEqual(restart(self.user), first)

    def test_the_secret_is_encrypted_and_bound_to_its_row(self) -> None:
        secret = get_or_create_pending(self.user)
        row = PendingTOTPEnrolment.objects.get(user=self.user)
        self.assertNotIn(secret, row.secret_encrypted)
        other = User.objects.create_user(email="other@example.ro", password=PASSWORD)
        get_or_create_pending(other)
        other_row = PendingTOTPEnrolment.objects.get(user=other)
        other_row.secret_encrypted = row.secret_encrypted
        with self.assertRaises(DecryptionError):
            other_row.secret()

    def test_nothing_is_stored_on_the_user_row_until_confirmed(self) -> None:
        get_or_create_pending(self.user)
        self.user.refresh_from_db()
        self.assertEqual(self.user._two_factor_secret, "")
        self.assertFalse(self.user.two_factor_enabled)

    def test_a_right_password_and_code_enable_it_and_consume_the_enrolment(self) -> None:
        secret = get_or_create_pending(self.user)
        result = complete_enrolment(
            self.user.pk, password=PASSWORD, code=pyotp.TOTP(secret).now(), request=self.request
        )
        self.assertEqual(result.status, "enabled")
        self.assertEqual(len(result.backup_codes), 8)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, secret)
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=self.user).exists())

    def test_a_wrong_password_or_code_gets_one_answer_and_keeps_the_enrolment(self) -> None:
        secret = get_or_create_pending(self.user)
        wrong_password = complete_enrolment(
            self.user.pk, password="wrong", code=pyotp.TOTP(secret).now(), request=self.request
        )
        wrong_code = complete_enrolment(self.user.pk, password=PASSWORD, code="000000", request=self.request)
        self.assertEqual((wrong_password.status, wrong_code.status), ("incorrect", "incorrect"))
        self.assertEqual(get_or_create_pending(self.user), secret)
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)

    def test_an_enrolment_that_expired_between_showing_and_confirming_is_refused(self) -> None:
        secret = get_or_create_pending(self.user)
        code = pyotp.TOTP(secret).now()
        with self._later(16):
            result = complete_enrolment(self.user.pk, password=PASSWORD, code=code, request=self.request)
        self.assertEqual(result.status, "expired")
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)

    def test_without_an_enrolment_nothing_is_enabled(self) -> None:
        result = complete_enrolment(self.user.pk, password=PASSWORD, code="123456", request=self.request)
        self.assertEqual(result.status, "expired")

    def test_an_account_already_enrolled_is_left_alone(self) -> None:
        secret = get_or_create_pending(self.user)
        complete_enrolment(self.user.pk, password=PASSWORD, code=pyotp.TOTP(secret).now(), request=self.request)
        self.user.refresh_from_db()
        enabled_secret = self.user.two_factor_secret
        result = complete_enrolment(self.user.pk, password=PASSWORD, code="123456", request=self.request)
        self.assertEqual(result.status, "already_enabled")
        self.user.refresh_from_db()
        self.assertEqual(self.user.two_factor_secret, enabled_secret)

    def test_password_recovery_and_disabling_discard_a_pending_enrolment(self) -> None:
        for action in ("recover", "disable"):
            with self.subTest(action=action):
                get_or_create_pending(self.user)
                MFAService.apply_state_change(self.user, action=action)
                self.assertFalse(PendingTOTPEnrolment.objects.filter(user=self.user).exists())

    def test_discard_is_harmless_without_an_enrolment(self) -> None:
        discard(self.user.pk)
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=self.user).exists())
