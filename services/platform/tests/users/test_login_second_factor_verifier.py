"""The shared login second-factor check (#590).

Every login path that accepts a second factor (portal login, API token, staff web login)
goes through verify_login_second_factor, so they all accept exactly the same codes, spend
them the same way and charge the same lockout.
"""

from __future__ import annotations

import pyotp
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings

from apps.users.mfa import SecondFactorResult, TOTPService, verify_login_second_factor
from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


def _enrolled_user(email: str) -> tuple[User, str]:
    user = User.objects.create_user(email=email, password=PASSWORD)
    secret = TOTPService.generate_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = True
    user.save()
    return user, secret


@override_settings(CACHES=settings.LOCMEM_TEST_CACHE)
class VerifyLoginSecondFactorTests(TestCase):
    def setUp(self) -> None:
        cache.clear()  # the replay marker and the attempt budget live in the cache
        self.addCleanup(cache.clear)
        self.user, self.secret = _enrolled_user("verifier@example.ro")
        self.request = RequestFactory().post("/")

    def verify(self, code: str) -> SecondFactorResult:
        with transaction.atomic():
            locked = User.objects.select_for_update().get(pk=self.user.pk)
            return verify_login_second_factor(locked, code, self.request)

    def test_totp_is_accepted_and_reported_as_totp(self) -> None:
        result = self.verify(pyotp.TOTP(self.secret).now())
        self.assertEqual(result, SecondFactorResult(accepted=True, method="totp", rate_limited=False))

    def test_backup_code_is_accepted_once_and_reported_as_backup_code(self) -> None:
        code = self.user.generate_backup_codes()[0]
        self.assertEqual(self.verify(code), SecondFactorResult(accepted=True, method="backup_code", rate_limited=False))
        self.assertFalse(self.verify(code).accepted, "a backup code was accepted twice")

    def test_replayed_totp_is_refused(self) -> None:
        code = pyotp.TOTP(self.secret).now()
        self.assertTrue(self.verify(code).accepted)
        self.assertFalse(self.verify(code).accepted)

    def test_wrong_code_counts_toward_the_lockout(self) -> None:
        result = self.verify("000000")
        self.assertEqual(result, SecondFactorResult(accepted=False, method=None, rate_limited=False))
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

    def test_empty_code_counts_toward_the_lockout(self) -> None:
        self.assertFalse(self.verify("").accepted)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

    @override_settings(ACCOUNT_LOCKOUT_THRESHOLD=10)  # not yet locked: a lock in force is not extended
    def test_exhausted_budget_is_reported_and_still_counts(self) -> None:
        for _attempt in range(5):
            self.assertFalse(self.verify("000000").rate_limited)
        result = self.verify(pyotp.TOTP(self.secret).now())
        self.assertEqual(result, SecondFactorResult(accepted=False, method=None, rate_limited=True))
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 6)

    def test_successful_check_resets_the_attempt_budget(self) -> None:
        """L1: the budget counts successes too, so without a reset a sixth honest login fails."""
        codes = self.user.generate_backup_codes()
        for code in codes[:6]:
            result = self.verify(code)
            self.assertTrue(result.accepted, f"honest login refused: {result}")


class VerifyLoginSecondFactorGuardTests(TransactionTestCase):
    """Outside a transaction the caller cannot hold the row lock the check relies on.

    A TransactionTestCase, because TestCase wraps every test in an atomic block and the
    guard could never trip there.
    """

    def test_refuses_to_run_outside_a_transaction(self) -> None:
        user, secret = _enrolled_user("guard@example.ro")
        with self.assertRaises(RuntimeError):
            verify_login_second_factor(user, pyotp.TOTP(secret).now(), RequestFactory().post("/"))
        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 0)
