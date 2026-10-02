"""An audit write must never decide a second-factor check, nor abort the login around it.

verify_mfa_code audits each attempt. It used to call the audit service inside its own
catch-all, so an audit failure turned an accepted code into success=False, rejecting a valid
TOTP and wasting a backup code it had already consumed. On PostgreSQL a failed audit insert
also aborted the caller's transaction, so the login failed outright. Each audit write now runs
in its own savepoint and its failure is logged, not returned.
"""

from __future__ import annotations

from unittest.mock import patch

import pyotp
from django.conf import settings
from django.core.cache import cache
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from apps.users.mfa import MFAService, TOTPService
from apps.users.models import User, UserLoginLog

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
AUDIT = "apps.users.mfa.AuditService.log_2fa_event"


def _enrolled_staff(email: str) -> tuple[User, str]:
    user = User.objects.create_user(email=email, password=PASSWORD, is_staff=True, staff_role="support")
    secret = TOTPService.generate_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = True
    user.save()
    return user, secret


@override_settings(CACHES=settings.LOCMEM_TEST_CACHE)
class AuditFailureDoesNotDecideTheCheckTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user, self.secret = _enrolled_staff("audit-isolation@example.test")

    def test_a_valid_totp_is_accepted_when_the_audit_write_fails(self) -> None:
        with patch(AUDIT, side_effect=RuntimeError("audit store down")), transaction.atomic():
            outcome = MFAService.verify_mfa_code(self.user, pyotp.TOTP(self.secret).now())
        self.assertTrue(outcome["success"], "an audit failure rejected a valid code")
        self.assertEqual(outcome["method"], "totp")

    def test_a_backup_code_is_accepted_and_spent_once_when_the_audit_write_fails(self) -> None:
        code = self.user.generate_backup_codes()[0]
        with patch(AUDIT, side_effect=RuntimeError("audit store down")), transaction.atomic():
            outcome = MFAService.verify_mfa_code(self.user, code)
        self.assertTrue(outcome["success"], "the code was consumed but the check reported failure")
        self.assertEqual(outcome["method"], "backup_code")


@override_settings(CACHES=settings.LOCMEM_TEST_CACHE)
class AuditDatabaseErrorKeepsTheLoginTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("only PostgreSQL aborts a transaction on a failed statement")
        cache.clear()
        self.addCleanup(cache.clear)
        self.user, self.secret = _enrolled_staff("audit-isolation-pg@example.test")

    def test_a_database_error_in_the_mfa_audit_does_not_fail_the_staff_login(self) -> None:
        codes = self.user.generate_backup_codes()

        def failing_audit(*_args: object, **_kwargs: object) -> None:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 / 0")

        step_one = self.client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})
        self.assertEqual(step_one["Location"], reverse("users:mfa_verify"))
        with patch(AUDIT, side_effect=failing_audit) as audit:
            response = self.client.post(reverse("users:mfa_verify"), {"token": codes[0]})

        self.assertTrue(audit.called, "the audit write never ran, so this proves nothing")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("dashboard"))
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), len(codes) - 1, "the code must be spent exactly once")
        self.assertTrue(UserLoginLog.objects.filter(user=self.user, status="success").exists())
