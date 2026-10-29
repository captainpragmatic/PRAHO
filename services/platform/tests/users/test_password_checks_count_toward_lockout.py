"""Every password check a signed-in session can reach counts toward the account lockout.

Enabling 2FA, disabling it and regenerating backup codes checked the password without the
lockout, so a stolen session could guess it at the rate limit for as long as it liked; disabling
2FA also answered an account without 2FA differently once the password was right. The staff
pages did the same. A check that passed before a wrong code also upgraded an outdated password
hash, which moves the session hash and ends the session that made the check.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.core.cache import cache
from django.db.models import F
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.users import forms as forms_module
from apps.users.forms import LockedPasswordChangeForm
from apps.users.mfa import TOTPService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Original-secure123!"  # test fixture, not a credential
WRONG = "Not-the-password-1!"  # test fixture, not a credential
NEW_PASSWORD = "Another-secure123!"  # test fixture, not a credential
LOCKED_STAFF_CHECK = "Too many attempts. Please wait an hour and try again."
LOCKED_PASSWORD_CHANGE = "Too many password change attempts. Please wait before trying again."
PATHS = ("mfa/verify/", "mfa/disable/", "mfa/regenerate-backup-codes/", "change-password/")
OUTDATED_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher", "django.contrib.auth.hashers.PBKDF2PasswordHasher"]


def enrol(user: User) -> str:
    secret = TOTPService.generate_secret()
    user.two_factor_secret = secret
    user.two_factor_enabled = True
    user.save()
    user.generate_backup_codes()
    return secret


def outdated_hash(password: str) -> str:
    """A hash the preferred hasher (MD5 here) would replace on Django's check_password."""
    return PBKDF2PasswordHasher().encode(password, "outdatedsalt", iterations=1)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PortalPasswordChecksTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="Lockout Co", customer_type="company", status="active")

    def member(self, email: str, *, two_factor: bool) -> tuple[User, str]:
        user = User.objects.create_user(email=email, password=PASSWORD)
        CustomerMembership.objects.create(user=user, customer=self.customer, role="owner", is_primary=True)
        return user, (enrol(user) if two_factor else "")

    def call(self, user: User, suffix: str, **data: Any) -> Any:
        path = "/api/users/" + suffix
        body = {"user_id": user.pk, "customer_id": self.customer.pk, **data}
        if suffix == "change-password/":  # the one PUT among them
            payload = json.dumps({**body, "timestamp": time.time()}).encode()
            return self.client.put(path, payload, content_type="application/json", **hmac_headers("PUT", path, payload))
        return self.portal_post(path, body)

    def member_on(self, path: str, label: str) -> tuple[User, Any]:
        """A member set up for the path, and a function that tries a password on it with a valid code."""
        user, secret = self.member(f"{label}-{path.replace('/', '-')}@example.com", two_factor=path != "mfa/verify/")
        if path == "mfa/verify/":
            secret = self.pending_secret(user)

        def attempt(password: str) -> Any:
            code = pyotp.TOTP(secret).now()
            if path == "change-password/":
                return self.call(user, path, current_password=password, new_password=NEW_PASSWORD, token=code)
            return self.call(user, path, password=password, token=code)

        return user, attempt

    def pending_secret(self, user: User) -> str:
        response = self.call(user, "mfa/setup/")
        self.assertEqual(response.status_code, 200, response.content)
        return str(response.json()["setup_data"]["manual_entry_key"])

    def test_wrong_passwords_lock_the_account_on_every_path(self) -> None:
        threshold = settings.ACCOUNT_LOCKOUT_THRESHOLD
        for path in PATHS:
            with self.subTest(path=path):
                user, attempt = self.member_on(path, "lock")
                for _ in range(threshold):
                    self.assertEqual(attempt(WRONG).status_code, 400)
                user.refresh_from_db()
                self.assertEqual(user.failed_login_attempts, threshold)
                self.assertTrue(user.is_account_locked())

                before = (user.password, user.two_factor_enabled, list(user.backup_tokens))
                refused = attempt(PASSWORD)  # the right password, while locked: said so, and not counted
                self.assertEqual(refused.json().get("code"), "account_locked")
                user.refresh_from_db()
                self.assertEqual((user.password, user.two_factor_enabled, list(user.backup_tokens)), before)
                self.assertEqual(user.failed_login_attempts, threshold)

    def test_a_lockout_records_which_check_caused_it(self) -> None:
        sources = dict(zip(PATHS, ("mfa_enrolment", "mfa_disable", "backup_codes", "password_change"), strict=True))
        for path, source in sources.items():
            with self.subTest(path=path):
                user, attempt = self.member_on(path, "source")
                for _ in range(settings.ACCOUNT_LOCKOUT_THRESHOLD):
                    attempt(WRONG)
                self.assertEqual(AuditEvent.objects.get(action="account_locked", user=user).metadata["source"], source)

    def test_2fa_changes_without_2fa_say_so_alike_for_the_right_and_a_wrong_password(self) -> None:
        user, _secret = self.member("no-2fa@example.com", two_factor=False)
        for path in ("mfa/disable/", "mfa/regenerate-backup-codes/"):
            with self.subTest(path=path):
                right = self.call(user, path, password=PASSWORD, token="000000")
                wrong = self.call(user, path, password=WRONG, token="000000")
                self.assertEqual((right.status_code, right.json()), (wrong.status_code, wrong.json()))
                self.assertEqual(right.json().get("code"), "mfa_not_enabled")
        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 0)  # the password is never checked, so never counted

    @override_settings(PASSWORD_HASHERS=OUTDATED_HASHERS)
    def test_the_right_password_then_a_wrong_code_keeps_the_stored_hash(self) -> None:
        for path in ("mfa/verify/", "mfa/disable/", "mfa/regenerate-backup-codes/", "change-password/"):
            with self.subTest(path=path):
                user, _secret = self.member(
                    f"rehash-{path.replace('/', '-')}@example.com", two_factor=path != "mfa/verify/"
                )
                if path == "mfa/verify/":
                    self.pending_secret(user)
                User.objects.filter(pk=user.pk).update(password=outdated_hash(PASSWORD))
                user.refresh_from_db()
                stored, session_hash = user.password, user.get_session_auth_hash()

                if path == "change-password/":
                    response = self.call(
                        user, path, current_password=PASSWORD, new_password=NEW_PASSWORD, token="000000"
                    )
                else:
                    response = self.call(user, path, password=PASSWORD, token="000000")
                self.assertEqual(response.status_code, 400)
                user.refresh_from_db()
                self.assertEqual(user.password, stored)
                self.assertEqual(user.get_session_auth_hash(), session_hash)

    def test_a_complete_proof_resets_the_count(self) -> None:
        for path in PATHS:
            with self.subTest(path=path):
                user, attempt = self.member_on(path, "reset")
                for _ in range(2):
                    attempt(WRONG)
                user.refresh_from_db()
                self.assertEqual(user.failed_login_attempts, 2)

                ok = attempt(PASSWORD)
                self.assertEqual(ok.status_code, 200, ok.content)
                user.refresh_from_db()
                self.assertEqual(user.failed_login_attempts, 0)


class StaffPagePasswordChecksTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="staff-lockout@example.ro", password=PASSWORD, staff_role="support")
        self.secret = enrol(self.user)
        self.client.force_login(self.user)

    def lock_through(self, post: Any) -> None:
        for _ in range(settings.ACCOUNT_LOCKOUT_THRESHOLD):
            post(WRONG)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, settings.ACCOUNT_LOCKOUT_THRESHOLD)
        self.assertTrue(self.user.is_account_locked())

    def assert_success_resets(self, post: Any) -> None:
        post(WRONG)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        post(PASSWORD)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def regenerate(self, password: str) -> Any:
        data = {"password": password, "token": pyotp.TOTP(self.secret).now(), "confirm_regenerate": "on"}
        return self.client.post("/auth/mfa/regenerate-backup-codes/", data)

    def change_password(self, password: str) -> Any:
        data = {"old_password": password, "new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD}
        return self.client.post("/auth/password-change/", data)

    def test_a_complete_proof_on_either_page_resets_the_count(self) -> None:
        for post in (self.regenerate, self.change_password):
            with self.subTest(page=post.__name__):
                self.assert_success_resets(post)

    def test_wrong_passwords_on_backup_code_regeneration_lock_the_account(self) -> None:
        self.lock_through(self.regenerate)
        codes = list(self.user.backup_tokens)
        self.regenerate(PASSWORD)  # the right password, while locked
        self.user.refresh_from_db()
        self.assertEqual(list(self.user.backup_tokens), codes)

    def test_wrong_old_passwords_on_the_password_change_page_lock_the_account(self) -> None:
        self.lock_through(self.change_password)
        self.change_password(PASSWORD)  # the right password, while locked
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))

    def test_a_locked_account_is_told_so_on_the_staff_pages(self) -> None:
        User.objects.filter(pk=self.user.pk).update(
            failed_login_attempts=5, account_locked_until=timezone.now() + timedelta(minutes=5)
        )
        self.assertContains(self.regenerate(PASSWORD), LOCKED_STAFF_CHECK)
        self.assertContains(self.change_password(PASSWORD), LOCKED_PASSWORD_CHANGE)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 5)  # said so, and not counted

    def test_a_lock_landing_after_the_old_password_was_checked_refuses_the_change(self) -> None:
        real_clean = LockedPasswordChangeForm.clean_old_password

        def checked_then_locked(form: LockedPasswordChangeForm) -> str:
            value = real_clean(form)
            User.objects.filter(pk=self.user.pk).update(account_locked_until=timezone.now() + timedelta(minutes=5))
            return str(value)

        with patch.object(LockedPasswordChangeForm, "clean_old_password", checked_then_locked):
            response = self.change_password(PASSWORD)
        self.assertContains(response, LOCKED_PASSWORD_CHANGE)
        self.assertNotContains(response, "changed while this form was open")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))
        self.assertTrue(self.user.is_account_locked())

    def test_a_failure_recorded_after_the_change_commits_is_kept(self) -> None:
        self.change_password(WRONG)  # one failure before the change, which the change clears
        real_apply = forms_module.apply_password_change

        def applied_then_failed_elsewhere(*args: Any, **kwargs: Any) -> User:
            written = real_apply(*args, **kwargs)
            User.objects.filter(pk=self.user.pk).update(failed_login_attempts=F("failed_login_attempts") + 1)
            return written

        with patch.object(forms_module, "apply_password_change", applied_then_failed_elsewhere):
            response = self.change_password(PASSWORD)
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
