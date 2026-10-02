"""Token issuance must demand the second factor, exactly as login does (#565).

`/api/users/token/` is public (ADR-0031) and issued a 90-day bearer token on email and
password alone. For an account with 2FA enabled that made the password the whole
credential on this path, while every login path also asks for the code. The token is
only usable behind HMAC today (see test_token_auth_requires_hmac.py), so the gap was
latent, but it turns into an account takeover the day token auth is exposed.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pyotp
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from freezegun import freeze_time

from apps.users.mfa import TOTPService
from apps.users.models import APIToken, User
from apps.users.services import APITokenService

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
WRONG_PASSWORD = "definitely-not-the-password"  # test fixture, not a credential


# Same two overrides as test_token_endpoint_lockout.py: the throttles are live on this
# endpoint, and they need a real cache to count against.
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=True,
)
class TokenEndpointSecondFactorTests(TestCase):
    url = "/api/users/token/"

    def setUp(self) -> None:
        cache.clear()  # throttle buckets are cache-backed and leak between tests
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="mfa-owner@example.ro", password=PASSWORD)
        self.secret = TOTPService.generate_secret()
        self.user.two_factor_secret = self.secret
        self.user.two_factor_enabled = True
        self.user.save()

    def post(self, email: str = "", password: str = PASSWORD, **extra: str) -> tuple[int, dict[str, object]]:
        body = {"email": email or self.user.email, "password": password, **extra}
        response = self.client.post(self.url, body, content_type="application/json")
        return response.status_code, response.json()

    def assert_refused(self, status_code: int, payload: dict[str, object], tokens: int = 0) -> None:
        self.assertEqual(status_code, 401, payload)
        # Same body as a wrong password: a distinct message here would confirm the
        # password to anyone who can reach this public endpoint.
        self.assertEqual(payload, {"error": "Invalid credentials"})
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), tokens, "a token was issued without 2FA")

    # --- Fail on master: the password alone was enough -------------------------------

    def test_correct_password_without_a_code_issues_no_token(self) -> None:
        self.assert_refused(*self.post())

    def test_wrong_code_issues_no_token_and_counts_against_the_account(self) -> None:
        self.assert_refused(*self.post(mfa_token="000000"))
        self.user.refresh_from_db()
        # Unlike a wrong password, this failure required the right password, so it is
        # attributable to whoever holds it and may drive the lockout.
        self.assertEqual(self.user.failed_login_attempts, 1)

    def test_replayed_totp_issues_no_second_token(self) -> None:
        code = pyotp.TOTP(self.secret).now()
        self.assertEqual(self.post(mfa_token=code)[0], 200)
        self.assert_refused(*self.post(mfa_token=code), tokens=1)

    def test_locked_two_factor_account_gets_the_generic_refusal(self) -> None:
        self.user.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.user.save(update_fields=["account_locked_until"])
        self.assert_refused(*self.post(mfa_token=pyotp.TOTP(self.secret).now()))

    def test_inactive_two_factor_account_gets_the_generic_refusal(self) -> None:
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assert_refused(*self.post(mfa_token=pyotp.TOTP(self.secret).now()))

    # --- Interleavings: the decision is re-read on the locked row ----------------------

    def authenticate_then(self, change: Callable[[], None]) -> Any:
        """Run the real password check, then change the account before issuance continues."""

        def side_effect(*args: Any, **kwargs: Any) -> Any:
            result = authenticate(*args, **kwargs)
            change()
            return result

        return patch("apps.api.users.views.authenticate", side_effect=side_effect)

    def test_2fa_enrolled_after_the_password_check_is_still_required(self) -> None:
        plain = User.objects.create_user(email="enrolling@example.ro", password=PASSWORD)

        def enrol() -> None:
            User.objects.filter(pk=plain.pk).update(two_factor_enabled=True)

        with self.authenticate_then(enrol):
            status_code, payload = self.post(email=plain.email)
        self.assertEqual((status_code, payload), (401, {"error": "Invalid credentials"}))
        self.assertFalse(APIToken.objects.filter(user=plain).exists())

    def test_password_changed_after_the_password_check_issues_no_token(self) -> None:
        def change_password() -> None:
            fresh = User.objects.get(pk=self.user.pk)
            fresh.set_password("a-completely-different-passphrase")  # test fixture
            fresh.save(update_fields=["password"])

        with self.authenticate_then(change_password):
            self.assert_refused(*self.post(mfa_token=pyotp.TOTP(self.secret).now()))

    def test_lock_applied_after_the_password_check_issues_no_token(self) -> None:
        def lock() -> None:
            User.objects.filter(pk=self.user.pk).update(account_locked_until=timezone.now() + timedelta(minutes=30))

        with self.authenticate_then(lock):
            self.assert_refused(*self.post(mfa_token=pyotp.TOTP(self.secret).now()))

    # --- A code is only spent when a token is issued -----------------------------------

    def test_invalid_parameters_are_refused_before_the_code_is_spent(self) -> None:
        code = self.user.generate_backup_codes()[0]
        status_code, payload = self.post(mfa_token=code, ttl_days="0")
        self.assertEqual(status_code, 400, payload)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 8, "the backup code was spent on a refused request")
        self.assertEqual(self.post(mfa_token=code)[0], 200)

    def test_invalid_parameters_answer_the_same_whatever_the_password(self) -> None:
        # Answering 400 only after a correct password would confirm it.
        right = self.post(ttl_days="0")
        wrong = self.post(password=WRONG_PASSWORD, ttl_days="0")
        self.assertEqual(right, wrong)
        self.assertEqual(right[0], 400)

    @override_settings(API_TOKEN_MAX_ACTIVE_PER_USER=1)
    def test_token_quota_refusal_returns_the_backup_code_and_keeps_the_counter(self) -> None:
        APITokenService.issue_token(user=self.user, name="existing").unwrap()
        code = self.user.generate_backup_codes()[0]
        User.objects.filter(pk=self.user.pk).update(failed_login_attempts=2)

        status_code, payload = self.post(mfa_token=code)

        self.assertEqual(status_code, 400, payload)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 8, "a refused issuance spent the backup code")
        self.assertEqual(self.user.failed_login_attempts, 2, "a refused issuance reset the lockout counter")

    # --- Controls: already true on master and must stay true ---------------------------

    def test_success_resets_the_lockout_counter(self) -> None:
        User.objects.filter(pk=self.user.pk).update(failed_login_attempts=3)
        self.assertEqual(self.post(mfa_token=pyotp.TOTP(self.secret).now())[0], 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_valid_totp_issues_a_token(self) -> None:
        status_code, payload = self.post(mfa_token=pyotp.TOTP(self.secret).now())
        self.assertEqual(status_code, 200, payload)
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 1)

    def test_backup_code_issues_a_token_and_is_spent(self) -> None:
        code = self.user.generate_backup_codes()[0]
        status_code, payload = self.post(mfa_token=code)
        self.assertEqual(status_code, 200, payload)
        cache.clear()  # the replay must fail on the spent code, not on a throttle
        self.assert_refused(*self.post(mfa_token=code), tokens=1)

    def test_wrong_password_still_does_not_drive_the_lockout(self) -> None:
        status_code, payload = self.post(password=WRONG_PASSWORD, mfa_token="000000")
        self.assert_refused(status_code, payload)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_accounts_without_2fa_are_unaffected(self) -> None:
        plain = User.objects.create_user(email="plain@example.ro", password=PASSWORD)
        status_code, payload = self.post(email=plain.email)
        self.assertEqual(status_code, 200, payload)
        self.assertEqual(APIToken.objects.filter(user=plain).count(), 1)


LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


# The configured cache, not the LocMem stand-in above. Which store holds the TOTP replay
# marker decides whether a refused issuance spends the code, so this class needs the real one.
@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "test_token_totp_cache",
            "TIMEOUT": 300,
        }
    },
    RATE_LIMITING_ENABLED=True,
    API_TOKEN_MAX_ACTIVE_PER_USER=1,
)
class RefusedIssuanceTOTPReplayTests(TestCase):
    """A token refused at the live-token cap leaves the TOTP code usable once (ADR-0031).

    The replay marker is a cache write. Under DatabaseCache it runs on the default
    connection inside the issuance transaction, so set_rollback(True) discards it along
    with the rest of the refused request. A cache on a separate store keeps the marker.
    """

    url = "/api/users/token/"

    def setUp(self) -> None:
        call_command("createcachetable", verbosity=0)
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="totp-quota@example.ro", password=PASSWORD)
        self.secret = TOTPService.generate_secret()
        self.user.two_factor_secret = self.secret
        self.user.two_factor_enabled = True
        self.user.save()
        self.existing = APITokenService.issue_token(user=self.user, name="existing").unwrap().token

    def post(self, code: str) -> tuple[int, dict[str, object]]:
        body = {"email": self.user.email, "password": PASSWORD, "mfa_token": code}
        response = self.client.post(self.url, body, content_type="application/json")
        return response.status_code, response.json()

    def refuse_at_the_cap_then_retry(self) -> tuple[int, dict[str, object]]:
        # One frozen instant: both requests carry the same code inside the same TOTP step.
        with freeze_time("2026-10-02 10:00:05"):
            code = pyotp.TOTP(self.secret).now()
            status_code, payload = self.post(code)
            self.assertEqual(status_code, 400, payload)
            self.assertEqual(list(APIToken.objects.filter(user=self.user)), [self.existing])

            self.existing.delete()  # frees the one slot; the cache is left as it is
            return self.post(code)

    def test_the_same_totp_code_works_after_a_refused_issuance(self) -> None:
        status_code, payload = self.refuse_at_the_cap_then_retry()
        self.assertEqual(status_code, 200, payload)
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 1)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_a_separate_store_cache_keeps_the_refused_code_spent(self) -> None:
        # Control for the test above: with the marker outside the transaction, the retry
        # is a replay. Without this, the test above would also pass if the marker were
        # never written at all.
        status_code, payload = self.refuse_at_the_cap_then_retry()
        self.assertEqual((status_code, payload), (401, {"error": "Invalid credentials"}))
        self.assertFalse(APIToken.objects.filter(user=self.user).exists())
