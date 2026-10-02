"""The staff web login must ask for the second factor (#590).

The password step used to call login() for every staff user, so an account with TOTP
enrolled got in on the password alone. mfa_verify was written to resume a half-finished
login, but nothing ever started one. These tests drive the real two-step flow.
"""

from __future__ import annotations

import time
from datetime import timedelta
from importlib import import_module
from typing import Any
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.users.mfa import TOTPService
from apps.users.models import APIToken, User, UserLoginLog
from apps.users.services import SessionSecurityService
from apps.users.views import PRE_2FA_SESSION_KEY, PRE_2FA_TTL_SECONDS, _complete_pending_login, _PendingLogin

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
NEXT = "/customers/"


@override_settings(CACHES=settings.LOCMEM_TEST_CACHE)
class StaffLoginSecondFactorTests(TestCase):
    def setUp(self) -> None:
        cache.clear()  # the replay marker and the MFA attempt budget live in the cache
        self.addCleanup(cache.clear)
        self.user, self.secret = self.make_user("totp-staff@example.ro")

    # --- helpers ----------------------------------------------------------------------

    def make_user(self, email: str, *, staff_role: str = "support", enrolled: bool = True) -> tuple[User, str]:
        user = User.objects.create_user(email=email, password=PASSWORD, is_staff=True, staff_role=staff_role)
        secret = TOTPService.generate_secret()
        if enrolled:
            user.two_factor_secret = secret
            user.two_factor_enabled = True
            user.save()
        return user, secret

    def password_step(
        self, user: User | None = None, *, next_url: str = NEXT, remember: bool = False, client: Client | None = None,
        **extra: Any,
    ) -> Any:
        client = client or self.client
        data: dict[str, Any] = {"email": (user or self.user).email, "password": PASSWORD}
        if remember:
            data["remember_me"] = "on"
        return client.post(f"{reverse('users:login')}?next={next_url}", data, **extra)

    def code_step(self, code: str, *, client: Client | None = None, **extra: Any) -> Any:
        return (client or self.client).post(reverse("users:mfa_verify"), {"token": code}, **extra)

    def totp(self) -> str:
        return pyotp.TOTP(self.secret).now()

    def authenticated_id(self, client: Client | None = None) -> str | None:
        return (client or self.client).session.get("_auth_user_id")

    def latest_login_audit(self) -> AuditEvent:
        return AuditEvent.objects.filter(action="login_success").latest("timestamp")

    # --- the handoff ------------------------------------------------------------------

    def test_password_alone_does_not_authenticate_and_hands_off_to_mfa_verify(self) -> None:
        response = self.password_step()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("users:mfa_verify"))
        self.assertIsNone(self.authenticated_id(), "the password alone established a session")
        self.assertEqual(self.client.session[PRE_2FA_SESSION_KEY]["user_id"], self.user.pk)
        self.assertEqual(UserLoginLog.objects.filter(user=self.user).latest("timestamp").status, "password_ok_2fa_pending")

    def test_pending_user_cannot_reach_staff_pages(self) -> None:
        self.password_step()
        for url in (reverse("dashboard"), "/settings/api-tokens/"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(reverse("users:login")), response["Location"])

    def test_password_step_keeps_the_failure_count_until_the_second_factor(self) -> None:
        User.objects.filter(pk=self.user.pk).update(failed_login_attempts=3)
        self.password_step()
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 3)

    def test_session_key_changes_at_both_steps(self) -> None:
        session = self.client.session
        session["probe"] = True
        session.save()
        anonymous_key = session.session_key
        self.password_step()
        pending_key = self.client.session.session_key
        self.code_step(self.totp())
        authenticated_key = self.client.session.session_key
        self.assertEqual(len({anonymous_key, pending_key, authenticated_key}), 3)

    # --- completing the login ---------------------------------------------------------

    def test_correct_totp_completes_login_and_lands_on_the_stored_next(self) -> None:
        self.password_step()
        response = self.code_step(self.totp())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], NEXT)
        self.assertEqual(self.authenticated_id(), str(self.user.pk))
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)
        self.assertEqual(UserLoginLog.objects.filter(user=self.user).latest("timestamp").status, "success")
        self.assertEqual(self.latest_login_audit().metadata["authentication_method"], "2fa_totp")

    def test_backup_code_completes_login_once_and_is_audited_as_a_backup_code(self) -> None:
        code = self.user.generate_backup_codes()[0]
        self.password_step()
        self.assertEqual(self.code_step(code)["Location"], NEXT)
        self.assertEqual(self.latest_login_audit().metadata["authentication_method"], "2fa_backup_code")

        second = Client()
        self.password_step(client=second)
        response = self.code_step(code, client=second)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.authenticated_id(second), "a spent backup code logged in again")
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)

    def test_replayed_totp_is_refused(self) -> None:
        code = self.totp()
        self.password_step()
        self.assertEqual(self.code_step(code)["Location"], NEXT)

        second = Client()
        self.password_step(client=second)
        self.code_step(code, client=second)
        self.assertIsNone(self.authenticated_id(second), "a replayed TOTP code logged in")

    def test_backup_code_is_accepted_through_the_page_form(self) -> None:
        """The page posts one field, `token`, for both kinds of code (the old JS truncated to 6)."""
        response = self.client.get(reverse("users:mfa_verify"))
        self.assertEqual(response.status_code, 302)  # nothing pending yet
        self.password_step()
        page = self.client.get(reverse("users:mfa_verify"))
        self.assertContains(page, 'name="token"')
        self.assertNotContains(page, "substring(0, 6)")
        self.assertNotContains(page, "backup-token")

    # --- failures -----------------------------------------------------------------------

    def test_wrong_code_counts_toward_the_lockout_and_is_logged(self) -> None:
        self.password_step()
        response = self.code_step("000000")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.authenticated_id())
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        self.assertEqual(UserLoginLog.objects.filter(user=self.user).latest("timestamp").status, "failed_2fa")
        self.assertIn(PRE_2FA_SESSION_KEY, self.client.session)  # another attempt is allowed

    def test_lockout_at_the_threshold_clears_the_pending_login(self) -> None:
        User.objects.filter(pk=self.user.pk).update(failed_login_attempts=settings.ACCOUNT_LOCKOUT_THRESHOLD - 1)
        self.password_step()
        response = self.code_step("000000")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("users:login"))
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_account_locked())

    def test_expired_pending_login_redirects_to_login(self) -> None:
        self.password_step()
        session = self.client.session
        session[PRE_2FA_SESSION_KEY]["issued_at"] -= PRE_2FA_TTL_SECONDS + 1
        session.save()
        response = self.code_step(self.totp())
        self.assertEqual(response["Location"], reverse("users:login"))
        self.assertIsNone(self.authenticated_id())
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)

    def test_malformed_pending_state_redirects_to_login(self) -> None:
        self.password_step()
        valid = dict(self.client.session[PRE_2FA_SESSION_KEY])
        malformed: dict[str, Any] = {
            "not a dict": "x",
            "missing auth_hash": {k: v for k, v in valid.items() if k != "auth_hash"},
            "string issued_at": {**valid, "issued_at": str(valid["issued_at"])},
            "bool issued_at": {**valid, "issued_at": True},
            "future issued_at": {**valid, "issued_at": valid["issued_at"] + 3600},
            "string user_id": {**valid, "user_id": str(valid["user_id"])},
            "unknown backend": {**valid, "backend": "evil.Backend"},
            "external next": {**valid, "next": "https://evil.example/"},
        }
        for label, value in malformed.items():
            with self.subTest(label):
                session = self.client.session
                session[PRE_2FA_SESSION_KEY] = value
                session.save()
                response = self.code_step(self.totp())
                self.assertEqual(response["Location"], reverse("users:login"))
                self.assertIsNone(self.authenticated_id())
                self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)

    def test_account_changes_between_the_steps_refuse_the_login(self) -> None:
        def deactivate(user: User) -> None:
            User.objects.filter(pk=user.pk).update(is_active=False)

        def lock(user: User) -> None:
            User.objects.filter(pk=user.pk).update(account_locked_until=timezone.now() + timedelta(minutes=5))

        def demote(user: User) -> None:
            User.objects.filter(pk=user.pk).update(is_staff=False, staff_role="")

        def drop_2fa(user: User) -> None:
            User.objects.filter(pk=user.pk).update(two_factor_enabled=False)

        def change_password(user: User) -> None:
            fresh = User.objects.get(pk=user.pk)
            fresh.set_password("a-completely-new-password")
            fresh.save(update_fields=["password"])

        def delete(user: User) -> None:
            User.objects.filter(pk=user.pk).delete()

        for change in (deactivate, lock, demote, drop_2fa, change_password, delete):
            with self.subTest(change.__name__):
                user, secret = self.make_user(f"{change.__name__}@example.ro")
                client = Client()
                self.password_step(user, client=client)
                self.assertIn(PRE_2FA_SESSION_KEY, client.session)
                change(user)
                response = self.code_step(pyotp.TOTP(secret).now(), client=client)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], reverse("users:login"))
                self.assertIsNone(self.authenticated_id(client))
                self.assertNotIn(PRE_2FA_SESSION_KEY, client.session)

    def test_hostile_next_is_ignored(self) -> None:
        self.password_step(next_url="https://evil.example/")
        self.assertEqual(self.code_step(self.totp())["Location"], reverse("dashboard"))

    # --- session policy -------------------------------------------------------------------

    def test_remember_me_from_the_password_step_applies_after_the_second_factor(self) -> None:
        self.password_step(remember=True)
        self.assertIsNone(self.authenticated_id())
        self.assertEqual(self.code_step(self.totp())["Location"], NEXT)
        policies = SessionSecurityService._get_timeout_policies()
        self.assertEqual(self.client.session.get_expiry_age(), policies["remember_me"])

    def test_sensitive_role_timeout_beats_remember_me(self) -> None:
        admin, secret = self.make_user("totp-admin@example.ro", staff_role="admin")
        self.password_step(admin, remember=True)
        self.assertIsNone(self.authenticated_id())
        self.assertEqual(self.code_step(pyotp.TOTP(secret).now())["Location"], NEXT)
        self.assertEqual(self.authenticated_id(), str(admin.pk))
        policies = SessionSecurityService._get_timeout_policies()
        self.assertEqual(self.client.session.get_expiry_age(), policies["sensitive"])

    def test_failure_after_login_logs_the_request_out(self) -> None:
        """A failure after login() must not leave the request authenticated."""
        request = RequestFactory().post(reverse("users:mfa_verify"))
        request.session = import_module(settings.SESSION_ENGINE).SessionStore()
        request.user = AnonymousUser()
        pending = _PendingLogin(
            user_id=self.user.pk,
            issued_at=int(time.time()),
            remember_me=False,
            next=NEXT,
            auth_hash=self.user.get_session_auth_hash(),
            backend="django.contrib.auth.backends.ModelBackend",
        )
        with (
            patch.object(SessionSecurityService, "update_session_timeout", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            _complete_pending_login(request, pending, self.totp())
        self.assertFalse(request.user.is_authenticated)
        self.assertNotIn("_auth_user_id", request.session)

    def test_regression_guard_failure_after_login_leaves_no_session(self) -> None:
        """Through the client; Django also skips saving the session on a 500, so this alone is not proof."""
        self.password_step()
        with (
            patch.object(SessionSecurityService, "update_session_timeout", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            self.code_step(self.totp())
        self.assertIsNone(self.authenticated_id(), "a half-finished login kept its session")

    # --- HTMX, cancel, leftovers -------------------------------------------------------

    def test_htmx_gets_hx_redirect_at_both_steps(self) -> None:
        first = self.password_step(HTTP_HX_REQUEST="true")
        self.assertEqual(first["HX-Redirect"], reverse("users:mfa_verify"))
        second = self.code_step(self.totp(), HTTP_HX_REQUEST="true")
        self.assertEqual(second["HX-Redirect"], NEXT)
        self.assertEqual(self.authenticated_id(), str(self.user.pk))

    def test_cancel_link_clears_the_pending_login(self) -> None:
        self.password_step()
        page = self.client.get(reverse("users:mfa_verify"))
        self.assertContains(page, f'href="{reverse("users:logout")}"')
        self.client.get(reverse("users:logout"))
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)
        self.assertEqual(self.client.get(reverse("users:mfa_verify"))["Location"], reverse("users:login"))

    def test_authenticated_user_on_mfa_verify_goes_to_the_dashboard(self) -> None:
        self.client.force_login(self.user)
        session = self.client.session
        session[PRE_2FA_SESSION_KEY] = {"user_id": self.user.pk}
        session.save()
        response = self.client.get(reverse("users:mfa_verify"))
        self.assertEqual(response["Location"], reverse("dashboard"))
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)

    # --- regression guards: accounts without 2FA ----------------------------------------

    def test_regression_guard_staff_without_2fa_logs_in_on_the_password(self) -> None:
        plain, _secret = self.make_user("plain-staff@example.ro", enrolled=False)
        response = self.password_step(plain)
        self.assertEqual(response["Location"], NEXT)
        self.assertEqual(self.authenticated_id(), str(plain.pk))
        self.assertEqual(self.latest_login_audit().metadata["authentication_method"], "password")

    def test_password_login_clears_a_leftover_pending_state(self) -> None:
        self.password_step()
        plain, _secret = self.make_user("plain-after@example.ro", enrolled=False)
        self.password_step(plain)
        self.assertEqual(self.authenticated_id(), str(plain.pk))
        self.assertNotIn(PRE_2FA_SESSION_KEY, self.client.session)


# Same overrides as tests/api/test_token_endpoint_second_factor.py: the token endpoint's
# throttles are live, and the replay marker needs a real cache.
@override_settings(CACHES=settings.LOCMEM_TEST_CACHE, RATE_LIMITING_ENABLED=True)
class CrossChannelReplayTests(TestCase):
    """One TOTP code is good for one login, whichever channel spends it first."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(
            email="cross-channel@example.ro", password=PASSWORD, is_staff=True, staff_role="support"
        )
        self.secret = TOTPService.generate_secret()
        self.user.two_factor_secret = self.secret
        self.user.two_factor_enabled = True
        self.user.save()
        self.code = pyotp.TOTP(self.secret).now()

    def web_login(self, client: Client) -> Any:
        client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})
        return client.post(reverse("users:mfa_verify"), {"token": self.code})

    def api_token(self) -> Any:
        body = {"email": self.user.email, "password": PASSWORD, "mfa_token": self.code}
        return Client().post("/api/users/token/", body, content_type="application/json")

    def test_code_spent_on_the_web_is_refused_by_the_token_endpoint(self) -> None:
        web = Client()
        self.assertEqual(self.web_login(web)["Location"], reverse("dashboard"))
        self.assertEqual(self.api_token().status_code, 401)
        self.assertFalse(APIToken.objects.filter(user=self.user).exists())

    def test_code_spent_on_the_token_endpoint_is_refused_on_the_web(self) -> None:
        self.assertEqual(self.api_token().status_code, 200)
        web = Client()
        self.web_login(web)
        self.assertNotIn("_auth_user_id", web.session, "a TOTP code spent on the API logged in on the web")
