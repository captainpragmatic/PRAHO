"""Confirming one's identity opens the session's 300-second window for sensitive actions.

``POST /api/users/session/reauth/`` checks the password, and the second factor when it is on, as
login checks them: each failure counts toward the same lockout, and every failure gets one answer,
so it never says which factor was wrong. A 2FA account that sends no code is refused before its
password is checked. Only the session that made the check is opened, and only while it is live: a
check that lands after the session ended changes nothing, a backup code included.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any
from unittest import skipUnless
from unittest.mock import patch

import pyotp
from django.db import DatabaseError, connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.users import portal_sessions
from apps.users.mfa import TOTPService
from apps.users.models import PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Original-secure123!"  # test fixture, not a credential
WRONG = "Not-the-password-1!"  # test fixture, not a credential
PATH = "/api/users/session/reauth/"
FAILED = {"success": False, "code": "reauth_failed"}


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class ReauthTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="confirm@example.ro", password=PASSWORD)
        self.session = portal_sessions.open_session(self.user)
        self.stale = timezone.now() - timedelta(hours=1)
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=self.stale)

    def _enrol(self) -> str:
        secret = TOTPService.generate_secret()
        user = User.objects.get(pk=self.user.pk)
        user.two_factor_secret = secret
        user.two_factor_enabled = True
        user.save()
        self.backup_codes = user.generate_backup_codes()
        # Enrolment moved the session hash: the calling session is re-stamped, as enrolment does.
        PortalSession.objects.filter(pk=self.session.pk).update(credential_snapshot=user.get_session_auth_hash())
        return secret

    def _confirm(self, **fields: Any) -> Any:
        body = {"user_id": self.user.pk, "session_id": str(self.session.pk), **fields}
        return self.portal_post(PATH, body)

    def _row(self) -> PortalSession:
        return PortalSession.objects.get(pk=self.session.pk)

    def _failures(self) -> int:
        return User.objects.get(pk=self.user.pk).failed_login_attempts

    def test_the_right_password_opens_the_window_and_clears_the_count(self) -> None:
        User.objects.filter(pk=self.user.pk).update(failed_login_attempts=2)
        response = self._confirm(password=PASSWORD)
        self.assertEqual(response.status_code, 200, response.content)
        # The window it opened, which the portal echoes back to act in it.
        self.assertEqual(response.json(), {"success": True, "step_up_at": self._row().reauth_at.isoformat()})
        self.assertTrue(portal_sessions.recently_reauthenticated(self._row(), timezone.now()))
        self.assertEqual(self._failures(), 0)
        (event,) = AuditEvent.objects.filter(action="step_up_confirmed")
        self.assertNotIn(str(self.session.pk), str(event.metadata))  # a digest only

    def test_a_wrong_password_counts_and_leaves_the_window_shut(self) -> None:
        response = self._confirm(password=WRONG)
        self.assertEqual((response.status_code, response.json()), (400, FAILED))
        self.assertEqual(self._row().reauth_at, self.stale)
        self.assertEqual(self._failures(), 1)
        self.assertTrue(AuditEvent.objects.filter(action="step_up_failed").exists())

    def test_a_locked_account_is_told_so_without_checking_the_password(self) -> None:
        User.objects.filter(pk=self.user.pk).update(
            failed_login_attempts=5, account_locked_until=timezone.now() + timedelta(minutes=5)
        )
        response = self._confirm(password=PASSWORD)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get("code"), "account_locked")
        self.assertEqual(self._failures(), 5)
        self.assertEqual(self._row().reauth_at, self.stale)

    def test_a_two_factor_account_without_a_code_is_refused_before_its_password(self) -> None:
        self._enrol()
        for password in (PASSWORD, WRONG):
            with self.subTest(password=password):
                response = self._confirm(password=password)
                self.assertEqual((response.status_code, response.json()), (400, FAILED))
        self.assertEqual(self._failures(), 0)  # the password was never checked
        self.assertEqual(self._row().reauth_at, self.stale)

    def test_a_wrong_code_counts_and_answers_like_a_wrong_password(self) -> None:
        self._enrol()
        response = self._confirm(password=PASSWORD, mfa_code="000000")
        self.assertEqual((response.status_code, response.json()), (400, FAILED))
        self.assertEqual(self._failures(), 1)
        self.assertEqual(self._row().reauth_at, self.stale)

    def test_both_factors_open_the_window(self) -> None:
        secret = self._enrol()
        response = self._confirm(password=PASSWORD, mfa_code=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(portal_sessions.recently_reauthenticated(self._row(), timezone.now()))

    def test_a_spent_code_budget_is_a_throttle_not_a_wrong_answer(self) -> None:
        secret = self._enrol()
        with patch("apps.users.mfa.MFAService._check_rate_limit", return_value=False):
            response = self._confirm(password=PASSWORD, mfa_code=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json().get("code"), "rate_limited")
        self.assertEqual(self._row().reauth_at, self.stale)
        self.assertEqual(self._failures(), 1)  # the unchecked code still counts, as at login
        self.assertFalse(AuditEvent.objects.filter(action="step_up_failed").exists())

    def test_a_backup_code_opens_the_window_and_is_spent(self) -> None:
        self._enrol()
        code = self.backup_codes[0]
        self.assertEqual(self._confirm(password=PASSWORD, mfa_code=code).status_code, 200)
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=self.stale)
        self.assertEqual(self._confirm(password=PASSWORD, mfa_code=code).json(), FAILED)

    def test_a_session_ended_after_binding_opens_nothing_and_spends_no_code(self) -> None:
        self._enrol()
        code = self.backup_codes[0]
        resolve = portal_sessions.resolve

        def resolve_then_end(*args: Any, **kwargs: Any) -> PortalSession | None:
            row = resolve(*args, **kwargs)
            if row is not None:  # a logout in another request, between binding and this view
                PortalSession.objects.filter(pk=row.pk).update(revoked_at=timezone.now(), revoke_reason="logout")
            return row

        with patch("apps.users.portal_sessions.resolve", side_effect=resolve_then_end):
            response = self._confirm(password=PASSWORD, mfa_code=code)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["active"])
        self.assertEqual(self._row().reauth_at, self.stale)
        self.assertFalse(AuditEvent.objects.filter(action="step_up_confirmed").exists())
        # The code was not spent: it still opens a new session's window.
        self.session = portal_sessions.open_session(User.objects.get(pk=self.user.pk))
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=self.stale)
        self.assertEqual(self._confirm(password=PASSWORD, mfa_code=code).status_code, 200)

    def test_a_password_changed_after_binding_opens_nothing(self) -> None:
        resolve = portal_sessions.resolve

        def resolve_then_change(*args: Any, **kwargs: Any) -> PortalSession | None:
            row = resolve(*args, **kwargs)
            if row is not None:  # another request changes the password after this one was bound
                user = User.objects.get(pk=self.user.pk)
                user.set_password(PASSWORD)
                user.save(update_fields=["password"])
            return row

        with patch("apps.users.portal_sessions.resolve", side_effect=resolve_then_change):
            response = self._confirm(password=PASSWORD)
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(self._row().revoked_at)  # not ended: its credentials moved under it
        self.assertEqual(self._row().reauth_at, self.stale)

    def test_a_wrong_password_on_an_ended_session_is_not_counted(self) -> None:
        resolve = portal_sessions.resolve

        def resolve_then_end(*args: Any, **kwargs: Any) -> PortalSession | None:
            row = resolve(*args, **kwargs)
            if row is not None:
                PortalSession.objects.filter(pk=row.pk).update(revoked_at=timezone.now(), revoke_reason="logout")
            return row

        with patch("apps.users.portal_sessions.resolve", side_effect=resolve_then_end):
            response = self._confirm(password=WRONG)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self._failures(), 0)
        self.assertFalse(AuditEvent.objects.filter(action="step_up_failed").exists())

    def test_an_account_deleted_before_the_lock_ends_the_session_not_the_server(self) -> None:
        lock = User.objects.select_for_update

        def delete_then_lock(*args: Any, **kwargs: Any) -> Any:
            User.objects.filter(pk=self.user.pk).delete()  # after authentication read it, before this lock
            return lock(*args, **kwargs)

        with patch.object(User.objects, "select_for_update", side_effect=delete_then_lock):
            response = self._confirm(password=PASSWORD)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["active"])

    def test_a_window_that_cannot_be_recorded_undoes_the_spent_code(self) -> None:
        self._enrol()
        code = self.backup_codes[0]
        with patch("apps.users.portal_sessions.mark_reauth", return_value=False):
            response = self._confirm(password=PASSWORD, mfa_code=code)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(AuditEvent.objects.filter(action="step_up_confirmed").exists())
        # The code was not spent: it still opens the window once the session can be marked.
        self.assertEqual(self._confirm(password=PASSWORD, mfa_code=code).status_code, 200)

    def test_a_request_without_a_session_is_refused_as_an_ended_one(self) -> None:
        for required in (False, True):
            with self.subTest(required=required), override_settings(PORTAL_SESSION_REQUIRED=required):
                response = self.portal_post(PATH, {"user_id": self.user.pk, "password": PASSWORD})
                self.assertEqual(response.status_code, 401)
                self.assertFalse(response.json()["active"])
        self.assertEqual(self._row().reauth_at, self.stale)

    def test_a_malformed_password_is_refused_without_counting(self) -> None:
        for password in (None, 123, ["x"]):
            with self.subTest(password=password):
                self.assertEqual(self._confirm(password=password).json(), FAILED)
        self.assertEqual(self._failures(), 0)

    def test_a_database_fault_is_an_outage_not_a_refusal(self) -> None:
        with patch("apps.api.users.views.check_password_locked", side_effect=DatabaseError("down")):
            response = self._confirm(password=PASSWORD)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("active", response.json())


@skipUnless(connection.vendor == "postgresql", "row lock modes are PostgreSQL's")
@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class ReauthLockTests(HMACTestMixin, TestCase):
    def test_the_user_is_locked_without_blocking_a_revocation_s_audit_insert(self) -> None:
        # end() holds the session row while its audit insert takes a key-share lock on the user; a FOR
        # UPDATE on the user here, then a wait for the session, would deadlock with it.
        user = User.objects.create_user(email="lock@example.ro", password=PASSWORD)
        session = portal_sessions.open_session(user)
        with CaptureQueriesContext(connection) as queries:
            response = self.portal_post(PATH, {"user_id": user.pk, "session_id": str(session.pk), "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.content)
        locks = [q["sql"] for q in queries.captured_queries if " FOR " in q["sql"] and "UPDATE" in q["sql"]]
        user_lock = next(i for i, sql in enumerate(locks) if 'FROM "users" ' in sql)
        session_lock = next(i for i, sql in enumerate(locks) if f'FROM "{PortalSession._meta.db_table}" ' in sql)
        self.assertIn("FOR NO KEY UPDATE", locks[user_lock])
        self.assertLess(user_lock, session_lock)

    def test_the_profile_update_locks_the_user_the_same_way(self) -> None:
        user = User.objects.create_user(email="profile-lock@example.ro", password=PASSWORD)
        session = portal_sessions.open_session(user)
        body = json.dumps({"user_id": user.pk, "session_id": str(session.pk), "timestamp": time.time(), "phone": ""})
        with CaptureQueriesContext(connection) as queries:
            response = self.client.put(
                "/api/users/profile/",
                body,
                content_type="application/json",
                **hmac_headers("PUT", "/api/users/profile/", body.encode()),
            )
        self.assertEqual(response.status_code, 200, response.content)
        locks = [q["sql"] for q in queries.captured_queries if 'FROM "users" ' in q["sql"] and " FOR " in q["sql"]]
        self.assertTrue(locks)
        self.assertTrue(all("FOR NO KEY UPDATE" in sql for sql in locks), locks)
