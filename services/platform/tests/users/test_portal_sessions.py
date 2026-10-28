"""Platform owns the customer's portal session (ADR-0017 section 5).

Requests go through the real HMAC middleware (test settings strip it), so the binding is proven
where it runs: before any view, for decorated views and for views that read the signed user_id
themselves.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.session_digest import session_key_digest
from apps.users import portal_sessions
from apps.users.models import PortalSession, User
from apps.users.pending_totp import complete_enrolment
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PASSWORD = "Correct-Horse-Battery-9"  # test credential
PROBE = "/api/portal-session-probe/"  # no such route: 404 means the middleware admitted the request
CONSENT_HISTORY = "/api/gdpr/consent-history/"  # reads the signed user_id itself, outside secure_auth
LOGIN = "/api/users/login/"
SESSION_END = "/api/users/session/end/"
PASSWORD_CHANGE = "/api/users/change-password/"


def _customer(email: str = "customer@example.ro") -> User:
    return User.objects.create_user(email=email, password=PASSWORD)


class PortalSessionServiceTests(TestCase):
    def setUp(self) -> None:
        self.user = _customer()

    def test_open_session_binds_the_credentials_and_today_s_lifetimes(self) -> None:
        before = timezone.now()
        row = portal_sessions.open_session(self.user, ip="203.0.113.9", user_agent="Firefox")
        self.assertEqual(row.credential_snapshot, self.user.get_session_auth_hash())
        self.assertGreaterEqual(row.expires_at, before + portal_sessions.ABSOLUTE_TIMEOUT)
        self.assertLessEqual(row.idle_deadline, row.last_seen_at + portal_sessions.IDLE_TIMEOUT)
        self.assertNotIn("203.0.113.9", row.ip_digest)
        event = AuditEvent.objects.filter(action="login_success").latest("timestamp")
        self.assertEqual(event.metadata["portal_session"], session_key_digest(str(row.pk)))
        self.assertNotIn(str(row.pk), json.dumps(event.metadata))

    def test_resolve_refuses_every_dead_or_foreign_row(self) -> None:
        other = _customer("other@example.ro")
        live = portal_sessions.open_session(self.user)
        self.assertEqual(portal_sessions.resolve(str(live.pk), self.user.pk, interactive=False), live)
        self.assertIsNone(portal_sessions.resolve(str(live.pk), other.pk, interactive=False))
        for bad_id in ("", "not-a-uuid", str(live.pk).upper(), 42, None):
            with self.subTest(bad_id=bad_id):
                self.assertIsNone(portal_sessions.resolve(bad_id, self.user.pk, interactive=False))
        now = timezone.now()
        for field, value in (
            ("revoked_at", now),
            ("idle_deadline", now - timedelta(seconds=1)),
            ("expires_at", now - timedelta(seconds=1)),
        ):
            with self.subTest(field=field):
                row = portal_sessions.open_session(self.user)
                PortalSession.objects.filter(pk=row.pk).update(**{field: value})
                self.assertIsNone(portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False))
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertIsNone(portal_sessions.resolve(str(live.pk), self.user.pk, interactive=False))

    def test_a_credential_change_ends_the_row_at_its_next_request(self) -> None:
        row = portal_sessions.open_session(self.user)
        self.user.set_password("Another-Horse-Battery-7")
        self.user.save(update_fields=["password"])
        self.assertIsNone(portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False))
        row.refresh_from_db()
        self.assertIsNotNone(row.revoked_at)
        self.assertEqual(row.revoke_reason, portal_sessions.REASON_CREDENTIALS)

    def test_a_second_factor_rotation_ends_the_row(self) -> None:
        from apps.users.mfa import MFAService  # noqa: PLC0415

        row = portal_sessions.open_session(self.user)
        MFAService.apply_state_change(self.user, action="rotate")  # a WebAuthn key added or removed
        self.assertIsNone(portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False))

    def test_a_snapshot_under_a_retired_key_is_promoted(self) -> None:
        with override_settings(SECRET_KEY="old-key-" + "x" * 50):
            row = portal_sessions.open_session(self.user)
            old = row.credential_snapshot
        with override_settings(SECRET_KEY="new-key-" + "y" * 50, SECRET_KEY_FALLBACKS=["old-key-" + "x" * 50]):
            self.assertIsNotNone(portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False))
            row.refresh_from_db()
            self.assertNotEqual(row.credential_snapshot, old)
            self.assertEqual(row.credential_snapshot, User.objects.get(pk=self.user.pk).get_session_auth_hash())

    def test_only_interactive_activity_extends_the_idle_deadline(self) -> None:
        row = portal_sessions.open_session(self.user)
        stale = timezone.now() - timedelta(minutes=5)
        PortalSession.objects.filter(pk=row.pk).update(last_seen_at=stale, idle_deadline=stale + timedelta(hours=1))
        portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False)
        row.refresh_from_db()
        self.assertEqual(row.last_seen_at, stale)
        portal_sessions.resolve(str(row.pk), self.user.pk, interactive=True)
        row.refresh_from_db()
        self.assertGreater(row.last_seen_at, stale)
        self.assertLessEqual(row.idle_deadline, row.expires_at)

    def test_a_delayed_touch_never_moves_the_deadline_back(self) -> None:
        row = portal_sessions.open_session(self.user)
        later = timezone.now() + timedelta(minutes=2)
        PortalSession.objects.filter(pk=row.pk).update(last_seen_at=later, idle_deadline=later + timedelta(hours=1))
        with patch("apps.users.portal_sessions.TOUCH_INTERVAL", timedelta(0)):
            portal_sessions.resolve(str(row.pk), self.user.pk, interactive=True)
        row.refresh_from_db()
        self.assertEqual(row.last_seen_at, later)

    def test_restamp_keeps_only_a_live_row_still_on_the_old_hash(self) -> None:
        row = portal_sessions.open_session(self.user)
        old = row.credential_snapshot
        self.assertFalse(portal_sessions.restamp(row, old_hash="someone-else", new_hash="new"))
        self.assertTrue(portal_sessions.restamp(row, old_hash=old, new_hash="new"))
        portal_sessions.end(row, portal_sessions.REASON_LOGOUT)
        self.assertFalse(portal_sessions.restamp(row, old_hash="new", new_hash="newer"))
        row.refresh_from_db()
        self.assertEqual(row.credential_snapshot, "new")

    def test_the_caller_is_kept_only_from_the_hash_its_session_was_bound_to(self) -> None:
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.api.users.views import _keep_calling_session  # noqa: PLC0415

        row = portal_sessions.open_session(self.user)
        request = RequestFactory().post("/")
        vars(request)["portal_session"] = row  # as the HMAC middleware sets it
        keep = _keep_calling_session(request)
        # Another credential change landed before this one took the lock: the session must end.
        self.assertFalse(keep("hash-after-someone-else", "after"))
        self.assertTrue(keep(row.credential_snapshot, "after"))
        row.refresh_from_db()
        self.assertEqual(row.credential_snapshot, "after")

    def test_end_is_recorded_once(self) -> None:
        row = portal_sessions.open_session(self.user)
        self.assertTrue(portal_sessions.end(row, portal_sessions.REASON_LOGOUT))
        self.assertFalse(portal_sessions.end(row, "again"))
        self.assertEqual(AuditEvent.objects.filter(action="logout_manual").count(), 1)

    def test_sweep_deletes_only_rows_a_day_past_their_end(self) -> None:
        live = portal_sessions.open_session(self.user)
        ended_recently = portal_sessions.open_session(self.user)
        portal_sessions.end(ended_recently, portal_sessions.REASON_LOGOUT)
        old = portal_sessions.open_session(self.user)
        PortalSession.objects.filter(pk=old.pk).update(revoked_at=timezone.now() - timedelta(days=2))
        self.assertEqual(portal_sessions.sweep_expired(), 1)
        self.assertEqual(set(PortalSession.objects.values_list("pk", flat=True)), {live.pk, ended_recently.pk})

    def test_enrolment_keeps_the_calling_session_inside_its_transaction(self) -> None:
        import pyotp  # noqa: PLC0415

        from apps.users.pending_totp import get_or_create_pending  # noqa: PLC0415

        row = portal_sessions.open_session(self.user)
        other = portal_sessions.open_session(self.user)
        secret = get_or_create_pending(self.user)

        result = complete_enrolment(
            self.user.pk,
            password=PASSWORD,
            code=pyotp.TOTP(secret).now(),
            request=None,
            keep=lambda old, new: portal_sessions.restamp(row, old_hash=old, new_hash=new),
        )
        self.assertEqual(result.status, "enabled")
        self.assertIsNotNone(portal_sessions.resolve(str(row.pk), self.user.pk, interactive=False))
        self.assertIsNone(portal_sessions.resolve(str(other.pk), self.user.pk, interactive=False))


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, PORTAL_HMAC_MODE="legacy")
class PortalSessionBindingTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.user = _customer()
        self.row = portal_sessions.open_session(self.user)

    def _post(self, path: str, body: dict[str, object]) -> int:
        return self.portal_post(path, body).status_code

    def test_a_live_session_is_admitted(self) -> None:
        self.assertEqual(self._post(PROBE, {"user_id": self.user.pk, "session_id": str(self.row.pk)}), 404)

    def test_an_ended_session_is_refused_with_the_authoritative_shape(self) -> None:
        portal_sessions.end(self.row, portal_sessions.REASON_LOGOUT)
        response = self.portal_post(PROBE, {"user_id": self.user.pk, "session_id": str(self.row.pk)})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"active": False, "error": "Session validation failed"})

    def test_a_view_that_reads_the_signed_user_itself_is_bound_too(self) -> None:
        body = {"user_id": self.user.pk, "session_id": str(self.row.pk)}
        self.assertEqual(self._post(CONSENT_HISTORY, body), 200)
        portal_sessions.end(self.row, portal_sessions.REASON_LOGOUT)
        self.assertEqual(self._post(CONSENT_HISTORY, body), 401)

    def test_a_missing_session_is_refused_only_when_required(self) -> None:
        with override_settings(PORTAL_SESSION_REQUIRED=False):
            self.assertEqual(self._post(PROBE, {"user_id": self.user.pk}), 404)
        with override_settings(PORTAL_SESSION_REQUIRED=True):
            self.assertEqual(self._post(PROBE, {"user_id": self.user.pk}), 401)
            self.assertEqual(self._post(PROBE, {}), 404)  # names no user: login, registration, reset

    def test_a_session_without_a_user_is_refused(self) -> None:
        self.assertEqual(self._post(PROBE, {"session_id": str(self.row.pk)}), 401)

    def test_a_body_the_views_could_read_differently_is_refused(self) -> None:
        for raw in (
            b'{"user_id": %d, "user_id": 2, "timestamp": %d}' % (self.user.pk, int(time.time())),
            b"[1, 2]",
            b"not json",
        ):
            with self.subTest(raw=raw):
                headers = hmac_headers("POST", PROBE, raw, portal_id=self.portal_id)
                response = self.client.post(PROBE, raw, content_type="application/json", **headers)
                self.assertEqual(response.status_code, 400)
        for malformed in (True, 7.0, "7.0", 0):
            with self.subTest(user_id=malformed):
                self.assertEqual(self._post(PROBE, {"user_id": malformed}), 401)

    def test_login_opens_a_session_and_logout_ends_it(self) -> None:
        response = self.portal_post(LOGIN, {"email": self.user.email, "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        session_id = response.json()["session_id"]
        self.assertTrue(PortalSession.objects.filter(pk=session_id, user=self.user, revoked_at=None).exists())
        bound = {"user_id": self.user.pk, "session_id": session_id}
        self.assertEqual(self._post(SESSION_END, bound), 200)
        self.assertEqual(self._post(PROBE, bound), 401)
        self.assertEqual(self._post(PROBE, {"user_id": self.user.pk, "session_id": str(self.row.pk)}), 404)

    def test_a_credential_change_landing_after_binding_still_ends_the_caller(self) -> None:
        from apps.users.mfa import MFAService  # noqa: PLC0415

        original = portal_sessions.resolve

        def bind_then_change(raw_session_id: object, user_id: int, *, interactive: bool) -> PortalSession | None:
            row = original(raw_session_id, user_id, interactive=interactive)
            # Another request rotates a second factor after this one was bound, before its lock.
            MFAService.apply_state_change(User.objects.get(pk=self.user.pk), action="rotate")
            return row

        body = json.dumps(
            {
                "user_id": self.user.pk,
                "session_id": str(self.row.pk),
                "current_password": PASSWORD,
                "new_password": "Another-Horse-Battery-7",
                "timestamp": int(time.time()),
            }
        ).encode()
        with patch("apps.users.portal_sessions.resolve", side_effect=bind_then_change):
            response = self.client.put(
                PASSWORD_CHANGE,
                body,
                content_type="application/json",
                **hmac_headers("PUT", PASSWORD_CHANGE, body, portal_id=self.portal_id),
            )
        self.assertEqual(response.status_code, 200, response.content)
        # The caller's session was bound to the hash before the rotation, so it is not kept.
        self.assertEqual(self._post(PROBE, {"user_id": self.user.pk, "session_id": str(self.row.pk)}), 401)

    def test_a_password_change_keeps_the_calling_session_and_ends_the_others(self) -> None:
        other = portal_sessions.open_session(self.user)
        response = self.client.put(
            PASSWORD_CHANGE,
            body := json.dumps(
                {
                    "user_id": self.user.pk,
                    "session_id": str(self.row.pk),
                    "current_password": PASSWORD,
                    "new_password": "Another-Horse-Battery-7",
                    "timestamp": int(time.time()),
                }
            ).encode(),
            content_type="application/json",
            **hmac_headers("PUT", PASSWORD_CHANGE, body, portal_id=self.portal_id),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self._post(PROBE, {"user_id": self.user.pk, "session_id": str(self.row.pk)}), 404)
        self.assertEqual(self._post(PROBE, {"user_id": self.user.pk, "session_id": str(other.pk)}), 401)
