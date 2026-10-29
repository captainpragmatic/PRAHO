"""An operator can end portal sessions from the server: one person's, everyone's, or an incident's.

``--active-between`` selects every session whose life overlaps the window, quiet ones included: a
session opened before it and touched only before it is still selected while it was live through it.
Each session ends once, with its own audit event, and one more event records who ran the command,
with what selector and why. A revoked session is refused at its next call to Platform.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.users import portal_sessions
from apps.users.models import PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


def _run(*args: str) -> str:
    out = StringIO()
    with patch("apps.users.management.commands.revoke_portal_sessions.operator_name", return_value="ops-ana"):
        call_command("revoke_portal_sessions", *args, "--reason", "incident 42", stdout=out)
    return out.getvalue()


def _session(email: str, **times: Any) -> PortalSession:
    user = User.objects.filter(email=email).first() or User.objects.create_user(email=email)
    row = portal_sessions.open_session(user)
    if times:
        PortalSession.objects.filter(pk=row.pk).update(**times)
        row.refresh_from_db()
    return row


def _ended(row: PortalSession) -> bool:
    return PortalSession.objects.get(pk=row.pk).revoked_at is not None


class SelectorTests(TestCase):
    def test_one_person_s_sessions(self) -> None:
        first, second, other = _session("a@example.ro"), _session("a@example.ro"), _session("b@example.ro")
        out = _run("--user", "a@example.ro")
        self.assertEqual([_ended(row) for row in (first, second, other)], [True, True, False])
        self.assertIn("Ended 2 sessions for 1 person", out)
        self.assertIn("a@example.ro", out)

    def test_a_person_by_id(self) -> None:
        row = _session("id@example.ro")
        _run("--user", str(row.user_id))
        self.assertTrue(_ended(row))

    def test_everyone_s_sessions(self) -> None:
        rows = [_session("a@example.ro"), _session("b@example.ro")]
        out = _run("--all")
        self.assertTrue(all(_ended(row) for row in rows))
        self.assertIn("Ended 2 sessions for 2 people", out)

    def test_an_incident_window_selects_every_session_live_through_it(self) -> None:
        now = timezone.now()
        t1, t2 = now - timedelta(hours=2), now - timedelta(hours=1)
        live = {"idle_deadline": now + timedelta(hours=1), "expires_at": now + timedelta(hours=8)}
        across = _session("across@example.ro", created_at=t1 - timedelta(hours=1), last_seen_at=now, **live)
        quiet = _session(
            "quiet@example.ro", created_at=t1 - timedelta(minutes=10), last_seen_at=t1 - timedelta(minutes=10), **live
        )  # opened and last touched before the window, still live through it
        later = _session("later@example.ro", created_at=t2 + timedelta(minutes=5), last_seen_at=now, **live)
        expired = _session(
            "expired@example.ro",
            created_at=t1 - timedelta(hours=3),
            last_seen_at=t1 - timedelta(hours=3),
            idle_deadline=t1 - timedelta(hours=2),
            expires_at=now + timedelta(hours=8),
        )  # its idle limit passed before the window
        _run("--active-between", t1.isoformat(), t2.isoformat())
        self.assertEqual(
            {row.user.email: _ended(row) for row in (across, quiet, later, expired)},
            {
                "across@example.ro": True,
                "quiet@example.ro": True,
                "later@example.ro": False,
                "expired@example.ro": False,
            },
        )

    def test_a_dry_run_ends_nothing(self) -> None:
        row = _session("dry@example.ro")
        out = _run("--all", "--dry-run")
        self.assertFalse(_ended(row))
        self.assertIn("Would end 1 session for 1 person", out)
        self.assertFalse(AuditEvent.objects.filter(action="portal_sessions_revoked").exists())

    def test_a_session_already_ended_is_not_counted_again(self) -> None:
        _session("twice@example.ro")
        _run("--all")
        self.assertIn("Ended 0 sessions for 0 people", _run("--all"))


class ArgumentTests(TestCase):
    def test_exactly_one_selector_and_a_sound_window(self) -> None:
        now = timezone.now()
        refused = {
            "no selector": [],
            "two selectors": ["--all", "--user", "a@example.ro"],
            "reversed window": ["--active-between", now.isoformat(), (now - timedelta(hours=1)).isoformat()],
            "a time without its zone": ["--active-between", "2026-10-29T10:00:00", "2026-10-29T11:00:00"],
            "an unknown person": ["--user", "nobody@example.ro"],
        }
        for name, args in refused.items():
            with self.subTest(case=name), self.assertRaises(CommandError):
                _run(*args)

    def test_a_reason_is_required(self) -> None:
        with self.assertRaises(CommandError):
            call_command("revoke_portal_sessions", "--all", "--reason", "  ", stdout=StringIO())


class AuditTests(TestCase):
    def test_a_run_that_fails_midway_still_names_its_operator(self) -> None:
        first, second = _session("a@example.ro"), _session("b@example.ro")
        end = portal_sessions.end
        calls: list[PortalSession] = []

        def end_then_fail(row: PortalSession, reason: str) -> bool:
            calls.append(row)
            if len(calls) == 2:
                raise RuntimeError("database gone")
            return end(row, reason)

        with patch("apps.users.portal_sessions.end", side_effect=end_then_fail), self.assertRaises(RuntimeError):
            _run("--all")
        (event,) = AuditEvent.objects.filter(action="portal_sessions_revoked")
        self.assertEqual((event.metadata["sessions"], event.metadata["completed"]), (1, False))
        self.assertEqual(sum(_ended(row) for row in (first, second)), 1)

    def test_one_event_names_the_operator_the_selector_and_the_reason(self) -> None:
        _session("a@example.ro")
        _session("b@example.ro")
        _run("--all")
        (event,) = AuditEvent.objects.filter(action="portal_sessions_revoked")
        self.assertEqual(
            {key: event.metadata[key] for key in ("operator", "selector", "reason", "sessions")},
            {"operator": "ops-ana", "selector": "all", "reason": "incident 42", "sessions": 2},
        )
        self.assertEqual(AuditEvent.objects.filter(action="session_terminated").count(), 2)  # one per session


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class EnforcementTests(HMACTestMixin, TestCase):
    def test_a_revoked_session_is_refused_at_its_next_call(self) -> None:
        row = _session("next@example.ro")
        body = {"user_id": row.user_id, "session_id": str(row.pk)}
        self.assertEqual(self.portal_post("/api/users/mfa/status/", body).status_code, 200)
        _run("--user", "next@example.ro")
        refused = self.portal_post("/api/users/mfa/status/", body)
        self.assertEqual(refused.status_code, 401)
        self.assertFalse(refused.json()["active"])
