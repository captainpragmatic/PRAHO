"""A sensitive action needs a password (and second factor) check within the last 300 seconds.

A stolen portal session could otherwise reveal a gift-card code, or change who controls a company,
for as long as the session lives. Login counts as a check; after 300 seconds Platform answers
``reauth_required`` until the person confirms their identity again. A request with no bound session
never reaches a guarded action, whatever ``PORTAL_SESSION_REQUIRED`` says.

The window belongs to the browser that opened it: a request must echo the exact window it was given
(``step_up_at``), checked against the row as it is now. A request that loaded the session before the
person confirmed echoes the earlier window, so someone holding a copy of the cookie cannot act in it.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.api.step_up import step_up_refusal
from apps.users import portal_sessions
from apps.users.models import PortalSession, User
from apps.users.portal_sessions import STEP_UP_WINDOW, mark_reauth, recently_reauthenticated


def _session(email: str = "step-up@example.ro") -> PortalSession:
    return portal_sessions.open_session(User.objects.create_user(email=email))


class WindowTests(TestCase):
    def test_the_window_is_three_hundred_seconds_inclusive(self) -> None:
        row = _session()
        now = timezone.now()
        cases = {
            "299 s ago": (now - timedelta(seconds=299), True),
            "300 s ago": (now - STEP_UP_WINDOW, True),
            "301 s ago": (now - timedelta(seconds=301), False),
            "never": (None, False),
            "in the future": (now + timedelta(seconds=1), False),
        }
        for name, (reauth_at, fresh) in cases.items():
            with self.subTest(case=name):
                row.reauth_at = reauth_at
                self.assertIs(recently_reauthenticated(row, now), fresh)
        self.assertEqual(STEP_UP_WINDOW, timedelta(seconds=300))

    def test_marking_moves_a_live_session_forward(self) -> None:
        row = _session()
        PortalSession.objects.filter(pk=row.pk).update(reauth_at=timezone.now() - timedelta(hours=1))
        self.assertTrue(mark_reauth(row))
        stored = PortalSession.objects.get(pk=row.pk).reauth_at
        self.assertTrue(recently_reauthenticated(PortalSession.objects.get(pk=row.pk), timezone.now()))
        self.assertEqual(row.reauth_at, stored)

    def test_an_ended_session_is_never_marked(self) -> None:
        row = _session()
        before = timezone.now() - timedelta(hours=1)
        PortalSession.objects.filter(pk=row.pk).update(reauth_at=before)
        portal_sessions.end(row, portal_sessions.REASON_LOGOUT)
        self.assertFalse(mark_reauth(row))
        self.assertEqual(PortalSession.objects.get(pk=row.pk).reauth_at, before)


@override_settings(PORTAL_SESSION_REQUIRED=False)
class RefusalTests(TestCase):
    def _request(self, row: PortalSession | None, echo: object = "same") -> object:
        request = RequestFactory().post("/api/billing/gift-cards/reveal/")
        if row is not None:
            request.portal_session = row  # type: ignore[attr-defined]  # as bind_request sets it
            # What the portal sends back: by default the window this browser was given.
            request.portal_step_up_at = (  # type: ignore[attr-defined]  # as bind_request sets it
                portal_sessions.step_up_stamp(row) if echo == "same" else echo
            )
        return request

    def test_an_unbound_request_is_refused_as_an_ended_session(self) -> None:
        for required in (False, True):
            with self.subTest(required=required), override_settings(PORTAL_SESSION_REQUIRED=required):
                response = step_up_refusal(self._request(None))
                self.assertEqual(response.status_code, 401)
                self.assertIn(b'"active": false', response.content)

    def test_a_stale_session_is_asked_to_confirm_and_a_fresh_one_passes(self) -> None:
        row = _session()
        self.assertIsNone(step_up_refusal(self._request(row)))  # login counts as a check
        PortalSession.objects.filter(pk=row.pk).update(reauth_at=timezone.now() - timedelta(seconds=301))
        row.refresh_from_db()
        response = step_up_refusal(self._request(row))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data, {"success": False, "code": "reauth_required"})
        self.assertNotIn("active", response.data)  # never read by the portal as an ended session
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_only_the_window_s_own_stamp_opens_it(self) -> None:
        row = _session()
        other = (row.reauth_at - timedelta(seconds=1)).isoformat()
        for echo in (None, "", "not a time", 42, other):
            with self.subTest(echo=echo):
                response = step_up_refusal(self._request(row, echo))
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.data, {"success": False, "code": "reauth_required"})
        self.assertIsNone(step_up_refusal(self._request(row)))

    def test_a_new_confirmation_closes_the_window_to_every_earlier_stamp(self) -> None:
        row = _session()
        earlier = portal_sessions.step_up_stamp(row)
        bound_before = PortalSession.objects.get(pk=row.pk)  # a request that loaded the session first
        PortalSession.objects.filter(pk=row.pk).update(reauth_at=row.reauth_at - timedelta(seconds=5))
        confirmed = PortalSession.objects.get(pk=row.pk)
        self.assertIsNotNone(mark_reauth(confirmed))  # the person confirms
        self.assertEqual(step_up_refusal(self._request(bound_before, earlier)).status_code, 403)
        self.assertIsNone(step_up_refusal(self._request(confirmed)))
