"""The portal keeps the deadlines Platform gives a session, only when they can be Platform's."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from django.test import SimpleTestCase

from apps.users import session_deadlines
from apps.users.session_deadlines import CLOCK_ALLOWANCE, LONGEST_SESSION

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def _answer(tier: object = "remember", expires: object = None, idle: object = None) -> dict[str, object]:
    return {
        "session_tier": tier,
        "session_expires_at": (NOW + timedelta(days=30)).isoformat() if expires is None else expires,
        "session_idle_deadline": (NOW + timedelta(days=7)).isoformat() if idle is None else idle,
    }


class FromPlatformTests(SimpleTestCase):
    def test_platform_s_deadlines_are_kept_as_given(self) -> None:
        deadlines = session_deadlines.from_platform(_answer(), NOW)
        self.assertEqual(deadlines, session_deadlines.SessionDeadlines(
            "remember", NOW + timedelta(days=30), NOW + timedelta(days=7)
        ))

    def test_a_clock_difference_platform_accepts_is_allowed(self) -> None:
        ahead = NOW + LONGEST_SESSION + CLOCK_ALLOWANCE  # Platform's clock as far ahead as it accepts
        self.assertIsNotNone(session_deadlines.from_platform(_answer(expires=ahead.isoformat()), NOW))
        behind = (NOW + timedelta(days=30) - timedelta(seconds=2)).isoformat()
        self.assertIsNotNone(session_deadlines.from_platform(_answer(expires=behind), NOW))

    def test_anything_that_cannot_be_platform_s_is_refused(self) -> None:
        cases = {
            "an unknown tier": _answer(tier="forever"),
            "no tier": _answer(tier=None),
            "a list for a tier": _answer(tier=["standard"]),
            "a dict for a tier": _answer(tier={"standard": True}),
            "a naive time": _answer(expires=(NOW + timedelta(days=1)).replace(tzinfo=None).isoformat()),
            "not a time": _answer(idle="tomorrow"),
            "a number": _answer(expires=1700000000),
            "an end in the past": _answer(expires=(NOW - timedelta(seconds=1)).isoformat(), idle=NOW.isoformat()),
            "an idle deadline already passed": _answer(idle=NOW.isoformat()),
            "idle after the end": _answer(
                expires=(NOW + timedelta(hours=1)).isoformat(), idle=(NOW + timedelta(hours=2)).isoformat()
            ),
            "an end too far away": _answer(
                expires=(NOW + LONGEST_SESSION + CLOCK_ALLOWANCE + timedelta(seconds=1)).isoformat()
            ),
        }
        for name, answer in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(session_deadlines.from_platform(answer, NOW))

    def test_stored_deadlines_read_back_as_stored(self) -> None:
        session: dict[str, object] = {}
        deadlines = session_deadlines.SessionDeadlines("standard", NOW + timedelta(hours=24), NOW + timedelta(hours=1))
        session_deadlines.store(session, deadlines)
        self.assertEqual(session_deadlines.stored(session), deadlines)
        self.assertIsNone(session_deadlines.stored({}))
        self.assertIsNone(session_deadlines.stored({**session, "session_tier": ["standard"]}))
