"""One owner of a portal session's lifetimes: ``apps.users.session_policy`` (ADR-0017 section 5).

The values are NIST SP 800-63B-4's: a standard session is AAL2 (24 hours, 1 hour idle), a
"remember me" session is AAL1 (30 days, with a 7-day idle limit), acceptable because every sensitive
action needs a password check from the last 300 seconds. Staff always get the standard tier. A
session is live while a deadline is in the future; at the deadline it is over.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase

from apps.users import portal_sessions, session_policy
from apps.users.models import PortalSession, User

PASSWORD = "Correct-Horse-Battery-9"  # test credential


class PolicyTests(TestCase):
    def test_the_tiers_are_exactly_these(self) -> None:
        self.assertEqual(
            {tier: (life.absolute, life.idle) for tier, life in session_policy.TIERS.items()},
            {
                "standard": (timedelta(hours=24), timedelta(hours=1)),
                "remember": (timedelta(days=30), timedelta(days=7)),
                "customer_view": (timedelta(minutes=30), timedelta(minutes=10)),
            },
        )

    def test_each_tier_is_within_its_nist_assurance_level(self) -> None:
        for tier in ("standard", "customer_view"):  # AAL2: at most 24 hours, and 1 hour idle
            with self.subTest(tier=tier):
                self.assertLessEqual(session_policy.TIERS[tier].absolute, timedelta(hours=24))
                self.assertLessEqual(session_policy.TIERS[tier].idle, timedelta(hours=1))
        self.assertLessEqual(session_policy.TIERS["remember"].absolute, timedelta(days=30))  # AAL1
        for life in session_policy.TIERS.values():
            self.assertLessEqual(life.idle, life.absolute)

    def test_every_stored_tier_has_lifetimes(self) -> None:
        self.assertEqual({key for key, _label in PortalSession.TIER_CHOICES}, set(session_policy.TIERS))

    def test_only_a_customer_who_asked_is_remembered(self) -> None:
        customer = User(email="customer@example.ro")
        self.assertEqual(session_policy.tier_for(customer, remember_me=True), "remember")
        self.assertEqual(session_policy.tier_for(customer, remember_me=False), "standard")
        staff = {
            "the staff flag": User(email="a@example.ro", is_staff=True),
            "a staff role": User(email="b@example.ro", staff_role="support"),
            "a superuser": User(email="c@example.ro", is_superuser=True),
        }
        for name, user in staff.items():
            with self.subTest(staff=name):
                self.assertEqual(session_policy.tier_for(user, remember_me=True), "standard")


class TierLifetimeTests(TestCase):
    def setUp(self) -> None:
        self.customer = User.objects.create_user(email="customer@example.ro", password=PASSWORD)

    def test_a_session_opens_with_its_tier_s_deadlines(self) -> None:
        staff = User.objects.create_user(email="staff@example.ro", password=PASSWORD, staff_role="support")
        cases = {
            "customer, remembered": (self.customer, True, "remember", timedelta(days=30), timedelta(days=7)),
            "customer": (self.customer, False, "standard", timedelta(hours=24), timedelta(hours=1)),
            "staff who asked": (staff, True, "standard", timedelta(hours=24), timedelta(hours=1)),
        }
        for name, (user, remember, tier, absolute, idle) in cases.items():
            with self.subTest(case=name):
                row = portal_sessions.open_session(user, remember_me=remember)
                self.assertEqual(row.tier, tier)
                self.assertEqual(row.expires_at - row.last_seen_at, absolute)
                self.assertEqual(row.idle_deadline - row.last_seen_at, idle)

    def test_activity_extends_idle_by_the_tier_s_idle_and_never_past_the_end(self) -> None:
        row = portal_sessions.open_session(self.customer, remember_me=True)
        later = row.last_seen_at + timedelta(days=2)
        with patch("apps.users.portal_sessions.timezone.now", return_value=later):
            resolved = portal_sessions.resolve(str(row.pk), self.customer.pk, interactive=True)
        self.assertIsNotNone(resolved)
        self.assertEqual(PortalSession.objects.get(pk=row.pk).idle_deadline, later + timedelta(days=7))
        near_end = row.expires_at - timedelta(days=1)
        PortalSession.objects.filter(pk=row.pk).update(idle_deadline=near_end + timedelta(hours=1))
        with patch("apps.users.portal_sessions.timezone.now", return_value=near_end):
            portal_sessions.resolve(str(row.pk), self.customer.pk, interactive=True)
        self.assertEqual(PortalSession.objects.get(pk=row.pk).idle_deadline, row.expires_at)

    def test_each_deadline_ends_the_session_at_the_instant_it_passes(self) -> None:
        for deadline in ("expires_at", "idle_deadline"):
            for offset, live in ((timedelta(seconds=-1), True), (timedelta(0), False), (timedelta(seconds=1), False)):
                with self.subTest(deadline=deadline, offset=offset):
                    row = portal_sessions.open_session(self.customer)
                    at = getattr(row, deadline) + offset
                    other = "idle_deadline" if deadline == "expires_at" else "expires_at"
                    # The other deadline stays well ahead, so only this one decides.
                    PortalSession.objects.filter(pk=row.pk).update(**{other: at + timedelta(hours=1)})
                    with patch("apps.users.portal_sessions.timezone.now", return_value=at):
                        resolved = portal_sessions.resolve(str(row.pk), self.customer.pk, interactive=False)
                    self.assertEqual(resolved is not None, live)

    def test_a_remembered_session_ends_once_its_person_becomes_staff(self) -> None:
        row = portal_sessions.open_session(self.customer, remember_me=True)
        User.objects.filter(pk=self.customer.pk).update(staff_role="support")
        self.assertIsNone(portal_sessions.resolve(str(row.pk), self.customer.pk, interactive=False))
        row.refresh_from_db()
        self.assertIsNotNone(row.revoked_at)

    def test_a_tier_the_policy_does_not_know_ends_the_session_and_never_raises(self) -> None:
        row = portal_sessions.open_session(self.customer)
        PortalSession.objects.filter(pk=row.pk).update(tier="unknown")
        self.assertIsNone(portal_sessions.resolve(str(row.pk), self.customer.pk, interactive=True))
        row.refresh_from_db()
        self.assertIsNotNone(row.revoked_at)

    def test_a_staff_member_s_view_as_a_customer_keeps_its_short_lifetimes(self) -> None:
        self.assertEqual(session_policy.TIERS["customer_view"].absolute, timedelta(minutes=30))
        self.assertEqual(session_policy.lifetimes(PortalSession.TIER_CUSTOMER_VIEW).idle, timedelta(minutes=10))
        self.assertIsNone(session_policy.lifetimes("unknown"))
