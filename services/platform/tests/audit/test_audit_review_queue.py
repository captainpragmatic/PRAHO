"""Tests for the flagged-event review queue (#400).

Covers the two things the issue asked for — a queue over ``requires_review`` and a
mark-reviewed action that records who and when — plus the property that motivated the
companion-model design: reviewing must NOT mutate the append-only AuditEvent.
"""

from __future__ import annotations

import re
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent, AuditEventReview, audit_mutation_allowed

User = get_user_model()


class AuditReviewQueueTestCase(TestCase):
    def setUp(self) -> None:
        self.staff_user = User.objects.create_user(
            email="review-staff@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        self.other_staff = User.objects.create_user(
            email="review-staff2@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        self.regular_user = User.objects.create_user(email="review-user@example.com", password="testpass123")

        ct = ContentType.objects.get_for_model(User)
        self.flagged = AuditEvent.objects.create(
            user=self.regular_user,
            action="security_incident_detected",
            category="security_event",
            severity="critical",
            requires_review=True,
            content_type=ct,
            object_id=str(self.regular_user.id),
            description="FLAGGED-EVENT-NEEDS-REVIEW",
            ip_address="10.0.0.1",
        )
        self.unflagged = AuditEvent.objects.create(
            user=self.regular_user,
            action="login_success",
            category="authentication",
            severity="low",
            requires_review=False,
            content_type=ct,
            object_id=str(self.regular_user.id),
            description="ROUTINE-EVENT-NOT-FLAGGED",
            ip_address="10.0.0.2",
        )
        self.client = Client()
        self.client.login(email="review-staff@example.com", password="testpass123")

    # ---------------------------------------------------------------- access

    def test_queue_requires_staff(self) -> None:
        self.client.logout()
        self.assertEqual(self.client.get(reverse("audit:review_queue")).status_code, 302)

        self.client.login(email="review-user@example.com", password="testpass123")
        self.assertEqual(self.client.get(reverse("audit:review_queue")).status_code, 403)

        self.client.login(email="review-staff@example.com", password="testpass123")
        self.assertEqual(self.client.get(reverse("audit:review_queue")).status_code, 200)

    def test_mark_reviewed_requires_staff(self) -> None:
        url = reverse("audit:mark_event_reviewed", args=[self.flagged.id])
        self.client.login(email="review-user@example.com", password="testpass123")

        self.assertEqual(self.client.post(url, {}).status_code, 403)
        self.assertFalse(AuditEventReview.objects.exists())

    def test_mark_reviewed_rejects_get(self) -> None:
        """The action is a mutation; it must not be reachable by GET."""
        response = self.client.get(reverse("audit:mark_event_reviewed", args=[self.flagged.id]))
        self.assertEqual(response.status_code, 405)

    # ----------------------------------------------------------------- queue

    def test_queue_lists_only_flagged_events(self) -> None:
        response = self.client.get(reverse("audit:review_queue"))

        self.assertContains(response, "FLAGGED-EVENT-NEEDS-REVIEW")
        self.assertNotContains(response, "ROUTINE-EVENT-NOT-FLAGGED")

    def test_queue_defaults_to_unreviewed_and_reflects_review(self) -> None:
        """The default view is the actual work list: flagged AND not yet reviewed."""
        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {})

        default_view = self.client.get(reverse("audit:review_queue"))
        self.assertNotContains(default_view, "FLAGGED-EVENT-NEEDS-REVIEW")

        reviewed_view = self.client.get(reverse("audit:review_queue"), {"status": "reviewed"})
        self.assertContains(reviewed_view, "FLAGGED-EVENT-NEEDS-REVIEW")

        all_view = self.client.get(reverse("audit:review_queue"), {"status": "all"})
        self.assertContains(all_view, "FLAGGED-EVENT-NEEDS-REVIEW")

    def test_queue_stats_split_reviewed_and_unreviewed(self) -> None:
        before = self.client.get(reverse("audit:review_queue")).context["review_stats"]
        self.assertEqual(before["total_flagged"], 1)
        self.assertEqual(before["unreviewed"], 1)
        self.assertEqual(before["reviewed"], 0)
        self.assertEqual(before["my_reviews"], 0)

        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {})

        after = self.client.get(reverse("audit:review_queue")).context["review_stats"]
        self.assertEqual(after["unreviewed"], 0)
        self.assertEqual(after["reviewed"], 1)
        self.assertEqual(after["my_reviews"], 1)

    def test_queue_severity_filter(self) -> None:
        matching = self.client.get(reverse("audit:review_queue"), {"severity": "critical"})
        self.assertContains(matching, "FLAGGED-EVENT-NEEDS-REVIEW")

        non_matching = self.client.get(reverse("audit:review_queue"), {"severity": "low"})
        self.assertNotContains(non_matching, "FLAGGED-EVENT-NEEDS-REVIEW")

    # --------------------------------------------------------- mark reviewed

    def test_mark_reviewed_records_reviewer_and_timestamp(self) -> None:
        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {"notes": "Checked, benign."})

        review = AuditEventReview.objects.get(audit_event=self.flagged)
        self.assertEqual(review.reviewed_by, self.staff_user)
        self.assertEqual(review.notes, "Checked, benign.")
        self.assertIsNotNone(review.reviewed_at)

    def test_mark_reviewed_does_not_mutate_the_audit_event(self) -> None:
        """The whole point of the companion model: evidence stays append-only.

        If review state ever moves onto AuditEvent, this fails with
        AuditImmutabilityError — which is the signal to reconsider, not to widen the
        escape hatch.
        """
        before = AuditEvent.objects.get(pk=self.flagged.pk)
        before_stamp = (before.action, before.description, before.requires_review, before.timestamp)

        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {})

        # The review must actually have happened — without this, a view gutted
        # to a no-op passes trivially (an untouched event is always unmutated).
        self.assertTrue(AuditEventReview.objects.filter(audit_event=self.flagged).exists())
        after = AuditEvent.objects.get(pk=self.flagged.pk)
        self.assertEqual((after.action, after.description, after.requires_review, after.timestamp), before_stamp)

    def test_double_submit_keeps_the_first_review(self) -> None:
        """A double click (or two reviewers racing) must not 500 on the OneToOne."""
        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {"notes": "first"})

        self.client.login(email="review-staff2@example.com", password="testpass123")
        response = self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {"notes": "second"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AuditEventReview.objects.filter(audit_event=self.flagged).count(), 1)
        review = AuditEventReview.objects.get(audit_event=self.flagged)
        self.assertEqual(review.reviewed_by, self.staff_user)
        self.assertEqual(review.notes, "first")

    def test_cannot_review_an_unflagged_event(self) -> None:
        self.client.post(reverse("audit:mark_event_reviewed", args=[self.unflagged.id]), {})

        self.assertFalse(AuditEventReview.objects.filter(audit_event=self.unflagged).exists())

    def test_review_action_is_itself_audited(self) -> None:
        before = AuditEvent.objects.count()

        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged.id]), {})

        self.assertEqual(AuditEvent.objects.count(), before + 1)
        logged = AuditEvent.objects.order_by("-timestamp").first()
        assert logged is not None
        self.assertEqual(logged.metadata.get("reviewed_audit_event_id"), str(self.flagged.id))


class AuditEventReviewDeletionPathsTests(TestCase):
    """A review must never veto the deletion of what it annotates.

    ``audit_event`` was originally PROTECT, which inverts the dependency: the
    annotation blocks removal of the event, so retention deletion and GDPR erasure
    raise ProtectedError as soon as one reviewed event falls in scope — making a
    GDPR erasure request unfulfillable. These pin the deletion direction.
    """

    def setUp(self) -> None:
        self.staff_user = User.objects.create_user(
            email="deletion-staff@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        self.subject = User.objects.create_user(email="deletion-subject@example.com", password="testpass123")

        ct = ContentType.objects.get_for_model(User)
        self.event = AuditEvent.objects.create(
            user=self.subject,
            action="security_incident_detected",
            category="security_event",
            severity="critical",
            requires_review=True,
            content_type=ct,
            object_id=str(self.subject.id),
            description="REVIEWED-EVENT-IN-DELETION-SCOPE",
            ip_address="10.0.0.9",
        )
        self.review = AuditEventReview.objects.create(
            audit_event=self.event, reviewed_by=self.staff_user, notes="signed off"
        )

    def test_retention_delete_removes_a_reviewed_event(self) -> None:
        """The retention path deletes AuditEvent rows directly by id."""
        with audit_mutation_allowed("retention_delete"):
            AuditEvent.objects.filter(id=self.event.id).delete()

        self.assertFalse(AuditEvent.objects.filter(id=self.event.id).exists())
        self.assertFalse(AuditEventReview.objects.filter(id=self.review.id).exists())

    def test_gdpr_erasure_removes_a_reviewed_users_events(self) -> None:
        """GDPRDataService._delete_user_data filters by user, then deletes the account."""
        with audit_mutation_allowed("gdpr_erasure"):
            AuditEvent.objects.filter(user=self.subject).delete()
        self.subject.delete()

        self.assertFalse(AuditEvent.objects.filter(id=self.event.id).exists())
        self.assertFalse(AuditEventReview.objects.filter(id=self.review.id).exists())

    def test_deleting_the_reviewer_keeps_the_review(self) -> None:
        """reviewed_by is SET_NULL: a staff departure neither blocks nor erases sign-off."""
        self.staff_user.delete()

        self.review.refresh_from_db()
        self.assertIsNone(self.review.reviewed_by)
        self.assertEqual(self.review.notes, "signed off")


class AuditManagementDashboardStatsRenderingTests(TestCase):
    """#400: the dashboard stat cards rendered hardcoded zeros.

    The view builds counts under ``context["audit_stats"]`` but the template read flat
    names (``{{ total_events }}``) that were never set, so every card fell through to
    ``|default:0``. The existing dashboard test asserts on the context dict only, which
    is exactly why this survived — these assert on the RENDERED output.
    """

    def setUp(self) -> None:
        self.staff_user = User.objects.create_user(
            email="dash-staff@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        ct = ContentType.objects.get_for_model(User)

        def _event(**overrides: object) -> AuditEvent:
            defaults: dict[str, object] = {
                "user": self.staff_user,
                "action": "security_incident_detected",
                "category": "security_event",
                "severity": "critical",
                "requires_review": True,
                "content_type": ct,
                "object_id": str(self.staff_user.id),
                "ip_address": "10.0.0.3",
            }
            defaults.update(overrides)
            return AuditEvent.objects.create(**defaults)

        # Distinct per-card counts (#467): identical seeds let a template that
        # binds the wrong stat to a card — or swaps two cards — pass unnoticed.
        self.flagged_events = [_event(description=f"dash event {i}") for i in range(3)]
        # Splits total_events from critical_events and review_required.
        _event(description="benign low event", severity="low", requires_review=False)
        # Outside the 7-day window: splits total_events from today_events and
        # exercises the card's window semantics.
        _event(
            description="stale flagged event",
            severity="high",
            timestamp=timezone.now() - timedelta(days=8),
        )
        # Flagged but already reviewed: the Awaiting Review card must exclude
        # it (it also splits critical_events from review_required).
        reviewed_event = _event(description="already reviewed event")
        AuditEventReview.objects.create(audit_event=reviewed_event, reviewed_by=self.staff_user)

        self.client = Client()
        self.client.login(email="dash-staff@example.com", password="testpass123")

    @staticmethod
    def _expected_stats() -> dict[str, int]:
        """The card semantics the dashboard promises, computed independently."""
        # One clock read, like the view: two now() calls straddling midnight
        # would anchor the windows to different days and flake.
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        return {
            "Total Events": AuditEvent.objects.count(),
            "Events Today": AuditEvent.objects.filter(timestamp__gte=today_start).count(),
            "Critical Events (7d)": AuditEvent.objects.filter(severity="critical", timestamp__gte=week_start).count(),
            "Awaiting Review (7d)": AuditEvent.objects.filter(
                requires_review=True, timestamp__gte=week_start, review__isnull=True
            ).count(),
        }

    def _card_count(self, content: str, label: str) -> int:
        """Return the count rendered inside the card whose label is ``label``.

        Label-anchored on purpose: a bare number-in-markup assertion proves the
        number appears SOMEWHERE on the page, so equal counts or swapped card
        bindings both slip through.
        """
        match = re.search(
            re.escape(label) + r'</p>\s*<p class="[^"]*\btext-2xl\b[^"]*">(\d+)</p>',
            content,
        )
        self.assertIsNotNone(match, f"card {label!r} not found in rendered dashboard")
        assert match is not None
        return int(match.group(1))

    def test_stat_cards_render_real_counts_not_zero(self) -> None:
        response = self.client.get(reverse("audit:management_dashboard"))
        content = response.content.decode()

        expected = self._expected_stats()
        # The seeds guarantee pairwise-distinct counts — the precondition for
        # the label-anchored assertions below to discriminate at all.
        self.assertEqual(len(set(expected.values())), 4, expected)
        for label, count in expected.items():
            self.assertEqual(self._card_count(content, label), count, f"card {label!r}")

    def test_completing_a_review_decreases_the_awaiting_review_card(self) -> None:
        """#467: the card is a workload indicator — reviews must move it."""
        before = self.client.get(reverse("audit:management_dashboard"))
        before_count = self._card_count(before.content.decode(), "Awaiting Review (7d)")

        self.client.post(reverse("audit:mark_event_reviewed", args=[self.flagged_events[0].id]), {})

        after = self.client.get(reverse("audit:management_dashboard"))
        self.assertEqual(after.context["audit_stats"]["review_required"], before_count - 1)
        self.assertEqual(self._card_count(after.content.decode(), "Awaiting Review (7d)"), before_count - 1)

    def test_dashboard_links_to_review_queue(self) -> None:
        response = self.client.get(reverse("audit:management_dashboard"))

        self.assertContains(response, reverse("audit:review_queue"))
