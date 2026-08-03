"""Tests for the flagged-event review queue (#400).

Covers the two things the issue asked for — a queue over ``requires_review`` and a
mark-reviewed action that records who and when — plus the property that motivated the
companion-model design: reviewing must NOT mutate the append-only AuditEvent.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent, AuditEventReview

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
        for i in range(3):
            AuditEvent.objects.create(
                user=self.staff_user,
                action="security_incident_detected",
                category="security_event",
                severity="critical",
                requires_review=True,
                content_type=ct,
                object_id=str(self.staff_user.id),
                description=f"dash event {i}",
                ip_address="10.0.0.3",
            )
        self.client = Client()
        self.client.login(email="dash-staff@example.com", password="testpass123")

    def test_stat_cards_render_real_counts_not_zero(self) -> None:
        response = self.client.get(reverse("audit:management_dashboard"))
        content = response.content.decode()

        stats = response.context["audit_stats"]
        self.assertGreater(stats["total_events"], 0)

        # The rendered page must show the computed totals.
        self.assertIn(f'<p class="text-2xl font-semibold text-white">{stats["total_events"]}</p>', content)
        self.assertIn(f'<p class="text-2xl font-semibold text-white">{stats["review_required"]}</p>', content)

    def test_dashboard_links_to_review_queue(self) -> None:
        response = self.client.get(reverse("audit:management_dashboard"))

        self.assertContains(response, reverse("audit:review_queue"))
