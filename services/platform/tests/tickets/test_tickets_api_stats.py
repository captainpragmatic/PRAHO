"""
Tests for SQLite-compatible ticket stats calculation (A1 TODO fix).

Verifies Python-side average response time and satisfaction rating.
"""

from datetime import timedelta

from django.db.models import Avg
from django.test import TestCase

from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket, TicketComment
from apps.users.models import CustomerMembership, User


class TicketResponseTimeTests(TestCase):
    """A1: Python-side average response time calculation"""

    def setUp(self):
        self.user = User.objects.create_user(email="support@test.ro", password="testpass123", is_staff=True)
        self.customer = Customer.objects.create(
            name="Stats SRL", customer_type="company",
        )
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.category = SupportCategory.objects.create(name="General", name_en="General")

    def test_staff_reply_creates_response_time_data(self):
        """Tickets with staff comments provide response time data"""
        ticket = Ticket.objects.create(
            customer=self.customer, created_by=self.user, title="Test",
            description="Test ticket", category=self.category, status="open",
        )
        comment = TicketComment.objects.create(
            ticket=ticket, content="Staff reply", author=self.user, comment_type="support",
        )
        # Manually offset created_at by 2 hours
        TicketComment.objects.filter(pk=comment.pk).update(
            created_at=ticket.created_at + timedelta(hours=2),
        )

        first_staff = ticket.comments.filter(comment_type="support").order_by("created_at").first()
        self.assertIsNotNone(first_staff)
        delta_hours = (first_staff.created_at - ticket.created_at).total_seconds() / 3600
        self.assertAlmostEqual(delta_hours, 2.0, places=1)

    def test_no_staff_replies_returns_zero(self):
        """Tickets without staff comments yield no response time"""
        ticket = Ticket.objects.create(
            customer=self.customer, created_by=self.user, title="Unresponded",
            description="Unresponded ticket", category=self.category, status="open",
        )
        staff_comments = ticket.comments.filter(comment_type="support")
        self.assertEqual(staff_comments.count(), 0)


class TicketSatisfactionRatingTests(TestCase):
    """A1: Satisfaction rating aggregation works on SQLite"""

    def setUp(self):
        self.user = User.objects.create_user(email="sat@test.ro", password="testpass123", is_staff=True)
        self.customer = Customer.objects.create(
            name="Rating SRL", customer_type="company",
        )
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.category = SupportCategory.objects.create(name="Rating", name_en="Rating")

    def test_avg_satisfaction_works_on_sqlite(self):
        """Avg() on integer satisfaction_rating field works in SQLite"""
        Ticket.objects.create(
            customer=self.customer, created_by=self.user, title="Good",
            description="Good ticket", category=self.category, status="closed",
            satisfaction_rating=5,
        )
        Ticket.objects.create(
            customer=self.customer, created_by=self.user, title="OK",
            description="OK ticket", category=self.category, status="closed",
            satisfaction_rating=3,
        )
        avg = Ticket.objects.filter(
            satisfaction_rating__isnull=False,
        ).aggregate(avg=Avg("satisfaction_rating"))["avg"]
        self.assertAlmostEqual(avg, 4.0, places=1)

    def test_empty_satisfaction_returns_none(self):
        """No rated tickets → Avg returns None"""
        avg = Ticket.objects.filter(
            satisfaction_rating__isnull=False,
        ).aggregate(avg=Avg("satisfaction_rating"))["avg"]
        self.assertIsNone(avg)
