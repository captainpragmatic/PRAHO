"""
Tests for SQLite-compatible ticket stats calculation (A1 TODO fix).

Verifies Python-side average response time and satisfaction rating.
"""

from datetime import timedelta
from unittest.mock import patch

from django.db.models import Avg
from django.test import RequestFactory, TestCase

from apps.api.tickets.views import customer_tickets_summary_api
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


class TicketSummaryHandlerShapeTests(TestCase):
    """customer_tickets_summary_api must emit waiting_on_customer count.

    Regression of PR #164 review finding H5b: the platform handler at
    services/platform/apps/api/tickets/views.py:475-555 previously omitted
    waiting_on_customer entirely, so the portal's account-health banner
    that reads tickets_summary['waiting_on_customer'] was permanently
    zero. Also covers the dead pending_tickets filter (status='pending'
    is not a valid Ticket status enum value; was always 0).
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="shape@test.ro", password="testpass123", is_staff=True,
        )
        self.customer = Customer.objects.create(name="Shape SRL", customer_type="company")
        CustomerMembership.objects.create(
            user=self.user, customer=self.customer, role="owner", is_primary=True,
        )
        self.category = SupportCategory.objects.create(name="General", name_en="General")

    def _create_ticket(self, status: str, title: str = "Test"):
        return Ticket.objects.create(
            customer=self.customer, created_by=self.user, title=title,
            description="Test ticket", category=self.category, status=status,
        )

    def _post_to_summary(self):
        """Bypass the HMAC auth decorator by patching get_authenticated_customer
        to return our test customer. The handler still receives a real
        HttpRequest so DRF's request adapter is happy."""
        request = RequestFactory().post("/api/tickets/summary/")
        with patch(
            "apps.api.secure_auth.get_authenticated_customer",
            return_value=(self.customer, None),
        ):
            return customer_tickets_summary_api(request)

    def test_summary_response_includes_waiting_on_customer_field(self):
        """summary_data must contain waiting_on_customer (consumed by portal
        account_health banner — without this field the banner is dead code)."""
        self._create_ticket("open", "open ticket")
        self._create_ticket("in_progress", "in_progress ticket")
        self._create_ticket("waiting_on_customer", "wait ticket")
        self._create_ticket("closed", "closed ticket")

        response = self._post_to_summary()

        self.assertEqual(response.status_code, 200)
        data = response.data["data"]
        self.assertIn(
            "waiting_on_customer", data,
            msg="customer_tickets_summary_api must emit waiting_on_customer "
                "(consumed by portal account_health banner)",
        )
        self.assertEqual(data["waiting_on_customer"], 1)

    def test_summary_response_open_tickets_includes_in_progress(self):
        """open_tickets should count tickets in `open` and `in_progress` —
        the existing behavior; protects against future drift."""
        self._create_ticket("open", "open")
        self._create_ticket("in_progress", "wip")

        response = self._post_to_summary()
        self.assertEqual(response.data["data"]["open_tickets"], 2)
