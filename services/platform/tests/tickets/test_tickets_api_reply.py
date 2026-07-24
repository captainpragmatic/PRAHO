"""Regression tests for the customer ticket reply API lifecycle boundary."""

import json
from unittest.mock import patch

from django.test import RequestFactory, TestCase
from rest_framework.response import Response

from apps.api.tickets.views import customer_ticket_reply_api
from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket
from apps.tickets.services import TicketStatusService
from apps.users.models import CustomerMembership, User


class CustomerTicketReplyAPITests(TestCase):
    """The signed API must serialize customer replies with lifecycle workers."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="customer@example.com", password="testpass123")
        self.customer = Customer.objects.create(
            name="API Customer SRL",
            customer_type="company",
            status="active",
            primary_email=self.user.email,
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True,
            is_active=True,
        )
        self.category = SupportCategory.objects.create(name="General", name_en="General")
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            created_by=self.user,
            title="Reply race",
            description="Waiting for a customer response",
            category=self.category,
            status="waiting_on_customer",
        )

    def _post_reply(self, content: str = "Customer API reply") -> Response:
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/reply/",
            data=json.dumps({"content": content}),
            content_type="application/json",
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return customer_ticket_reply_api(request, ticket_id=self.ticket.pk)

    def test_reply_transitions_ticket_and_persists_comment_atomically(self) -> None:
        response = self._post_reply()

        self.assertEqual(response.status_code, 201)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, "open")
        self.assertTrue(self.ticket.has_customer_replied)
        self.assertEqual(self.ticket.comments.filter(content="Customer API reply").count(), 1)

    def test_transition_failure_rolls_back_comment(self) -> None:
        original_comment_count = self.ticket.comments.count()

        with patch.object(TicketStatusService, "handle_customer_reply", side_effect=ValueError("invalid transition")):
            response = self._post_reply()

        self.assertEqual(response.status_code, 500)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.comments.count(), original_comment_count)
        self.assertFalse(self.ticket.has_customer_replied)

    def test_reply_losing_auto_close_race_does_not_reopen_or_persist(self) -> None:
        """An auto-close that wins the lock makes the stale API reply fail closed."""
        original_comment_count = self.ticket.comments.count()
        original_select_for_update = Ticket.objects.select_for_update

        def auto_close_before_reply_lock(*args, **kwargs):
            current = Ticket.objects.get(pk=self.ticket.pk)
            TicketStatusService.close_ticket(current, "auto_closed")
            return original_select_for_update(*args, **kwargs)

        with (
            patch.object(Ticket.objects, "select_for_update", side_effect=auto_close_before_reply_lock),
        ):
            response = self._post_reply("A reply racing the auto-close worker")

        self.assertEqual(response.status_code, 400)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, "closed")
        self.assertEqual(self.ticket.resolution_code, "auto_closed")
        self.assertEqual(self.ticket.comments.count(), original_comment_count)
        self.assertFalse(self.ticket.has_customer_replied)
