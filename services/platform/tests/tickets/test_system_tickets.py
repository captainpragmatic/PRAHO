"""Tickets Platform raises and writes on by itself, alongside staff working the same ticket."""

from __future__ import annotations

from django.test import TestCase

from apps.customers.models import Customer
from apps.tickets.models import Ticket
from apps.tickets.services import TicketStatusService, add_system_comment, open_system_ticket
from apps.users.models import User


class SystemTicketCommentTests(TestCase):
    def setUp(self):
        customer = Customer.objects.create(
            name="System ticket customer", customer_type="company", status="active", primary_email="st@example.test"
        )
        self.ticket = open_system_ticket(customer, title="Notice", description="Body", related_service=None)
        TicketStatusService.close_ticket(self.ticket, "fixed")

    def test_a_note_on_an_older_copy_keeps_what_staff_changed_since(self):
        stale = Ticket.objects.get(pk=self.ticket.pk)
        agent = User.objects.create_user("agent@example.test", "fixture-password")
        current = Ticket.objects.get(pk=self.ticket.pk)
        TicketStatusService.reopen_ticket(current)
        current.assigned_to = agent
        current.save(update_fields=["assigned_to"])
        add_system_comment(stale, "Writes are now held.")
        current.refresh_from_db()
        self.assertEqual((current.status, current.assigned_to_id), ("open", agent.pk))
        self.assertEqual(current.comments.filter(is_public=True, comment_type="system").count(), 1)

    def test_a_note_reopens_a_closed_ticket(self):
        add_system_comment(self.ticket, "Writes are now held.")
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, "open")

    def test_a_note_is_signed_with_the_deployments_own_brand(self):
        from apps.settings.models import SystemSetting  # noqa: PLC0415

        SystemSetting.objects.create(
            key="company.brand_name", value="Example Hosting", default_value="", data_type="string", category="company"
        )
        comment = add_system_comment(self.ticket, "Writes are now held.")
        self.assertEqual(comment.author_name, "Example Hosting")
