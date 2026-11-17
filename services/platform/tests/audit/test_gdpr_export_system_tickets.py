"""A ticket Platform raised for the person has no author, and is in their export by its contact email."""

from __future__ import annotations

from django.test import TestCase

from apps.audit.services import GDPRExportService
from apps.customers.models import Customer
from apps.tickets.services import open_system_ticket
from apps.users.models import CustomerMembership, User


class SystemTicketExportTests(TestCase):
    def test_a_system_ticket_is_exported_by_its_contact_email_only_to_that_person(self):
        customer = Customer.objects.create(
            name="Export customer", customer_type="company", status="active", primary_email="Owner@Example.test"
        )
        owner = User.objects.create_user("owner@example.test", "fixture-password")
        CustomerMembership.objects.create(user=owner, customer=customer, role="owner", is_primary=True)
        stranger = User.objects.create_user("stranger@example.test", "fixture-password")
        ticket = open_system_ticket(customer, title="Platform notice", description="Body", related_service=None)

        def exported(user):
            data = GDPRExportService._collect_user_data(user, {"include_tickets": True})
            return [item["ticket_id"] for item in data["support_tickets"]]

        self.assertIsNone(ticket.created_by_id)
        self.assertEqual(exported(owner), [ticket.pk])  # matched case-insensitively, as erasure matches it
        self.assertEqual(exported(stranger), [])
