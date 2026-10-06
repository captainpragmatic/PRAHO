"""Ticket creation survives optional audit failures."""

from apps.customers.models import Customer
from apps.tickets.models import Ticket
from tests.common._signal_isolation import SignalIsolationTestCase


class TicketSignalIsolationTests(SignalIsolationTestCase):
    def test_ticket_creation_survives_failed_audit_write(self) -> None:
        customer = Customer.objects.create(name="Isolation", primary_email="ticket-customer@example.com")
        ticket = self.run_effect(
            "apps.tickets.signals.TicketsAuditService.log_ticket_opened",
            lambda: Ticket.objects.create(customer=customer, title="Isolation", description="Test", category=None),
        )
        self.assertTrue(Ticket.objects.filter(pk=ticket.pk).exists())
