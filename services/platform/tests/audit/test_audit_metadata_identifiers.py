"""Audit metadata carries identifiers, not copies of the record (rows 56, 52).

A customer or ticket event's metadata used to copy the customer's name, email, phone, website and
the account manager's email, and a ticket's title and contact. Those copies outlive every change to
the record and are not where an erasure looks first. Metadata now holds ids, the type, the changed
field names and compliance flags. The changed values live in `old_values` and `new_values`, with
the same keys, the changed fields only, and nothing is written when nothing changed.
"""

from __future__ import annotations

from django.test import TestCase

from apps.audit.models import AuditEvent, ComplianceLog
from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import User

EMAIL = "ioana.rowe@example.test"
PERSONAL = ("ioana", "rowe", EMAIL, "+40722123456", "ioana-rowe.example.test", "manager@example.test")


def _events(customer: Customer, action: str) -> list[AuditEvent]:
    return list(AuditEvent.objects.filter(action=action, object_id=str(customer.pk)).order_by("timestamp"))


class CustomerEventMetadataTests(TestCase):
    def setUp(self) -> None:
        manager = User.objects.create_user(email="manager@example.test", password="x-pass-123", is_staff=True)
        self.customer = Customer.objects.create(
            name="Ioana Rowe",
            customer_type="individual",
            status="active",
            primary_email=EMAIL,
            primary_phone="+40722123456",
            website="https://ioana-rowe.example.test",
            assigned_account_manager=manager,
        )

    def test_customer_event_metadata_holds_identifiers_only(self) -> None:
        self.customer.primary_phone = "+40733000000"
        self.customer.save()

        for action in ("customer_created", "customer_updated"):
            (event,) = _events(self.customer, action)
            metadata = str(event.metadata).lower()
            for value in PERSONAL:
                self.assertNotIn(value, metadata, action)
            self.assertEqual(event.metadata["customer_id"], str(self.customer.pk))
            self.assertEqual(event.metadata["customer_type"], "individual")
        (updated,) = _events(self.customer, "customer_updated")
        self.assertEqual(updated.metadata["changed_fields"], ["primary_phone"])

    def test_old_and_new_values_hold_the_same_changed_fields(self) -> None:
        self.customer.primary_phone = "+40733000000"
        self.customer.industry = "Hosting"
        self.customer.save()

        (event,) = _events(self.customer, "customer_updated")
        self.assertEqual(event.old_values, {"primary_phone": "+40722123456", "industry": ""})
        self.assertEqual(event.new_values, {"primary_phone": "+40733000000", "industry": "Hosting"})

    def test_a_save_that_changes_nothing_writes_no_event(self) -> None:
        self.customer.save()
        self.assertEqual(_events(self.customer, "customer_updated"), [])

    def test_a_consent_only_change_still_runs_the_consent_handlers(self) -> None:
        self.customer.marketing_consent = True
        self.customer.save()

        (event,) = _events(self.customer, "customer_updated")
        self.assertEqual(event.new_values, {"marketing_consent": True})
        consent_trail = ComplianceLog.objects.filter(
            compliance_type="marketing_consent", reference_id=f"customer_{self.customer.pk}"
        )
        self.assertTrue(consent_trail.exists(), "the consent trail (#182) must still be written")


class TicketEventMetadataTests(TestCase):
    def test_ticket_opened_metadata_holds_no_title_or_contact(self) -> None:
        customer = Customer.objects.create(name="Ioana Rowe", customer_type="individual", status="active")
        category = SupportCategory.objects.create(name="General", name_en="General")
        ticket = Ticket.objects.create(
            customer=customer,
            category=category,
            title="Ioana Rowe cannot log in",
            description="x",
            contact_person="Ioana Rowe",
            contact_email=EMAIL,
            status="open",
        )

        event = AuditEvent.objects.get(action="support_ticket_created", object_id=str(ticket.pk))
        metadata = str(event.metadata).lower()
        for value in ("ioana", "rowe", EMAIL):
            self.assertNotIn(value, metadata)
        self.assertEqual(event.metadata["ticket_number"], ticket.ticket_number)
        self.assertEqual(event.metadata["customer_id"], str(customer.pk))
