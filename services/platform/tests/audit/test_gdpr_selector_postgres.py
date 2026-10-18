"""On PostgreSQL, erasure finds the person's billing and order events through their customer.

`AuditEvent.object_id` is text, while an invoice's key is an integer and an order's a UUID. The
selector matches the ids as text, so this runs where the types really differ.
"""

from __future__ import annotations

from unittest import skipUnless

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.audit.person_events import capture_subject, events_about
from apps.billing.invoice_models import Invoice
from apps.orders.models import Order
from apps.users.models import CustomerMembership, User
from tests.factories.billing_factories import create_invoice
from tests.factories.core_factories import create_individual_customer


@skipUnless(connection.vendor == "postgresql", "the id types only differ on PostgreSQL")
class SelectorFindsCustomerRecordsOnPostgresTests(TestCase):
    def test_invoice_and_order_events_of_an_owned_customer_are_about_the_person(self) -> None:
        person = User.objects.create_user(email="pg.person@example.test", password="x-pass-123")
        customer = create_individual_customer(email="pg.person@example.test")
        CustomerMembership.objects.create(user=person, customer=customer, role="owner", is_primary=True)
        invoice = create_invoice(customer)
        order = Order.objects.create(customer=customer, currency=invoice.currency)
        stranger_invoice = create_invoice(create_individual_customer(email="x@example.test"), number="INV-OTHER")
        events = {
            name: AuditEvent.objects.create(
                action=f"{name}_event",
                category="business_operation",
                severity="low",
                content_type=ContentType.objects.get_for_model(model),
                object_id=str(obj.pk),
                description=name,
            )
            for name, model, obj in (
                ("invoice", Invoice, invoice),
                ("order", Order, order),
                ("stranger", Invoice, stranger_invoice),
            )
        }

        found = set(events_about(capture_subject(person)).values_list("pk", flat=True))

        self.assertIn(events["invoice"].pk, found)
        self.assertIn(events["order"].pk, found)
        self.assertNotIn(events["stranger"].pk, found)
