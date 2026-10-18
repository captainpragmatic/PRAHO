"""Anonymising a person also anonymises the live record of the individual customer they are.

An individual customer is the person. Their live record (name, contact, addresses) goes with the
user. Issued invoices are fiscal records and keep the buyer as issued.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService
from apps.billing.invoice_models import Invoice
from apps.customers.contact_models import CustomerAddress
from apps.customers.customer_models import Customer
from apps.users.models import CustomerMembership, User
from tests.factories.billing_factories import create_invoice
from tests.factories.core_factories import create_individual_customer

EMAIL = "ioana.rowe@example.test"


class CustomerRowAnonymisationTests(TestCase):
    def setUp(self) -> None:
        self.person = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana")
        self.customer = create_individual_customer(first_name="Ioana", last_name="Rowe", email=EMAIL)
        Customer.objects.filter(pk=self.customer.pk).update(website="https://ioana-rowe.example.test")
        CustomerMembership.objects.create(user=self.person, customer=self.customer, role="owner", is_primary=True)

    def anonymise(self) -> None:
        request = GDPRDeletionService.create_deletion_request(user=self.person, deletion_type="anonymize").unwrap()
        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

    def test_the_live_customer_record_goes_and_the_issued_invoice_stays(self) -> None:
        invoice = create_invoice(self.customer, number="INV-ROWE-1")
        Invoice.objects.filter(pk=invoice.pk).update(
            bill_to_name="Ioana Rowe", bill_to_email=EMAIL, bill_to_address1="Str. Rowe 7", locked_at=timezone.now()
        )
        company = Customer.objects.create(
            name="Rowe Consulting SRL", customer_type="company", company_name="Rowe Consulting SRL", status="active"
        )
        CustomerMembership.objects.create(user=self.person, customer=company, role="owner")

        self.anonymise()

        self.customer.refresh_from_db()
        record = " ".join(
            [self.customer.name, self.customer.primary_email, self.customer.primary_phone, self.customer.website]
        ).lower()
        for identifier in ("ioana", "rowe", EMAIL, "+40722123456"):
            self.assertNotIn(identifier, record)
        for address in CustomerAddress.all_objects.filter(customer=self.customer):
            self.assertNotIn("Str.", address.address_line1)
            self.assertEqual(address.postal_code, "000000")
        self.assertTrue(
            AuditEvent.objects.filter(
                action="data_anonymization_completed", metadata__customer_id=str(self.customer.pk)
            ).exists()
        )
        # The fiscal record keeps the buyer as issued; a company is not the person.
        invoice.refresh_from_db()
        self.assertEqual((invoice.bill_to_name, invoice.bill_to_email), ("Ioana Rowe", EMAIL))
        self.assertEqual(invoice.bill_to_address1, "Str. Rowe 7")
        company.refresh_from_db()
        self.assertEqual(company.name, "Rowe Consulting SRL")

    def test_an_individual_customer_with_another_owner_is_left_as_it_is(self) -> None:
        other = User.objects.create_user(email="second.owner@example.test", password="x-pass-123")
        CustomerMembership.objects.create(user=other, customer=self.customer, role="owner")

        self.anonymise()

        self.customer.refresh_from_db()
        self.assertEqual(self.customer.primary_email, EMAIL)
