"""A customer's CNP is encrypted at rest, shown to staff only as "on file", and erased by GDPR.

`CustomerTaxProfile.cnp` is an EncryptedTextField bound to the row's `encryption_context_id`,
which a trigger keeps immutable (customers 0004, ADR-0040). GDPR anonymisation clears the CNP of
the individual customers the user owns wherever it is not a fiscal record: the tax profile, every
proforma and every invoice not yet issued. Issued invoices keep their snapshot for the legal
retention period.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService, gdpr_deletion_service
from apps.billing.invoice_models import Invoice
from apps.billing.invoice_querysets import InvoiceQuerySet
from apps.billing.proforma_models import ProformaInvoice, ProformaLine
from apps.billing.services import ProformaConversionService
from apps.billing.usage_invoice_service import UsageInvoiceService
from apps.common.encryption import EncryptionError
from apps.customers.models import Customer
from apps.customers.profile_models import CustomerTaxProfile
from apps.users.models import CustomerMembership
from tests.billing import _fiscal_correction_helpers as h

User = get_user_model()
CNP = "1850101123451"


def stored_cnp(profile_id: int) -> str | None:
    expression = "cnp::text" if connection.vendor == "postgresql" else "cnp"
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {expression} FROM customer_tax_profiles WHERE id = %s", [profile_id])  # noqa: S608
        value = cursor.fetchone()[0]
    return None if value is None else str(value)


def individual(name: str, cnp: str = CNP) -> tuple[Customer, CustomerTaxProfile]:
    customer = Customer.objects.create(
        name=name, customer_type="individual", status="active", primary_email=f"{uuid.uuid4().hex[:8]}@example.test"
    )
    return customer, CustomerTaxProfile.objects.create(customer=customer, cnp=cnp)


class TaxProfileCNPAtRestTests(TestCase):
    def test_the_cnp_is_stored_as_ciphertext(self) -> None:
        _customer, profile = individual("At Rest")

        raw = stored_cnp(profile.pk)
        assert raw is not None
        self.assertIn("aes:v2:", raw)
        self.assertNotIn(CNP, raw)
        self.assertEqual(CustomerTaxProfile.objects.get(pk=profile.pk).cnp, CNP)

    def test_no_cnp_is_stored_as_null(self) -> None:
        _customer, profile = individual("No CNP", cnp="")

        self.assertIsNone(stored_cnp(profile.pk))
        self.assertEqual(CustomerTaxProfile.objects.get(pk=profile.pk).cnp, "")

    def test_the_encryption_context_cannot_change(self) -> None:
        _customer, profile = individual("Trigger")

        with self.assertRaises(DatabaseError), transaction.atomic():
            CustomerTaxProfile.objects.filter(pk=profile.pk).update(encryption_context_id=uuid.uuid4())

        self.assertEqual(CustomerTaxProfile.objects.get(pk=profile.pk).cnp, CNP)

    def test_a_cnp_cannot_be_written_without_its_row(self) -> None:
        _customer, profile = individual("Unbound", cnp="")

        with self.assertRaises(EncryptionError), transaction.atomic():
            CustomerTaxProfile.objects.filter(pk=profile.pk).update(cnp=CNP)

        self.assertIsNone(stored_cnp(profile.pk))

    def test_the_reencryption_command_finds_every_cnp_current(self) -> None:
        individual("Current")
        out = StringIO()

        call_command("reencrypt_with_aad", "--dry-run", stdout=out)

        self.assertIn("customer_tax_profiles.cnp", out.getvalue())
        self.assertRegex(out.getvalue(), r"Total: 0 migrated, 0 rekeyed, [1-9]\d* already v2, 0 corrupt")


class StaffCustomerListCNPTests(TestCase):
    def setUp(self) -> None:
        staff = User.objects.create_user(
            email="cnp-staff@example.test", password="staffpass123", is_staff=True, staff_role="admin"
        )
        self.client.force_login(staff)

    def test_the_list_says_a_cnp_is_on_file_without_showing_it(self) -> None:
        individual("Ion Popescu")
        Customer.objects.create(
            name="No CNP Person", customer_type="individual", status="active", primary_email="none@example.test"
        )

        response = self.client.get(reverse("customers:list"))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("CNP on file", content)
        self.assertEqual(content.count("CNP on file"), 2)  # the table row and the mobile card
        self.assertNotIn(CNP[:8], content)


class GDPRErasureCNPTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="erase-me@example.test", password="pass12345")
        self.customer, self.profile = individual("Erase Me")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)

    def anonymize(self) -> None:
        request = gdpr_deletion_service.create_deletion_request(user=self.user, deletion_type="anonymize").unwrap()
        result = gdpr_deletion_service.process_deletion_request(request)
        self.assertTrue(result.is_ok(), result)

    def test_erasure_clears_the_cnp_of_customers_the_user_owns(self) -> None:
        deleted_customer, deleted_profile = individual("Soft Deleted")
        CustomerMembership.objects.create(user=self.user, customer=deleted_customer, role="owner")
        deleted_profile.soft_delete()
        other_customer, other_profile = individual("Not Theirs")
        viewer_customer, viewer_profile = individual("Viewer Only")
        CustomerMembership.objects.create(user=self.user, customer=viewer_customer, role="viewer")

        self.anonymize()

        self.assertIsNone(stored_cnp(self.profile.pk))
        self.assertIsNone(stored_cnp(deleted_profile.pk))
        self.assertEqual(CustomerTaxProfile.objects.get(pk=other_profile.pk).cnp, CNP)
        self.assertEqual(CustomerTaxProfile.objects.get(pk=viewer_profile.pk).cnp, CNP)
        self.assertIsNotNone(other_customer.pk)

    def invoice(self, customer: Customer, *, issue: bool) -> Invoice:
        invoice = h.issued_invoice(customer, issue=False)
        invoice.bill_to_cnp = CNP
        invoice.due_at = timezone.now() + timedelta(days=30)
        invoice.save()
        if issue:
            invoice.issue()
            invoice.save()
            self.assertIsNotNone(invoice.locked_at)
        return invoice

    def proforma(self, customer: Customer, **fields: object) -> ProformaInvoice:
        return ProformaInvoice.objects.create(
            customer=customer,
            currency=h.ron(),
            number=f"PRO-{uuid.uuid4().hex[:8]}",
            valid_until=timezone.now() + timedelta(days=30),
            bill_to_cnp=CNP,
            **fields,
        )

    def test_erasure_keeps_the_cnp_on_issued_invoices(self) -> None:
        issued = self.invoice(self.customer, issue=True)

        self.anonymize()

        self.assertEqual(Invoice.objects.get(pk=issued.pk).bill_to_cnp, CNP)

    def test_erasure_clears_proformas_and_invoices_not_yet_issued(self) -> None:
        proformas = [self.proforma(self.customer, status=status) for status, _label in ProformaInvoice.STATUS_CHOICES]
        self.assertEqual(
            set(ProformaInvoice.objects.filter(pk__in=[p.pk for p in proformas]).values_list("status", flat=True)),
            {status for status, _label in ProformaInvoice.STATUS_CHOICES},
        )
        draft = self.invoice(self.customer, issue=False)
        other_customer, _other_profile = individual("Someone Else")
        others = (self.proforma(other_customer), self.invoice(other_customer, issue=False))

        self.anonymize()

        for proforma in proformas:
            with self.subTest(status=proforma.status):
                self.assertEqual(ProformaInvoice.objects.get(pk=proforma.pk).bill_to_cnp, "")
        self.assertEqual(Invoice.objects.get(pk=draft.pk).bill_to_cnp, "")
        for document in others:
            self.assertEqual(type(document).objects.get(pk=document.pk).bill_to_cnp, CNP)
        cleared = AuditEvent.objects.filter(action="data_anonymization_completed", metadata__field="bill_to_cnp")
        self.assertEqual(cleared.count(), len(proformas) + 1)
        self.assertEqual(
            {event.metadata.get("proforma_id") for event in cleared if "proforma_id" in event.metadata},
            {proforma.pk for proforma in proformas},
        )
        self.assertEqual([event.metadata["invoice_id"] for event in cleared if "invoice_id" in event.metadata], [draft.pk])

    def test_an_unreadable_cnp_does_not_block_the_erasure(self) -> None:
        proforma = self.proforma(self.customer)
        donor = self.proforma(self.customer)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE billing_proforma_invoices SET bill_to_cnp = "
                "(SELECT bill_to_cnp FROM billing_proforma_invoices WHERE id = %s) WHERE id = %s",
                [donor.pk, proforma.pk],
            )

        self.anonymize()

        self.assertEqual(ProformaInvoice.objects.get(pk=proforma.pk).bill_to_cnp, "")

    def test_an_invoice_issued_from_a_copy_loaded_before_erasure_keeps_no_cnp(self) -> None:
        """Issuance reloads its draft under lock; a copy read before the erasure cannot write it back."""
        draft = self.invoice(self.customer, issue=False)
        stale = Invoice.objects.get(pk=draft.pk)
        self.anonymize()

        with patch.object(Invoice.objects, "get", return_value=stale):
            result = UsageInvoiceService().issue_invoice(str(draft.pk))

        self.assertTrue(result.is_ok(), result)
        issued = Invoice.objects.filter(pk=draft.pk).values_list("locked_at", flat=True).get()
        self.assertIsNotNone(issued)
        self.assertEqual(Invoice.objects.filter(pk=draft.pk).first().bill_to_cnp, "")

    def test_a_proforma_edited_from_a_copy_loaded_before_erasure_keeps_no_cnp(self) -> None:
        """The staff edit reloads its proforma under lock; a copy read before the erasure cannot write it back."""
        proforma = self.proforma(self.customer)
        stale = ProformaInvoice.objects.get(pk=proforma.pk)
        self.anonymize()
        staff = User.objects.create_user(
            email="edit-staff@example.test", password="pass12345", is_staff=True, staff_role="billing"
        )
        self.client.force_login(staff)
        data = {
            "customer": self.customer.pk,
            "valid_until": (timezone.localdate() + timedelta(days=30)).isoformat(),
            "line_0_description": "Hosting",
            "line_0_quantity": "1",
            "line_0_unit_price": "10.00",
            "line_0_vat_rate": "21",
        }

        with patch("apps.billing.views.get_object_or_404", return_value=stale):
            response = self.client.post(reverse("billing:proforma_edit", args=[proforma.pk]), data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(ProformaInvoice.objects.get(pk=proforma.pk).bill_to_cnp, "")

    def test_an_invoice_issued_during_the_erasure_is_not_audited_as_cleared(self) -> None:
        racing = self.invoice(self.customer, issue=False)
        other = self.invoice(self.customer, issue=False)
        original_update = InvoiceQuerySet.update

        def issue_first(queryset: InvoiceQuerySet, **kwargs: object) -> int:
            if "bill_to_cnp" in kwargs:
                issued = Invoice.objects.get(pk=racing.pk)
                issued.due_at = timezone.now() + timedelta(days=30)
                issued.issue()
                issued.save()
            return original_update(queryset, **kwargs)

        with patch.object(InvoiceQuerySet, "update", issue_first):
            self.anonymize()

        self.assertEqual(Invoice.objects.get(pk=racing.pk).bill_to_cnp, CNP)
        self.assertEqual(Invoice.objects.get(pk=other.pk).bill_to_cnp, "")
        audited = [
            event.metadata["invoice_id"]
            for event in AuditEvent.objects.filter(action="data_anonymization_completed", metadata__field="bill_to_cnp")
            if "invoice_id" in event.metadata
        ]
        self.assertEqual(audited, [other.pk])

    def test_a_proforma_converted_after_erasure_bills_without_a_cnp(self) -> None:
        proforma = self.proforma(self.customer, subtotal_cents=10000, tax_cents=2100, total_cents=12100)
        ProformaLine.objects.create(
            proforma=proforma,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )

        self.anonymize()
        invoice = ProformaConversionService.convert_to_invoice(str(proforma.pk)).unwrap()

        self.assertEqual(Invoice.objects.get(pk=invoice.pk).bill_to_cnp, "")

    def test_erasure_is_audited_without_the_cnp(self) -> None:
        self.anonymize()

        events = AuditEvent.objects.filter(action="data_anonymization_completed", metadata__field="cnp")
        self.assertEqual(events.count(), 1)
        event = events.get()
        self.assertEqual(event.metadata["tax_profile_id"], self.profile.pk)
        self.assertEqual(event.metadata["customer_id"], str(self.customer.pk))
        self.assertNotIn(CNP, str(event.metadata) + str(event.old_values) + str(event.new_values))

    def test_a_failure_part_way_rolls_the_whole_erasure_back(self) -> None:
        original_email = self.user.email
        request = gdpr_deletion_service.create_deletion_request(user=self.user, deletion_type="anonymize").unwrap()

        with patch(
            "apps.audit.services.AuditService.log_simple_event", side_effect=DatabaseError("audit store unavailable")
        ):
            result = GDPRDeletionService.process_deletion_request(request)

        self.assertTrue(result.is_err())
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, original_email)
        self.assertEqual(CustomerTaxProfile.objects.get(pk=self.profile.pk).cnp, CNP)
        request.refresh_from_db()
        self.assertEqual(request.status, "failed")
