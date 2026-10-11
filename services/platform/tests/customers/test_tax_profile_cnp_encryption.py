"""A customer's CNP is encrypted at rest, shown to staff only as "on file", and erased by GDPR.

`CustomerTaxProfile.cnp` is an EncryptedTextField bound to the row's `encryption_context_id`,
which a trigger keeps immutable (customers 0004, ADR-0040). GDPR anonymisation clears the
profile's CNP for the individual customers the user owns; issued invoices keep their own
snapshot for the legal retention period.
"""

from __future__ import annotations

import uuid
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.test import TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService, gdpr_deletion_service
from apps.billing.invoice_models import Invoice
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

    def test_erasure_keeps_the_cnp_on_issued_invoices(self) -> None:
        invoice = h.issued_invoice(self.customer, issue=False)
        invoice.bill_to_cnp = CNP
        invoice.save()

        self.anonymize()

        self.assertEqual(Invoice.objects.get(pk=invoice.pk).bill_to_cnp, CNP)

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
