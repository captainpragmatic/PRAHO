"""A GDPR export includes the billing data the person is the subject of (Art. 15).

`billing_data` was declared and never filled, though the export's scope has `include_billing`.
It now holds, for each individual customer the person owns, the tax profile (with the CNP), the
invoices and the proformas, each reduced to an allowlist of fields. A company's documents are its
own records and are not exported to its members. An unreadable CNP fails the export rather than
giving the person an incomplete copy.
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.services import GDPRExportService
from apps.billing.invoice_models import Invoice
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import Customer
from apps.customers.profile_models import CustomerTaxProfile
from apps.users.models import CustomerMembership
from tests.billing import _fiscal_correction_helpers as h

User = get_user_model()
CNP = "1850101123451"
SNAPSHOT = sorted(Invoice._BILLING_SNAPSHOT_FIELDS)
INVOICE_FIELDS = {
    "number", "document_kind", "status", "issued_at", "due_at", "currency",
    "subtotal_cents", "tax_cents", "total_cents", *SNAPSHOT,
}
PROFORMA_FIELDS = {"number", "status", "valid_until", "currency", "subtotal_cents", "tax_cents", "total_cents", *SNAPSHOT}
SCOPE = {"include_profile": True, "include_customers": True, "include_billing": True, "include_tickets": True}


class ExportBillingDataTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="billing-subject@example.test", password="pass12345")

    def customer(self, customer_type: str, role: str, *, cnp: str = "") -> Customer:
        customer = Customer.objects.create(
            name=f"{customer_type} {uuid.uuid4().hex[:6]}",
            customer_type=customer_type,
            status="active",
            primary_email=f"{uuid.uuid4().hex[:8]}@example.test",
        )
        CustomerTaxProfile.objects.create(customer=customer, cnp=cnp)
        CustomerMembership.objects.create(user=self.user, customer=customer, role=role)
        return customer

    def documents(self, customer: Customer, cnp: str = "") -> tuple[Invoice, ProformaInvoice]:
        invoice = h.issued_invoice(customer, issue=False)
        invoice.bill_to_cnp = cnp
        invoice.save()
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            currency=h.ron(),
            number=f"PRO-{uuid.uuid4().hex[:8]}",
            valid_until=timezone.now() + timedelta(days=30),
            bill_to_cnp=cnp,
        )
        return invoice, proforma

    def billing(self, scope: dict[str, bool] | None = None) -> list[dict[str, object]]:
        data = GDPRExportService._collect_user_data(self.user, scope or SCOPE)
        return data["billing_data"]

    def test_an_individual_owner_gets_their_tax_profile_invoices_and_proformas(self) -> None:
        customer = self.customer("individual", "owner", cnp=CNP)
        invoice, proforma = self.documents(customer, cnp=CNP)

        [entry] = self.billing()

        self.assertEqual(entry["customer_id"], customer.pk)
        self.assertEqual(entry["tax_profile"]["cnp"], CNP)
        [exported_invoice] = entry["invoices"]
        [exported_proforma] = entry["proformas"]
        self.assertEqual(set(exported_invoice), INVOICE_FIELDS)
        self.assertEqual(set(exported_proforma), PROFORMA_FIELDS)
        self.assertEqual(exported_invoice["bill_to_cnp"], CNP)
        self.assertEqual(exported_invoice["number"], invoice.number)
        self.assertEqual(exported_proforma["number"], proforma.number)

    def test_company_documents_and_other_roles_are_not_exported(self) -> None:
        self.documents(self.customer("company", "owner"))
        self.documents(self.customer("company", "billing"))
        self.documents(self.customer("individual", "viewer", cnp=CNP), cnp=CNP)

        self.assertEqual(self.billing(), [])

    def test_a_soft_deleted_tax_profile_is_still_exported(self) -> None:
        customer = self.customer("individual", "owner", cnp=CNP)
        CustomerTaxProfile.objects.get(customer=customer).soft_delete()

        [entry] = self.billing()

        self.assertEqual(entry["tax_profile"]["cnp"], CNP)

    def test_each_profile_and_document_counts_as_a_record(self) -> None:
        customer = self.customer("individual", "owner", cnp=CNP)
        self.documents(customer, cnp=CNP)
        self.documents(customer, cnp=CNP)
        only_billing = {
            "include_profile": False, "include_customers": False, "include_billing": True,
            "include_tickets": False, "include_audit_logs": False,
        }
        data = GDPRExportService._collect_user_data(self.user, only_billing)

        # The user profile (always counted), then one tax profile, two invoices and two proformas.
        self.assertEqual(GDPRExportService._count_records(data), 1 + 1 + 2 + 2)

    def test_a_former_owner_gets_no_billing_data(self) -> None:
        customer = self.customer("individual", "owner", cnp=CNP)
        self.documents(customer, cnp=CNP)
        CustomerMembership.objects.filter(user=self.user, customer=customer).update(is_active=False)

        self.assertEqual(self.billing(), [])

    def test_billing_follows_its_own_scope_flag(self) -> None:
        self.documents(self.customer("individual", "owner", cnp=CNP), cnp=CNP)

        self.assertEqual(self.billing({**SCOPE, "include_billing": False}), [])
        self.assertEqual(len(self.billing({**SCOPE, "include_customers": False})), 1)


class ExportBillingFailsClosedTests(TestCase):
    def setUp(self) -> None:
        media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        settings_override = override_settings(MEDIA_ROOT=media)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.media = Path(media)
        self.user = User.objects.create_user(email="unreadable@example.test", password="pass12345")

    def test_an_unreadable_cnp_fails_the_export_and_leaves_no_file(self) -> None:
        customer = Customer.objects.create(
            name="Unreadable", customer_type="individual", status="active", primary_email="u@example.test"
        )
        CustomerMembership.objects.create(user=self.user, customer=customer, role="owner")
        profile = CustomerTaxProfile.objects.create(customer=customer, cnp=CNP)
        donor = CustomerTaxProfile.objects.create(
            customer=Customer.objects.create(name="Donor", customer_type="individual", primary_email="d@example.test"),
            cnp=CNP,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_tax_profiles SET cnp = (SELECT cnp FROM customer_tax_profiles WHERE id = %s) "
                "WHERE id = %s",
                [donor.pk, profile.pk],
            )
        export = GDPRExportService.create_data_export_request(self.user).unwrap()

        result = GDPRExportService.process_data_export(export)

        self.assertTrue(result.is_err())
        export.refresh_from_db()
        self.assertEqual((export.status, export.file_path), ("failed", ""))
        self.assertFalse((self.media / "gdpr_exports").exists() and any((self.media / "gdpr_exports").iterdir()))
