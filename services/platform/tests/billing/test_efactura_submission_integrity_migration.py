"""Migration coverage for e-Factura claim and response evidence fields."""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from tests.helpers.migrations import restore_to_leaf

MIGRATE_FROM = ("billing", "0039_invoice_tax_point_and_fx_snapshot")
MIGRATE_TO = ("billing", "0040_efactura_submission_integrity")


class EFacturaSubmissionIntegrityMigrationTest(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        currency = CurrencyFactory(code="RON")
        customer = CustomerFactory()
        invoice = InvoiceFactory(customer=customer, currency=currency, number="INV-MIGRATION-ARCHIVE")
        document = EFacturaDocument.objects.create(
            invoice=invoice,
            response_archive="efactura/pdf/2026/07/legacy-response.pdf",
        )
        self.document_id = document.pk

        MigrationExecutor(connection).migrate([MIGRATE_FROM])

    def tearDown(self) -> None:
        # Restore the CURRENT leaf, not MIGRATE_TO: that name was the leaf only when
        # this test was written, and every migration added since would be left
        # unapplied for each later test in the process (#445).
        restore_to_leaf("billing")
        super().tearDown()

    def test_legacy_storage_key_survives_truthful_field_rename(self) -> None:
        old_executor = MigrationExecutor(connection)
        old_apps = old_executor.loader.project_state([MIGRATE_FROM]).apps
        old_document_model = old_apps.get_model("billing", "EFacturaDocument")

        before = old_document_model.objects.get(pk=self.document_id)
        self.assertEqual(before.signed_pdf.name, "efactura/pdf/2026/07/legacy-response.pdf")

        old_executor.migrate([MIGRATE_TO])
        migrated_apps = old_executor.loader.project_state([MIGRATE_TO]).apps
        migrated_document_model = migrated_apps.get_model("billing", "EFacturaDocument")

        after = migrated_document_model.objects.get(pk=self.document_id)
        self.assertEqual(after.response_archive.name, "efactura/pdf/2026/07/legacy-response.pdf")
        self.assertEqual(after.response_archive_sha256, "")
        self.assertIsNone(after.response_archive_downloaded_at)
