"""A billing file is deleted only when nothing fiscal depends on it, and never left without a row.

An issued invoice's PDF and XML, and an e-Factura document that reached ANAF, are fiscal records:
deleting their rows (a cascade that bypasses Invoice.delete(), for one) must not delete the files.
A draft's files go once its delete commits. The writers store a file before its row names it, so
a failed row save deletes the new file, and a replaced file is deleted only once the replacement
commits.
"""

from __future__ import annotations

import tempfile
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models.deletion import Collector
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import EFacturaClient
from apps.billing.efactura.models import EFacturaDocument
from apps.billing.efactura.service import EFacturaService
from apps.billing.efactura.xml_builder import XMLBuilderError
from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.documents import get_invoice_pdf_bytes
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.common.types import Ok
from tests.billing._storno_helpers import v2_evidence
from tests.billing.efactura.test_response_archive import response_zip
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.helpers.fsm_helpers import force_status


@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_NAME="Files Supplier SRL",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Supplier Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Files Bank",
)
class BillingFileLifecycleTests(TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        media = override_settings(MEDIA_ROOT=directory.name)
        media.enable()
        self.addCleanup(media.disable)
        self.media = Path(directory.name)
        self.customer = CustomerFactory()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.counter = 0

    def _invoice(self, status: str = "draft", issuer: str = "builtin") -> Invoice:
        self.counter += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FILES-{self.counter:03d}",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            issued_at=timezone.now() - timedelta(days=1),
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name="Files SRL",
            bill_to_tax_id="RO87654321",
            bill_to_address1="Customer Street 2",
            bill_to_city="Cluj-Napoca",
            bill_to_postal="400001",
            bill_to_country="RO",
            issuer_provider=issuer,
            vat_evidence=v2_evidence(subtotal=10000, tax=2100, total=12100, rate="21"),
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        invoice.pdf_file.save(f"invoice_{invoice.number}.pdf", ContentFile(b"%PDF"), save=False)
        invoice.save(update_fields=["pdf_file"])
        if status != "draft":
            force_status(invoice, status)
        return invoice

    def _document(self, invoice: Invoice, status: str = "draft") -> EFacturaDocument:
        document, _ = EFacturaDocument.objects.get_or_create(invoice=invoice, defaults={"environment": "test"})
        document.xml_file.save(f"{invoice.number}.xml", ContentFile(b"<Invoice/>"), save=False)
        document.response_archive.save(f"efactura_{document.id}.zip", ContentFile(response_zip()), save=False)
        document.save(update_fields=["xml_file", "response_archive", "updated_at"])
        if status != "draft":
            force_status(document, status)
        return document

    def _exists(self, name: str) -> bool:
        return (self.media / name).exists()

    def test_draft_invoice_delete_removes_its_files_after_commit(self) -> None:
        invoice = self._invoice()
        document = self._document(invoice)
        names = [invoice.pdf_file.name, document.xml_file.name, document.response_archive.name]

        with self.captureOnCommitCallbacks(execute=True):
            invoice.delete()
            self.assertEqual([name for name in names if not self._exists(name)], [], "kept until the commit")

        self.assertEqual([name for name in names if self._exists(name)], [])

    def test_issued_invoice_cascade_keeps_its_fiscal_files(self) -> None:
        invoice = self._invoice(status="issued")
        document = self._document(invoice)
        names = [invoice.pdf_file.name, document.xml_file.name, document.response_archive.name]

        with self.captureOnCommitCallbacks(execute=True), self.assertLogs("apps.billing.signals", "ERROR"):
            collector = Collector(using="default", origin=invoice)  # A cascade that bypasses Invoice.delete()
            collector.collect([invoice])
            collector.delete()

        self.assertEqual([name for name in names if not self._exists(name)], [])

    def test_accepted_document_delete_keeps_the_anaf_archive(self) -> None:
        document = self._document(self._invoice(), status="accepted")

        with self.captureOnCommitCallbacks(execute=True), self.assertLogs("apps.billing.signals", "ERROR"):
            document.delete()

        self.assertTrue(self._exists(document.response_archive.name))
        self.assertTrue(self._exists(document.xml_file.name))

    def test_efactura_document_delete_removes_xml_and_archive_after_commit(self) -> None:
        document = self._document(self._invoice())
        names = [document.xml_file.name, document.response_archive.name]

        with self.captureOnCommitCallbacks(execute=True), self.assertRaises(RuntimeError), transaction.atomic():
            EFacturaDocument.objects.get(pk=document.pk).delete()
            raise RuntimeError("rolled back")
        self.assertEqual([name for name in names if not self._exists(name)], [], "a rolled-back delete keeps them")

        with self.captureOnCommitCallbacks(execute=True):
            document.delete()
            self.assertTrue(all(self._exists(name) for name in names))

        self.assertEqual([name for name in names if self._exists(name)], [])

    def test_regenerated_xml_deletes_the_superseded_object_after_commit(self) -> None:
        invoice = self._invoice(status="issued")
        document, _ = EFacturaDocument.objects.get_or_create(invoice=invoice, defaults={"environment": "test"})
        service = EFacturaService()
        with self.captureOnCommitCallbacks(execute=True):
            service._generate_xml(invoice, document)
        first = document.xml_file.name

        with self.captureOnCommitCallbacks(execute=True):
            service._generate_xml(invoice, document)
            self.assertTrue(self._exists(first), "the superseded XML stays until the new name commits")
        second = EFacturaDocument.objects.get(pk=document.pk).xml_file.name

        self.assertNotEqual(first, second)
        self.assertFalse(self._exists(first))
        self.assertTrue(self._exists(second))

    def test_xml_row_save_failure_deletes_the_stored_xml(self) -> None:
        invoice = self._invoice(status="issued")
        document, _ = EFacturaDocument.objects.get_or_create(invoice=invoice, defaults={"environment": "test"})
        original_save = EFacturaDocument.save

        def fail_on_recording_the_file(instance: EFacturaDocument, *args: Any, **kwargs: Any) -> None:
            if "xml_file" in (kwargs.get("update_fields") or ()):
                raise OSError("row save failed")
            original_save(instance, *args, **kwargs)

        with patch.object(EFacturaDocument, "save", fail_on_recording_the_file), self.assertRaises(XMLBuilderError) as raised:
            EFacturaService()._generate_xml(invoice, document)

        self.assertIn("row save failed", str(raised.exception), "the XML was built and stored; recording it failed")

        self.assertEqual(list((self.media / "efactura").rglob("*.xml")), [])

    def test_replaced_archive_deletes_the_superseded_object_after_commit(self) -> None:
        document = self._document(self._invoice(status="issued"), status="accepted")
        superseded = document.response_archive.name
        (self.media / superseded).write_bytes(b"damaged")  # Fails the integrity check, so it is downloaded again
        document.anaf_download_id = "DOWNLOAD-1"
        document.save(update_fields=["anaf_download_id", "updated_at"])
        client = Mock(spec=EFacturaClient)
        client.download_response.return_value = response_zip()

        with self.captureOnCommitCallbacks(execute=True):
            EFacturaService(client=client).download_response(document)
            self.assertTrue(self._exists(superseded))

        document.refresh_from_db()
        self.assertNotEqual(document.response_archive.name, superseded)
        self.assertFalse(self._exists(superseded))
        self.assertTrue(document.verify_response_archive_integrity())

    def test_pdf_row_save_failure_deletes_the_stored_pdf(self) -> None:
        invoice = self._invoice(issuer=ISSUER_SMARTBILL)
        invoice.pdf_file.delete(save=False)
        Invoice.objects.filter(pk=invoice.pk).update(pdf_file="")
        invoice.refresh_from_db()
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number="000124",
        )
        original_save = Invoice.save

        def fail_on_recording_the_file(instance: Invoice, *args: Any, **kwargs: Any) -> None:
            if "pdf_file" in (kwargs.get("update_fields") or ()):
                raise OSError("row save failed")
            original_save(instance, *args, **kwargs)

        with (
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf", return_value=Ok(b"%PDF-1.4")),
            patch.object(Invoice, "save", fail_on_recording_the_file),
            self.assertRaises(OSError),
        ):
            get_invoice_pdf_bytes(invoice)

        self.assertFalse(default_storage.exists(f"invoices/pdf/invoice_{invoice.number}.pdf"))
        self.assertEqual(list(self.media.rglob("*.pdf")), [])

    def test_a_rolled_back_submission_claim_deletes_the_xml_it_stored(self) -> None:
        invoice = self._invoice(status="issued")
        EFacturaDocument.objects.filter(invoice=invoice).delete()

        with (
            patch.object(EFacturaService, "_is_b2c", side_effect=RuntimeError("detector failed")),
            self.assertRaises(RuntimeError),
        ):
            EFacturaService()._prepare_and_claim_submission(invoice)

        self.assertFalse(EFacturaDocument.objects.filter(invoice=invoice).exists(), "the claim rolled back")
        self.assertEqual(list((self.media / "efactura").rglob("*.xml")), [])
