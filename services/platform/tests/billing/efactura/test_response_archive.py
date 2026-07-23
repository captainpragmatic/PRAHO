"""ANAF response archive storage and integrity regressions (#352)."""

from __future__ import annotations

import hashlib
import io
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings

from apps.billing.efactura.client import EFacturaClient, StatusResponse
from apps.billing.efactura.models import EFacturaDocument
from apps.billing.efactura.service import EFacturaService
from tests.helpers.fsm_helpers import force_status


def response_zip(
    *,
    invoice_xml: bytes = b"<Invoice xmlns='urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'/>",
    signature_xml: bytes = b"<Signature xmlns='urn:anaf:signature'/>",
    include_invoice: bool = True,
    include_signature: bool = True,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        if include_invoice:
            archive.writestr("12345.xml", invoice_xml)
        if include_signature:
            archive.writestr("semnatura_12345.xml", signature_xml)
    return buffer.getvalue()


@override_settings(EFACTURA_ENABLED=True, EFACTURA_ENVIRONMENT="test")
class EFacturaResponseArchiveTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.media_directory = tempfile.TemporaryDirectory()
        self.media_override = override_settings(MEDIA_ROOT=self.media_directory.name)
        self.media_override.enable()

        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        currency = CurrencyFactory(code="RON")
        customer = CustomerFactory()
        invoice = InvoiceFactory(
            customer=customer,
            currency=currency,
            number="INV-ARCHIVE-1",
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            status="issued",
        )
        self.document = EFacturaDocument.objects.create(invoice=invoice)
        self.document.anaf_download_id = "DOWNLOAD-1"
        self.document.save(update_fields=["anaf_download_id", "updated_at"])
        force_status(self.document, "accepted")
        self.client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.client)

    def tearDown(self) -> None:
        self.media_override.disable()
        self.media_directory.cleanup()
        super().tearDown()

    def test_valid_zip_is_stored_byte_for_byte_with_sha256(self):
        content = response_zip()
        self.client.download_response.return_value = content

        result = self.service.download_response(self.document)

        self.assertEqual(result, content)
        self.document.refresh_from_db()
        self.assertTrue(self.document.response_archive.name.endswith(".zip"))
        self.assertIn("efactura/responses/", self.document.response_archive.name)
        with self.document.response_archive.open("rb") as stored:
            self.assertEqual(stored.read(), content)
        self.assertEqual(self.document.response_archive_sha256, hashlib.sha256(content).hexdigest())
        self.assertIsNotNone(self.document.response_archive_downloaded_at)
        self.assertTrue(self.document.verify_response_archive_integrity())

    def test_acceptance_status_poll_immediately_archives_the_anaf_response(self):
        content = response_zip()
        force_status(self.document, "submitted")
        self.document.anaf_upload_index = "UPLOAD-1"
        self.document.save(update_fields=["anaf_upload_index", "updated_at"])
        self.client.get_upload_status.return_value = StatusResponse(
            status="ok",
            download_id="DOWNLOAD-1",
            raw_response={"stare": "ok", "id_descarcare": "DOWNLOAD-1"},
        )
        self.client.download_response.return_value = content

        result = self.service.check_status(self.document)

        self.assertEqual(result.status, "accepted")
        self.document.refresh_from_db()
        self.assertEqual(self.document.status, "accepted")
        self.assertTrue(self.document.verify_response_archive_integrity())
        self.client.download_response.assert_called_once_with("DOWNLOAD-1")

    def test_integrity_check_detects_storage_tampering(self):
        content = response_zip()
        self.client.download_response.return_value = content
        self.service.download_response(self.document)
        self.document.refresh_from_db()

        Path(self.document.response_archive.path).write_bytes(b"tampered")

        self.assertFalse(self.document.verify_response_archive_integrity())

    def test_second_download_reuses_verified_archive_without_network_io(self):
        content = response_zip()
        self.client.download_response.return_value = content
        self.assertEqual(self.service.download_response(self.document), content)
        self.document.refresh_from_db()
        self.client.reset_mock()

        result = self.service.download_response(self.document)

        self.assertEqual(result, content)
        self.client.download_response.assert_not_called()

    def test_storage_failure_does_not_record_archive_completion(self):
        content = response_zip()
        self.client.download_response.return_value = content

        with patch.object(self.document.response_archive, "save", side_effect=OSError("storage offline")):
            result = self.service.download_response(self.document)

        self.assertIsNone(result)
        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)
        self.assertEqual(self.document.response_archive_sha256, "")
        self.assertIsNone(self.document.response_archive_downloaded_at)

    def test_invalid_zip_is_rejected_without_persisting_evidence(self):
        self.client.download_response.return_value = b"not a zip"

        result = self.service.download_response(self.document)

        self.assertIsNone(result)
        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)
        self.assertEqual(self.document.response_archive_sha256, "")
        self.assertIsNone(self.document.response_archive_downloaded_at)

    def test_non_bytes_download_is_a_controlled_archive_failure(self):
        self.client.download_response.return_value = Mock(name="malformed download body")

        result = self.service.download_response(self.document)

        self.assertIsNone(result)
        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)

    def test_archive_without_invoice_xml_is_rejected(self):
        self.client.download_response.return_value = response_zip(include_invoice=False)

        self.assertIsNone(self.service.download_response(self.document))

        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)

    def test_archive_without_ministry_signature_xml_is_rejected(self):
        self.client.download_response.return_value = response_zip(include_signature=False)

        self.assertIsNone(self.service.download_response(self.document))

        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)

    def test_archive_with_malformed_xml_is_rejected(self):
        self.client.download_response.return_value = response_zip(invoice_xml=b"<Invoice>")

        self.assertIsNone(self.service.download_response(self.document))

        self.document.refresh_from_db()
        self.assertFalse(self.document.response_archive)

    def test_validation_never_extracts_members_to_the_filesystem(self):
        self.client.download_response.return_value = response_zip()

        with patch.object(zipfile.ZipFile, "extract") as extract, patch.object(
            zipfile.ZipFile, "extractall"
        ) as extractall:
            result = self.service.download_response(self.document)

        self.assertIsNotNone(result)
        extract.assert_not_called()
        extractall.assert_not_called()
