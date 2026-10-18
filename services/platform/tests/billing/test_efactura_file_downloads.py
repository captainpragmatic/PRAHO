"""Staff download the stored e-Factura XML and the ANAF response archive, verified, never cached.

These files are fiscal records: the XML actually submitted and the ZIP ANAF returned. They used to
be reachable only through the web server's /media/ route, which skipped every check. Now one staff
view serves them. It reads the bytes through the storage API, checks them against the recorded
hash, and serves exactly those bytes: a mismatch is refused, never served. Each download is audited
by document, invoice, file kind and outcome, with no filename and no contents.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from botocore.exceptions import ClientError, EndpointConnectionError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.billing.efactura.models import EFacturaDocument
from tests.common import test_media_storage_contract as media_contract

User = get_user_model()

XML = "<Invoice xmlns='urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'>INV-FILES-1</Invoice>"
ARCHIVE = b"PK\x05\x06" + b"\x00" * 18


class EFacturaFileDownloadTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        media = tempfile.TemporaryDirectory()
        self.addCleanup(media.cleanup)
        override = override_settings(MEDIA_ROOT=media.name)
        override.enable()
        self.addCleanup(override.disable)

        from tests.factories import InvoiceFactory  # noqa: PLC0415

        self.invoice = InvoiceFactory(number="INV-FILES-1", status="issued")
        self.document = EFacturaDocument.objects.create(invoice=self.invoice, xml_content=XML)
        self.document.xml_file.save("INV-FILES-1.xml", ContentFile(XML.encode("utf-8")), save=False)
        self.document.response_archive.save("INV-FILES-1.zip", ContentFile(ARCHIVE), save=False)
        self.document.response_archive_sha256 = hashlib.sha256(ARCHIVE).hexdigest()
        self.document.save(update_fields=["xml_file", "response_archive", "response_archive_sha256", "updated_at"])

        self.billing = User.objects.create_user(email="billing-files@example.com", is_staff=True, staff_role="billing")
        self.client = Client()
        self.client.force_login(self.billing)

    def _get(self, kind: str):
        return self.client.get(reverse("billing:efactura_document_file", kwargs={"pk": self.document.pk, "kind": kind}))

    def _events(self) -> list[AuditEvent]:
        return list(AuditEvent.objects.filter(action="efactura_file_downloaded").order_by("timestamp"))

    def test_staff_downloads_the_stored_anaf_archive_and_xml(self) -> None:
        xml = self._get("xml")
        archive = self._get("archive")

        self.assertEqual(xml.status_code, 200)
        self.assertEqual(xml.content, XML.encode("utf-8"))
        self.assertEqual(xml["Content-Type"], "application/xml")
        self.assertEqual(xml["Content-Disposition"], 'attachment; filename="e_factura_INV-FILES-1.xml"')
        self.assertEqual(archive.status_code, 200)
        self.assertEqual(archive.content, ARCHIVE)
        self.assertEqual(archive["Content-Type"], "application/zip")
        for response in (xml, archive):
            self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertEqual([e.metadata["outcome"] for e in self._events()], ["served", "served"])

    def test_tampered_xml_file_is_refused_against_xml_hash(self) -> None:
        Path(self.document.xml_file.path).write_bytes(b"<Invoice>forged</Invoice>")

        response = self._get("xml")

        self.assertEqual(response.status_code, 409)
        self.assertNotIn(b"forged", response.content)
        self.assertEqual(self._events()[-1].metadata["outcome"], "integrity_failed")

    def test_tampered_archive_is_refused(self) -> None:
        Path(self.document.response_archive.path).write_bytes(b"tampered")

        response = self._get("archive")

        self.assertEqual(response.status_code, 409)
        self.assertNotIn(b"tampered", response.content)
        # A bad archive never blocks the XML.
        self.assertEqual(self._get("xml").status_code, 200)

    def test_xml_downloads_when_there_is_no_archive(self) -> None:
        EFacturaDocument.objects.filter(pk=self.document.pk).update(response_archive="", response_archive_sha256="")

        self.assertEqual(self._get("xml").status_code, 200)
        self.assertEqual(self._get("archive").status_code, 404)
        self.assertEqual(self._get("anything-else").status_code, 404)

    def test_missing_object_is_404_and_backend_error_is_503(self) -> None:
        # S3-shaped storage: no path() at all, so the view must read through the storage API.
        location = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, location, ignore_errors=True)
        storages = override_settings(
            STORAGES={
                "default": {"BACKEND": f"{media_contract.__name__}.PathlessStorage", "OPTIONS": {"location": location}},
                "staticfiles": settings.STORAGES["staticfiles"],
            }
        )
        storages.enable()
        self.addCleanup(storages.disable)
        self.document.xml_file.save("INV-FILES-1.xml", ContentFile(XML.encode("utf-8")))

        self.assertEqual(self._get("xml").status_code, 200)
        with patch.object(media_contract.PathlessStorage, "_open", side_effect=OSError("backend down")):
            self.assertEqual(self._get("xml").status_code, 503)
        self.document.xml_file.storage.delete(self.document.xml_file.name)
        self.assertEqual(self._get("xml").status_code, 404)
        self.assertEqual([e.metadata["outcome"] for e in self._events()], ["served", "unavailable", "missing"])

    def test_object_store_errors_are_404_or_503(self) -> None:
        # On MEDIA_STORAGE=s3 a read fails with botocore's errors, not OSError: a missing key is a
        # 404 response from the store, and a refused or unreachable store is anything else.
        def client_error(status: int) -> ClientError:
            return ClientError({"Error": {"Code": str(status)}, "ResponseMetadata": {"HTTPStatusCode": status}}, "GetObject")

        for error, expected in (
            (client_error(404), 404),
            (client_error(403), 503),
            (EndpointConnectionError(endpoint_url="https://objects.example.test"), 503),
        ):
            with self.subTest(error=type(error).__name__), patch.object(FileSystemStorage, "_open", side_effect=error):
                self.assertEqual(self._get("xml").status_code, expected)
        self.assertEqual([e.metadata["outcome"] for e in self._events()], ["missing", "unavailable", "unavailable"])

    def test_detail_page_links_both_verifiable_files(self) -> None:
        response = self.client.get(reverse("billing:efactura_document_detail", kwargs={"pk": self.document.pk}))

        for kind in ("xml", "archive"):
            url = reverse("billing:efactura_document_file", kwargs={"pk": self.document.pk, "kind": kind})
            self.assertContains(response, f'href="{url}"')
        self.assertNotContains(response, self.document.response_archive.name)

    def test_non_billing_staff_cannot_download_fiscal_files(self) -> None:
        support = User.objects.create_user(email="support-files@example.com", is_staff=True, staff_role="support")
        client = Client()
        client.force_login(support)

        response = client.get(reverse("billing:efactura_document_file", kwargs={"pk": self.document.pk, "kind": "xml"}))

        self.assertNotEqual(response.status_code, 200)
        self.assertNotIn(XML.encode("utf-8"), response.content)
        self.assertEqual(self._events(), [])

    def test_download_audit_payload_has_no_filename_or_contents(self) -> None:
        self._get("xml")

        (event,) = self._events()
        self.assertEqual(event.user, self.billing)
        self.assertEqual(event.metadata["document_id"], str(self.document.pk))
        self.assertEqual(event.metadata["invoice_id"], self.invoice.pk)
        self.assertEqual(event.metadata["file_kind"], "xml")
        stored = json.dumps([event.description, event.metadata, event.old_values, event.new_values])
        for leaked in ("INV-FILES-1.xml", "efactura/", "forged", "<Invoice"):
            self.assertNotIn(leaked, stored)
