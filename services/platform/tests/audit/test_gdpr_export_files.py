"""GDPR export files are encrypted at rest, bound to their export, and read only through that binding.

From media, an export file reaches every backup and the staff network's direct /media route.
apps.audit.export_files stores AES-256-GCM v2 ciphertext whose AAD names the export, and reads
with that AAD: anything else is refused, never served (ADR-0040). These tests use a temporary
MEDIA_ROOT and real storage, so what they check is what lands on disk.
"""

from __future__ import annotations

import base64
import json
import shutil
import struct
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.audit.export_files import read_export_file
from apps.audit.models import AuditEvent, ComplianceLog, DataExport
from apps.audit.services import EXPORT_DOWNLOAD_DAYS, GDPRExportService
from apps.common.encryption import VERSIONED_V1_PREFIX, VERSIONED_V2_PREFIX, DecryptionError

User = get_user_model()
EMAIL = "export-subject@example.test"
PASSWORD = "export-pass-123"


class ExportFileTestCase(TestCase):
    def setUp(self) -> None:
        media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        settings_override = override_settings(MEDIA_ROOT=media)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.media = Path(media)
        self.user = User.objects.create_user(email=EMAIL, password=PASSWORD, first_name="Exportina")

    def completed_export(self) -> DataExport:
        export = GDPRExportService.create_data_export_request(self.user).unwrap()
        result = GDPRExportService.process_data_export(export)
        self.assertTrue(result.is_ok(), result)
        export.refresh_from_db()
        return export

    def stored_bytes(self, export: DataExport) -> bytes:
        return (self.media / export.file_path).read_bytes()

    def overwrite(self, export: DataExport, content: bytes) -> None:
        (self.media / export.file_path).write_bytes(content)


class ExportFileAtRestTests(ExportFileTestCase):
    def test_the_file_on_disk_is_ciphertext_named_after_the_export(self) -> None:
        export = self.completed_export()

        raw = self.stored_bytes(export)
        self.assertTrue(raw.startswith(VERSIONED_V2_PREFIX.encode()))
        self.assertNotIn(EMAIL.encode(), raw)
        self.assertNotIn(b"Exportina", raw)
        self.assertEqual(export.file_path, f"gdpr_exports/{export.id}.enc")

    def test_the_export_reads_back_through_its_binding(self) -> None:
        export = self.completed_export()

        data = json.loads(read_export_file(export))

        self.assertEqual(data["user_profile"]["email"], EMAIL)

    def test_the_download_window_starts_at_completion(self) -> None:
        export = self.completed_export()

        assert export.completed_at is not None
        self.assertEqual(export.expires_at, export.completed_at + timedelta(days=EXPORT_DOWNLOAD_DAYS))


class ExportFileRefusalTests(ExportFileTestCase):
    def test_a_file_copied_from_another_export_is_refused(self) -> None:
        first = self.completed_export()
        second = self.completed_export()
        self.overwrite(second, self.stored_bytes(first))

        with self.assertRaises(DecryptionError):
            read_export_file(second)

    def test_plaintext_empty_and_undecodable_files_are_refused(self) -> None:
        export = self.completed_export()
        for content in (json.dumps({"user_profile": {"email": EMAIL}}).encode(), b"", b"\xff\xfe"):
            with self.subTest(content=content[:20]):
                self.overwrite(export, content)
                with self.assertRaises(DecryptionError):
                    read_export_file(export)

    def test_ciphertext_repackaged_without_its_binding_is_refused(self) -> None:
        export = self.completed_export()
        raw = base64.urlsafe_b64decode(self.stored_bytes(export)[len(VERSIONED_V2_PREFIX) :])
        aad_length = struct.unpack("!H", raw[:2])[0]
        unbound = VERSIONED_V1_PREFIX + base64.urlsafe_b64encode(raw[2 + aad_length :]).decode("ascii")
        self.overwrite(export, unbound.encode("ascii"))

        with self.assertRaises(DecryptionError):
            read_export_file(export)


class ExportFileOwnershipTests(ExportFileTestCase):
    def test_a_completed_export_is_not_processed_again(self) -> None:
        export = self.completed_export()
        before = sorted(p.name for p in (self.media / "gdpr_exports").iterdir())

        result = GDPRExportService.process_data_export(export)

        self.assertTrue(result.is_err())
        self.assertEqual(sorted(p.name for p in (self.media / "gdpr_exports").iterdir()), before)
        export.refresh_from_db()
        self.assertEqual(export.status, "completed")

    def test_a_failure_after_the_write_deletes_the_file(self) -> None:
        export = GDPRExportService.create_data_export_request(self.user).unwrap()

        with patch(
            "apps.audit.services.AuditService.log_compliance_event", side_effect=DatabaseError("audit store down")
        ):
            result = GDPRExportService.process_data_export(export)

        self.assertTrue(result.is_err())
        export.refresh_from_db()
        self.assertEqual(export.status, "failed")
        self.assertEqual(export.file_path, "")
        self.assertEqual(list((self.media / "gdpr_exports").iterdir()), [])


class ExportDownloadTests(ExportFileTestCase):
    def test_the_owner_downloads_the_decrypted_export_uncached(self) -> None:
        export = self.completed_export()
        self.client.login(email=EMAIL, password=PASSWORD)

        response = self.client.get(reverse("audit:download_data_export", args=[export.id]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(json.loads(response.content)["user_profile"]["email"], EMAIL)

    def test_a_file_that_is_not_this_export_s_ciphertext_is_not_served(self) -> None:
        first = self.completed_export()
        second = self.completed_export()
        self.overwrite(second, self.stored_bytes(first))
        self.client.login(email=EMAIL, password=PASSWORD)

        response = self.client.get(reverse("audit:download_data_export", args=[second.id]))

        self.assertRedirects(response, reverse("audit:gdpr_dashboard"))
        second.refresh_from_db()
        self.assertEqual(second.download_count, 0)
        self.assertFalse(
            ComplianceLog.objects.filter(reference_id=f"export_download_{second.id}").exists(),
            "a refused file must not be recorded as downloaded",
        )

    def test_staff_are_not_recorded_as_downloading_a_refused_file(self) -> None:
        first = self.completed_export()
        second = self.completed_export()
        self.overwrite(second, self.stored_bytes(first))
        staff = User.objects.create_user(
            email="export-staff@example.test", password=PASSWORD, is_staff=True, staff_role="admin"
        )
        self.client.force_login(staff)

        response = self.client.get(reverse("audit:download_user_export", args=[second.id]))

        self.assertRedirects(response, reverse("audit:gdpr_management_dashboard"))
        self.assertFalse(AuditEvent.objects.filter(action="access", object_id=str(second.id)).exists())
