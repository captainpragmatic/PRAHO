"""GDPR export files are deleted when their download window closes and when the person is erased.

An export file holds a person's data. apps.audit.tasks.delete_expired_data_exports deletes the files
of expired exports daily; erasure (anonymise or delete) closes the person's exports in its own
transaction and deletes their files after it commits. Every path deletes the file first and then
blanks the row's path only if it still points at that file, and keeps the row as the record.
These tests use a temporary MEDIA_ROOT and real storage.
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.export_files import untrack_export_file
from apps.audit.models import DataExport
from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.audit.tasks import delete_expired_data_exports
from apps.customers.models import Customer
from apps.promotions.models import TenderRefundCommand
from tests.billing import _fiscal_correction_helpers as h

User = get_user_model()
PASSWORD = "lifecycle-pass-123"


class ExportLifecycleTestCase(TestCase):
    def setUp(self) -> None:
        media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        settings_override = override_settings(MEDIA_ROOT=media)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.media = Path(media)
        self.user = User.objects.create_user(email="lifecycle@example.test", password=PASSWORD)

    def completed_export(self, user: object | None = None) -> DataExport:
        export = GDPRExportService.create_data_export_request(user or self.user).unwrap()
        self.assertTrue(GDPRExportService.process_data_export(export).is_ok())
        export.refresh_from_db()
        self.assertTrue(self.on_disk(export.file_path))
        return export

    def expire(self, export: DataExport) -> None:
        DataExport.objects.filter(pk=export.pk).update(expires_at=timezone.now() - timedelta(minutes=1))

    def on_disk(self, path: str) -> bool:
        return (self.media / path).exists()


class ExpiredExportCleanupTests(ExportLifecycleTestCase):
    def test_expired_files_are_deleted_and_their_rows_kept(self) -> None:
        expired = self.completed_export()
        current = self.completed_export()
        self.expire(expired)
        expired_path = expired.file_path

        self.assertEqual(delete_expired_data_exports(), {"deleted": 1, "failed": 0})

        self.assertFalse(self.on_disk(expired_path))
        expired.refresh_from_db()
        self.assertEqual(expired.file_path, "")
        self.assertEqual(expired.status, "completed")
        self.assertTrue(self.on_disk(current.file_path))
        self.assertEqual(delete_expired_data_exports(), {"deleted": 0, "failed": 0})

    def test_a_file_already_gone_still_untracks_the_row(self) -> None:
        export = self.completed_export()
        self.expire(export)
        (self.media / export.file_path).unlink()

        self.assertEqual(delete_expired_data_exports()["deleted"], 1)

        export.refresh_from_db()
        self.assertEqual(export.file_path, "")

    def test_a_failed_delete_keeps_the_path_for_the_next_run(self) -> None:
        export = self.completed_export()
        self.expire(export)

        with patch("apps.audit.export_files.default_storage.delete", side_effect=OSError("disk busy")):
            self.assertEqual(delete_expired_data_exports(), {"deleted": 0, "failed": 1})

        export.refresh_from_db()
        self.assertTrue(export.file_path)
        self.assertTrue(self.on_disk(export.file_path))

    def test_a_path_rewritten_meanwhile_is_not_untracked(self) -> None:
        export = self.completed_export()
        self.expire(export)
        stale_path = export.file_path
        DataExport.objects.filter(pk=export.pk).update(file_path="gdpr_exports/rewritten.enc")

        self.assertFalse(untrack_export_file(export.pk, stale_path))

        export.refresh_from_db()
        self.assertEqual(export.file_path, "gdpr_exports/rewritten.enc")
        self.assertTrue(self.on_disk(stale_path), "a file the row no longer tracks is not this call's to delete")


    def test_an_export_regenerated_at_the_same_path_is_not_untracked(self) -> None:
        # Regeneration reuses the deterministic path with a fresh window; the new file is kept.
        export = self.completed_export()

        self.assertFalse(untrack_export_file(export.pk, export.file_path))

        self.assertTrue(self.on_disk(export.file_path))
        export.refresh_from_db()
        self.assertTrue(export.file_path)


class ErasureDeletesExportFilesTests(ExportLifecycleTestCase):
    def erase(self, deletion_type: str) -> object:
        request = GDPRDeletionService.create_deletion_request(user=self.user, deletion_type=deletion_type).unwrap()
        return GDPRDeletionService.process_deletion_request(request)

    def test_anonymisation_deletes_the_files_only_after_it_commits(self) -> None:
        export = self.completed_export()
        pending = GDPRExportService.create_data_export_request(self.user).unwrap()
        path = export.file_path

        with self.captureOnCommitCallbacks() as callbacks:
            self.assertTrue(self.erase("anonymize").is_ok())
            self.assertTrue(self.on_disk(path), "a file must outlive the erasure until it commits")
        self.assertTrue(callbacks)
        for callback in callbacks:
            callback()

        self.assertFalse(self.on_disk(path))
        export.refresh_from_db()
        self.assertEqual(export.file_path, "")
        self.assertLessEqual(export.expires_at, timezone.now())
        pending.refresh_from_db()
        self.assertEqual(pending.status, "failed")

    def test_a_user_instance_loaded_before_the_erasure_cannot_request_an_export(self) -> None:
        stale = User.objects.get(pk=self.user.pk)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(self.erase("anonymize").is_ok())
        before = DataExport.objects.count()

        self.assertTrue(GDPRExportService.create_data_export_request(stale).is_err())

        self.assertEqual(DataExport.objects.count(), before)

    def test_an_erased_person_cannot_request_or_receive_an_export(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(self.erase("anonymize").is_ok())
        self.user.refresh_from_db()

        self.assertTrue(GDPRExportService.create_data_export_request(self.user).is_err())
        # A request that slipped in alongside the erasure is refused when processed.
        late = DataExport.objects.create(
            requested_by=self.user, export_type="gdpr", scope={}, status="pending",
            expires_at=timezone.now() + timedelta(days=7),
        )
        self.assertTrue(GDPRExportService.process_data_export(late).is_err())
        late.refresh_from_db()
        self.assertEqual((late.status, late.file_path), ("failed", ""))
        self.assertFalse((self.media / "gdpr_exports").exists() and any((self.media / "gdpr_exports").iterdir()))

    def test_full_deletion_deletes_the_files_and_keeps_the_rows(self) -> None:
        export = self.completed_export()
        path = export.file_path

        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(self.erase("delete").is_ok())

        self.assertFalse(self.on_disk(path))
        export.refresh_from_db()
        self.assertIsNone(export.requested_by)
        self.assertEqual(export.file_path, "")

    def test_a_full_deletion_refused_part_way_changes_nothing(self) -> None:
        export = self.completed_export()
        path = export.file_path
        expires_at = export.expires_at
        customer = Customer.objects.create(name="Protects the user", status="active", primary_email="p@example.test")
        TenderRefundCommand.objects.create(
            invoice=h.issued_invoice(customer, issue=False),
            customer=customer,
            amount_cents=100,
            operation_key="lifecycle-protected-user",
            reason="A refund this user requested keeps the user",
            created_by=self.user,
        )

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            self.assertTrue(self.erase("delete").is_err())

        self.assertEqual(callbacks, [])
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        self.assertTrue(self.on_disk(path))
        export.refresh_from_db()
        self.assertEqual((export.file_path, export.expires_at), (path, expires_at))


class StaffAndDashboardTests(ExportLifecycleTestCase):
    def test_staff_delete_of_an_expired_export_deletes_the_file_and_keeps_the_row(self) -> None:
        export = self.completed_export()
        self.expire(export)
        path = export.file_path
        staff = User.objects.create_user(email="lifecycle-staff@example.test", password=PASSWORD, is_staff=True, staff_role="admin")
        self.client.force_login(staff)

        self.client.post(reverse("audit:process_export_request", args=[export.id]), {"action": "delete_expired"})

        self.assertFalse(self.on_disk(path))
        export.refresh_from_db()
        self.assertEqual(export.file_path, "")

    def test_the_dashboard_offers_only_downloadable_exports(self) -> None:
        current = self.completed_export()
        expired = self.completed_export()
        self.expire(expired)
        self.client.login(email="lifecycle@example.test", password=PASSWORD)

        content = self.client.get(reverse("audit:gdpr_dashboard")).content.decode()

        self.assertIn(reverse("audit:download_data_export", kwargs={"export_id": current.id}), content)
        self.assertNotIn(reverse("audit:download_data_export", kwargs={"export_id": expired.id}), content)
