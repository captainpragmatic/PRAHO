"""A GDPR export requested through the portal is generated and downloadable.

The portal's request used to create a pending export that nothing ever processed, while the page
promised an email that does not exist. Requests are now queued (with a sweeper for anything left
pending), a repeat request returns the existing export, and the signed download endpoint returns
the decrypted file of the person's own export only.
"""

from __future__ import annotations

import shutil
import tempfile
import time
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import Resolver404, resolve
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.gdpr.views import EXPORT_API_MAX_BYTES, data_export_api, data_export_download_api
from apps.audit.models import ComplianceLog, DataExport
from apps.audit.services import GDPRExportService
from apps.audit.tasks import process_data_export_task, process_pending_data_exports
from tests.factories.core_factories import UserCreationRequest, create_user


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class ExportDeliveryTestCase(TestCase):
    def setUp(self) -> None:
        media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        settings_override = override_settings(MEDIA_ROOT=media)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.media = Path(media)
        self.factory = APIRequestFactory()
        self.user = create_user(UserCreationRequest(username="exporter", email="exporter@example.test"))

    def signed(self, path: str, data: dict[str, object]) -> object:
        request = self.factory.post(path, data={**data, "timestamp": time.time()}, format="json")
        request._portal_authenticated = True
        return request

    def request_export(self, user_id: int | None = None) -> object:
        return data_export_api(
            self.signed("/api/gdpr/data-export/", {"user_id": user_id or self.user.id, "action": "request"})
        )

    def download(self, export_id: uuid.UUID, user_id: int | None = None) -> object:
        path = f"/api/gdpr/data-export/{export_id}/download/"
        return data_export_download_api(self.signed(path, {"user_id": user_id or self.user.id}), export_id=export_id)

    def completed_export(self) -> DataExport:
        export = GDPRExportService.create_data_export_request(self.user).unwrap()
        self.assertTrue(GDPRExportService.process_data_export(export).is_ok())
        export.refresh_from_db()
        return export


class ExportRequestTests(ExportDeliveryTestCase):
    def test_a_request_is_queued_for_generation_after_commit(self) -> None:
        with patch("apps.api.gdpr.views.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            response = self.request_export()

        self.assertEqual(response.status_code, 200)
        export = DataExport.objects.get(requested_by=self.user)
        enqueue.assert_called_once_with("apps.audit.tasks.process_data_export_task", str(export.id))
        self.assertEqual(response.data["status"], "pending")

    def test_a_repeat_request_returns_the_existing_export(self) -> None:
        with patch("apps.api.gdpr.views.async_task"), self.captureOnCommitCallbacks(execute=True):
            first = self.request_export()
            second = self.request_export()

        self.assertEqual(first.data["export_id"], second.data["export_id"])
        self.assertEqual(DataExport.objects.filter(requested_by=self.user).count(), 1)

    def test_a_repeat_request_is_not_queued_again(self) -> None:
        with patch("apps.api.gdpr.views.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            self.request_export()
            self.request_export()

        enqueue.assert_called_once()

    def test_the_queued_task_generates_the_export(self) -> None:
        export = GDPRExportService.create_data_export_request(self.user).unwrap()

        self.assertEqual(process_data_export_task(str(export.id)), "completed")

        export.refresh_from_db()
        self.assertTrue(export.is_downloadable)

    def test_the_sweeper_generates_exports_left_pending(self) -> None:
        stale = GDPRExportService.create_data_export_request(self.user).unwrap()
        DataExport.objects.filter(pk=stale.pk).update(requested_at=timezone.now() - timedelta(minutes=30))
        other = create_user(UserCreationRequest(username="fresh", email="fresh@example.test"))
        fresh = GDPRExportService.create_data_export_request(other).unwrap()

        self.assertEqual(process_pending_data_exports(), {"completed": 1, "failed": 0})

        stale.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual((stale.status, fresh.status), ("completed", "pending"))

    def test_the_status_says_which_exports_can_be_downloaded(self) -> None:
        export = self.completed_export()

        [entry] = GDPRExportService.get_user_exports(self.user)

        self.assertEqual(entry["id"], str(export.id))
        self.assertTrue(entry["downloadable"])


class ExportDownloadTests(ExportDeliveryTestCase):
    def test_the_owner_gets_the_decrypted_file_uncached_and_it_is_counted(self) -> None:
        export = self.completed_export()

        response = self.download(export.id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn(b"exporter@example.test", response.content)
        export.refresh_from_db()
        self.assertEqual(export.download_count, 1)
        self.assertTrue(ComplianceLog.objects.filter(reference_id=f"export_download_{export.id}").exists())

    def test_another_person_cannot_download_it(self) -> None:
        export = self.completed_export()
        other = create_user(UserCreationRequest(username="other", email="other@example.test"))

        response = self.download(export.id, user_id=other.id)

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("exporter@example.test", str(response.data))

    def test_an_inactive_person_cannot_download(self) -> None:
        export = self.completed_export()
        type(self.user).objects.filter(pk=self.user.pk).update(is_active=False)

        self.assertEqual(self.download(export.id).status_code, 403)

    def test_expired_missing_or_unreadable_files_are_refused_and_not_counted(self) -> None:
        expired = self.completed_export()
        DataExport.objects.filter(pk=expired.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.download(expired.id).status_code, 404)

        for damage in ("delete", "corrupt"):
            export = self.completed_export()
            with self.subTest(damage=damage):
                path = self.media / export.file_path
                if damage == "delete":
                    path.unlink()
                else:
                    path.write_bytes(b"not ciphertext")
                self.assertEqual(self.download(export.id).status_code, 404)
                export.refresh_from_db()
                self.assertEqual(export.download_count, 0)
            DataExport.objects.filter(pk=export.pk).update(status="failed")

    def test_a_broken_export_makes_way_for_a_new_request(self) -> None:
        export = self.completed_export()
        (self.media / export.file_path).unlink()

        self.assertEqual(self.download(export.id).status_code, 404)

        export.refresh_from_db()
        self.assertEqual(export.status, "failed")
        with patch("apps.api.gdpr.views.async_task"), self.captureOnCommitCallbacks(execute=True):
            response = self.request_export()
        self.assertNotEqual(response.data["export_id"], str(export.id))

    def test_an_export_too_large_for_the_portal_is_refused_and_not_offered(self) -> None:
        export = self.completed_export()
        DataExport.objects.filter(pk=export.pk).update(file_size=EXPORT_API_MAX_BYTES + 1)

        self.assertEqual(self.download(export.id).status_code, 413)
        status = data_export_api(self.signed("/api/gdpr/data-export/", {"user_id": self.user.id, "action": "status"}))
        [entry] = status.data["exports"]
        self.assertEqual((entry["downloadable"], entry["too_large"]), (False, True))

    def test_only_a_uuid_reaches_the_endpoint(self) -> None:
        with self.assertRaises(Resolver404):
            resolve("/api/gdpr/data-export/not-a-uuid/download/")
