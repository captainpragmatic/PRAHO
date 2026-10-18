"""Two downloads of one GDPR export at once both count.

The staff views read the count, added one and saved it, so two overlapping downloads both wrote the
same number and one was lost from the count the audit evidence carries. They now increment in the
database, as the API does.
"""

from __future__ import annotations

import tempfile
import threading
from datetime import timedelta
from unittest.mock import patch

from django.db import connection
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.export_files import read_export_file, write_export_file
from apps.audit.models import ComplianceLog, DataExport
from apps.users.models import User


class StaffExportDownloadCountTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("overlapping downloads need PostgreSQL's concurrent sessions; SQLite serialises them")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        media = override_settings(MEDIA_ROOT=directory.name)
        media.enable()
        self.addCleanup(media.disable)
        self.user = User.objects.create_user(email="counter@example.test", password="Counter-secure123!")
        self.export = DataExport.objects.create(
            requested_by=self.user,
            export_type="gdpr",
            status="completed",
            expires_at=timezone.now() + timedelta(days=7),
        )
        self.export.file_path = write_export_file(self.export, "{}")
        self.export.save(update_fields=["file_path"])

    def test_staff_export_download_count_has_no_lost_update(self) -> None:
        both_read = threading.Barrier(2, timeout=10)
        statuses: list[int] = []

        def read_then_wait(export: DataExport) -> str:
            content = read_export_file(export)
            both_read.wait()  # Each request has loaded the row before either records its download
            return content

        def download() -> None:
            try:
                client = Client()
                client.force_login(self.user)
                response = client.get(reverse("audit:download_data_export", args=[self.export.id]))
                statuses.append(response.status_code)
            finally:
                connection.close()

        # Patched once, outside the workers: a patch entered per thread races with the other's exit.
        with patch("apps.audit.views.read_export_file", side_effect=read_then_wait):
            workers = [threading.Thread(target=download) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=30)

        self.assertEqual(statuses, [200, 200])
        self.export.refresh_from_db()
        self.assertEqual(self.export.download_count, 2)
        counts = sorted(
            ComplianceLog.objects.filter(reference_id=f"export_download_{self.export.id}").values_list(
                "evidence__download_count", flat=True
            )
        )
        self.assertEqual(counts, [1, 2], "each download's evidence records its own count")
