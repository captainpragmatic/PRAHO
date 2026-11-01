"""Requesting an export from the dashboard downloads the file, instead of replacing the page with it.

The dashboard's export form posts with htmx (target body). The view answered with the JSON file itself: XHR ignores
Content-Disposition, so the whole page was replaced by raw JSON and nothing downloaded. Now htmx is sent to the
download URL, and the download is counted and audited there, on the GET that serves it.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import DataExport
from apps.common.types import Ok


class GdprExportDownloadTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(email="export-owner@example.com", password="pw-123456")
        self.client.force_login(self.user)
        self.export = DataExport.objects.create(
            requested_by=self.user,
            export_type="gdpr",
            scope={},
            status="completed",
            file_path="exports/ready.json",
            expires_at=timezone.now() + timedelta(days=7),
        )

    @patch("apps.audit.views.default_storage.exists", return_value=True)
    @patch("apps.audit.views.read_export_file", return_value='{"profile": {}}')
    @patch("apps.audit.views.gdpr_export_service")
    def test_htmx_is_sent_to_the_download_which_counts_once(self, service, _read, _exists) -> None:
        service.create_data_export_request.return_value = Ok(self.export)

        response = self.client.post(reverse("audit:request_data_export"), HTTP_HX_REQUEST="true")

        download = reverse("audit:download_data_export", args=[self.export.id])
        self.assertEqual(response["HX-Redirect"], download)
        self.assertNotIn(b'"profile"', response.content)
        self.export.refresh_from_db()
        self.assertEqual(self.export.download_count, 0)

        served = self.client.get(download)
        self.assertEqual(served.status_code, 200)
        self.assertIn("attachment", served["Content-Disposition"])
        self.export.refresh_from_db()
        self.assertEqual(self.export.download_count, 1)
