"""Requesting an export from the dashboard reloads the dashboard, with the ready export offered for download.

The dashboard's export form posts with htmx (target body). The view answered with the JSON file itself: XHR ignores
Content-Disposition, so the whole page was replaced by raw JSON and nothing downloaded. Sending htmx straight to the
download instead left the page as it was: the browser saved the file, but the modal stayed open with its spinner and
the new export wasn't listed. Now htmx reloads the dashboard, which lists the export with its Download link; the
download is counted and audited on the GET that serves it.
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
    def test_htmx_reloads_the_dashboard_which_offers_the_download_counted_once(self, service, _read, _exists) -> None:
        service.create_data_export_request.return_value = Ok(self.export)

        response = self.client.post(reverse("audit:request_data_export"), HTTP_HX_REQUEST="true")

        self.assertEqual(response["HX-Redirect"], reverse("audit:gdpr_dashboard"))
        self.assertNotIn(b'"profile"', response.content)
        download = reverse("audit:download_data_export", args=[self.export.id])
        dashboard = self.client.get(reverse("audit:gdpr_dashboard")).content.decode()
        self.assertIn(download, dashboard)
        self.assertIn("Your export is ready. Download it from Recent Data Exports below.", dashboard)
        self.export.refresh_from_db()
        self.assertEqual(self.export.download_count, 0)

        served = self.client.get(download)
        self.assertEqual(served.status_code, 200)
        self.assertIn("attachment", served["Content-Disposition"])
        self.export.refresh_from_db()
        self.assertEqual(self.export.download_count, 1)
