from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import RequestFactory, SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.api_client.views import download_attachment


class DownloadAttachmentViewTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request(self):
        request = self.factory.get("/tickets/11/attachments/22/download/")
        request.session = {"customer_id": 1, "user_id": 2}
        return request

    @patch("apps.api_client.views.platform_api._make_binary_request_with_headers")
    def test_platform_404_becomes_generic_portal_404(self, mock_binary_request: MagicMock) -> None:
        platform_detail = "Storage object customers/1/private.pdf does not exist"
        mock_binary_request.side_effect = PlatformAPIError(platform_detail, status_code=404)

        response = download_attachment(self._request(), ticket_id=11, attachment_id=22)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"Attachment not found")
        self.assertNotIn(platform_detail.encode(), response.content)

    @patch("apps.api_client.views.platform_api._make_binary_request_with_headers")
    def test_platform_500_remains_generic_portal_500(self, mock_binary_request: MagicMock) -> None:
        mock_binary_request.side_effect = PlatformAPIError("Platform internal detail", status_code=500)

        with self.assertLogs("apps.api_client.views", level="ERROR"):
            response = download_attachment(self._request(), ticket_id=11, attachment_id=22)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content, b"Download failed")

    @patch("apps.api_client.views.platform_api._make_binary_request_with_headers")
    def test_unexpected_error_returns_500_with_traceback_log(self, mock_binary_request: MagicMock) -> None:
        mock_binary_request.side_effect = RuntimeError("unexpected failure")

        with self.assertLogs("apps.api_client.views", level="ERROR") as captured:
            response = download_attachment(self._request(), ticket_id=11, attachment_id=22)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content, b"Download failed")
        self.assertEqual(len(captured.records), 1)
        self.assertIsNotNone(captured.records[0].exc_info)

    @patch("apps.api_client.views.platform_api._make_binary_request_with_headers")
    def test_success_returns_bytes_and_content_disposition(self, mock_binary_request: MagicMock) -> None:
        mock_binary_request.return_value = (
            b"attachment bytes",
            {
                "Content-Type": "application/pdf",
                "Content-Disposition": 'attachment; filename="evidence.pdf"',
            },
        )

        response = download_attachment(self._request(), ticket_id=11, attachment_id=22)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"attachment bytes")
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="evidence.pdf"')
