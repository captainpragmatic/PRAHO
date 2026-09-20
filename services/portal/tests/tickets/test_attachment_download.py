"""Portal attachment proxy keeps identity server-side and preserves file bytes."""

from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.tickets.views import ticket_attachment_download, ticket_reply
from tests.dashboard.test_rate_limit_dashboard import _authenticated_request


class AttachmentDownloadContracts(SimpleTestCase):
    def test_download_uses_session_identity_and_binary_response(self):
        request = _authenticated_request("/tickets/2/attachments/3/download/?customer_id=999&user_id=999")
        with patch(
            "apps.tickets.views.tickets_api.download_ticket_attachment",
            return_value=(
                b"File bytes",
                {
                    "Content-Type": "text/plain",
                    "Content-Disposition": 'attachment; filename="diagnostics.txt"',
                },
            ),
        ) as download:
            response = ticket_attachment_download(request, 2, 3)
        download.assert_called_once_with("1", 1, 2, 3)
        self.assertEqual(response.content, b"File bytes")
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")

    def test_denied_and_missing_downloads_never_return_success_or_data(self):

        for status in (403, 404):
            with (
                patch(
                    "apps.tickets.views.tickets_api.download_ticket_attachment",
                    side_effect=PlatformAPIError("Denied", status_code=status),
                ),
                self.assertRaises(Http404),
            ):
                ticket_attachment_download(_authenticated_request(), 2, 3)
        request = _authenticated_request()
        request.session.clear()
        request.customer_id = None
        with patch("apps.tickets.views.tickets_api.download_ticket_attachment") as download:
            self.assertEqual(ticket_attachment_download(request, 2, 3).status_code, 302)
        download.assert_not_called()

    def test_oversized_upload_is_rejected_before_read_or_api_call(self):
        file = SimpleUploadedFile("large.txt", b"x" * (1024 * 1024 + 1))
        request = RequestFactory().post("/tickets/2/reply/", {"message": "Diagnostic", "attachments": file})
        authenticated = _authenticated_request()
        request.session = authenticated.session
        request._messages = authenticated._messages
        with patch("apps.tickets.views.tickets_api.add_ticket_reply") as reply:
            response = ticket_reply(request, 2)
        self.assertEqual(response.status_code, 302)
        reply.assert_not_called()
