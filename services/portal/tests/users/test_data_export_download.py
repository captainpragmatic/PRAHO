"""The portal lets a signed-in customer download their own GDPR export.

The page promised an email that never existed, and an export requested here was never generated.
Platform now generates it and serves it through a signed endpoint; the portal relays the file for
the session's own user, uncached, and keeps nothing.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse

from apps.api_client.services import PlatformAPIError

EXPORT_ID = uuid.uuid4()


class DataExportDownloadTests(TestCase):
    def sign_in(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["email"] = "customer@example.test"
        session.save()

    def test_a_signed_out_visitor_is_sent_to_login(self) -> None:
        response = self.client.get(reverse("users:data_export_download", args=[EXPORT_ID]))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

    @patch("apps.users.views.api_client.download_data_export", return_value=b'{"user_profile": {"email": "x"}}')
    def test_the_file_is_relayed_for_the_session_user_uncached(self, download: MagicMock) -> None:
        self.sign_in()

        response = self.client.get(reverse("users:data_export_download", args=[EXPORT_ID]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'{"user_profile": {"email": "x"}}')
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn(f'filename="gdpr-export-{EXPORT_ID}.json"', response["Content-Disposition"])
        args, _kwargs = download.call_args
        self.assertEqual(args, (2, str(EXPORT_ID)))

    @patch(
        "apps.users.views.api_client.download_data_export",
        side_effect=PlatformAPIError("Binary API request failed: Export not available", status_code=404),
    )
    def test_an_unavailable_export_returns_to_the_page_with_a_message(self, _download: MagicMock) -> None:
        self.sign_in()

        response = self.client.get(reverse("users:data_export_download", args=[EXPORT_ID]))

        self.assertRedirects(response, reverse("users:data_export"), fetch_redirect_response=False)
        text = " ".join(str(m) for m in get_messages(response.wsgi_request))
        self.assertIn("not available to download", text)

    @patch(
        "apps.users.views.api_client.download_data_export",
        side_effect=PlatformAPIError("Platform service timeout", is_unavailable=True),
    )
    def test_an_outage_is_not_reported_as_an_unavailable_export(self, _download: MagicMock) -> None:
        self.sign_in()

        response = self.client.get(reverse("users:data_export_download", args=[EXPORT_ID]))

        self.assertRedirects(response, reverse("users:data_export"), fetch_redirect_response=False)
        text = " ".join(str(m) for m in get_messages(response.wsgi_request))
        self.assertIn("temporarily unavailable", text)
        self.assertNotIn("Request a new one", text)

    @patch(
        "apps.users.views.api_client.download_data_export",
        side_effect=PlatformAPIError("Binary API request failed: too large", status_code=413),
    )
    def test_an_export_too_large_to_relay_says_so(self, _download: MagicMock) -> None:
        self.sign_in()

        response = self.client.get(reverse("users:data_export_download", args=[EXPORT_ID]))

        self.assertRedirects(response, reverse("users:data_export"), fetch_redirect_response=False)
        text = " ".join(str(m) for m in get_messages(response.wsgi_request))
        self.assertIn("too large to download here", text)
        self.assertNotIn("Request a new one", text)

    @patch("apps.users.views.api_client.get_data_export_status")
    def test_a_too_large_export_points_to_support_instead_of_a_button(self, status: MagicMock) -> None:
        large = uuid.uuid4()
        status.return_value = {
            "success": True,
            "exports": [
                {"id": str(large), "status": "completed", "downloadable": False, "too_large": True,
                 "requested_at": "2026-10-12T10:00:00", "completed_at": "2026-10-12T10:01:00",
                 "expires_at": "2026-10-19T10:01:00", "file_size": 30 * 1024 * 1024, "record_count": 7},
            ],
        }
        self.sign_in()

        content = self.client.get(reverse("users:data_export")).content.decode()

        self.assertNotIn(reverse("users:data_export_download", args=[large]), content)
        self.assertIn("too large to download here", content)

    @patch("apps.users.views.api_client.get_data_export_status")
    def test_only_downloadable_exports_get_a_download_button(self, status: MagicMock) -> None:
        ready, expired = uuid.uuid4(), uuid.uuid4()
        status.return_value = {
            "success": True,
            "exports": [
                {"id": str(ready), "status": "completed", "downloadable": True, "requested_at": "2026-10-12T10:00:00",
                 "completed_at": "2026-10-12T10:01:00", "expires_at": "2026-10-19T10:01:00", "file_size": 2048,
                 "record_count": 7},
                {"id": str(expired), "status": "completed", "downloadable": False, "requested_at": "2026-09-01T10:00:00",
                 "completed_at": "2026-09-01T10:01:00", "expires_at": "2026-09-08T10:01:00", "file_size": 2048,
                 "record_count": 7},
            ],
        }
        self.sign_in()

        content = self.client.get(reverse("users:data_export")).content.decode()

        self.assertIn(reverse("users:data_export_download", args=[ready]), content)
        self.assertNotIn(reverse("users:data_export_download", args=[expired]), content)
        self.assertNotIn("email", content.split("Export Process")[1].split("</ul>")[0])

    @patch("apps.users.views.api_client.request_data_export_secure", return_value={"success": True, "export_id": "x"})
    def test_a_request_says_where_to_find_the_export_not_an_email(self, request_export: MagicMock) -> None:
        self.sign_in()

        response = self.client.post(reverse("users:data_export"))

        self.assertRedirects(response, reverse("users:data_export"), fetch_redirect_response=False)
        text = " ".join(str(m) for m in get_messages(response.wsgi_request))
        self.assertIn("Refresh this page", text)
        self.assertNotIn("email", text)
        self.assertIn("ip_address", request_export.call_args.kwargs)
