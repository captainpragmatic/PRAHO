"""A reply the Platform refuses for a file shows the reason, not an outage."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "reply-refusal"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class ReplyAttachmentRefusalTests(SimpleTestCase):
    def _client(self) -> Client:
        cache.clear()
        client = Client(raise_request_exception=False)
        session = client.session
        session.update(
            {
                "user_id": 456,
                "customer_id": 123,
                "selected_customer_id": 123,
                "user_memberships": [{"customer_id": 123, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()
        return client

    def _post(self, client: Client, error: PlatformAPIError) -> HttpResponse:
        with patch("apps.tickets.views.tickets_api.add_ticket_reply", side_effect=error):
            return client.post(
                reverse("tickets:reply", args=[3]),
                {"message": "Logs attached", "attachments": SimpleUploadedFile("invoice.pdf", b"not a pdf")},
                headers={"HX-Request": "true"},
            )

    def test_portal_shows_the_refused_files_reason_not_an_outage(self) -> None:
        refusal = PlatformAPIError(
            "API request failed",
            status_code=400,
            response_data={"success": False, "errors": {"attachments": ["The file is not a PDF document."]}},
        )

        response = self._post(self._client(), refusal)

        self.assertEqual(response.status_code, 400)
        error = json.loads(response.content)["error"]
        self.assertIn("The file is not a PDF document.", error)
        self.assertNotIn("try again later", error)

    def test_another_platform_failure_is_still_reported_as_one(self) -> None:
        failure = PlatformAPIError("API request failed", status_code=500, response_data={"error": "boom"})

        response = self._post(self._client(), failure)

        self.assertEqual(response.status_code, 500)
        self.assertIn("try again later", json.loads(response.content)["error"])
