"""A saved reply must not be offered for submission again after a refresh outage."""

from __future__ import annotations

import re
import time
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "reply-refresh-outage",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class ReplyRefreshOutageTests(SimpleTestCase):
    def test_saved_reply_is_cleared_and_acknowledged_when_refresh_fails(self) -> None:
        for error in (
            PlatformAPIError("offline", is_unavailable=True),
            PlatformAPIError("maintenance", status_code=503, response_data={"error": "maintenance"}),
            PlatformAPIError("rate limited", status_code=429, retry_after=60),
        ):
            with self.subTest(error=error):
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
                message = "This reply has already been saved."
                with (
                    patch("apps.tickets.views.tickets_api.add_ticket_reply", return_value={"success": True}) as write,
                    patch("apps.tickets.views.tickets_api.get_ticket_detail", side_effect=error),
                ):
                    response = client.post(
                        reverse("tickets:reply", args=[3]),
                        {"message": message},
                        headers={"HX-Request": "true"},
                    )

                self.assertNotContains(response, message)
                fields = re.findall(
                    r'<textarea\b[^>]*name="message"[^>]*>(.*?)</textarea>',
                    response.content.decode(),
                    flags=re.DOTALL,
                )
                self.assertEqual([field.strip() for field in fields], [""])
                self.assertContains(response, "Reply added successfully.")
                self.assertContains(response, "Your reply was sent, but the thread could not refresh.")
                self.assertContains(response, 'href="' + reverse("tickets:detail", args=[3]) + '"')
                write.assert_called_once_with(
                    customer_id=123,
                    user_id=456,
                    ticket_id=3,
                    message=message,
                    attachments=None,
                )
