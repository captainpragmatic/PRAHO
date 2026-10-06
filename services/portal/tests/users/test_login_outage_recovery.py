"""An outage login page must have a safe recovery action."""

from __future__ import annotations

import html
import re
from unittest.mock import patch

from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError


@override_settings(
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class LoginOutageRecoveryTests(SimpleTestCase):
    def test_outage_offers_enabled_get_retry_without_preserving_password(self) -> None:
        for error in (
            PlatformAPIError("offline", is_unavailable=True),
            PlatformAPIError("maintenance", status_code=503, response_data={"error": "maintenance"}),
        ):
            with self.subTest(error=error):
                client = Client()
                with patch("apps.users.views.api_client.authenticate_customer", side_effect=error):
                    response = client.post(
                        "/login/?next=%2Ftickets%2F3%2F",
                        {"email": "someone@example.com", "password": "correct-horse"},
                    )

                body = response.content.decode()
                retry = re.search(r'<a\b[^>]*data-login-retry="true"[^>]*>', body)
                self.assertIsNotNone(retry, "The outage page must offer an enabled GET retry.")
                assert retry is not None
                self.assertNotRegex(retry.group(), r'\bdisabled(?:\s|=|>)|aria-disabled="true"')
                href = re.search(r'href="([^"]+)"', retry.group())
                assert href is not None
                self.assertEqual(html.unescape(href[1]), "/login/?next=%2Ftickets%2F3%2F")
                self.assertNotContains(response, "correct-horse")
                self.assertIn(b" disabled>", response.content)

                recovered = client.get(html.unescape(href[1]))
                self.assertContains(recovered, 'id="login-form"')
                self.assertNotIn(b" disabled>", recovered.content)
                self.assertNotContains(recovered, "correct-horse")
