"""The privacy pages describe the account's data processing as a notice, not a consent (ADR-0062).

Registration asks for no consent to process the account's data: that processing performs the
contract, and the privacy policy describes it. The privacy dashboard and consent history still
badged it "Active" or "Inactive" from a date the profile API never sends, so every customer saw
an inactive consent. They now link the privacy policy and show no consent state for it.
"""

from __future__ import annotations

import re
import time
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PrivacyNoticeDashboardTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update(
            {
                "customer_id": "1",
                "user_id": 10,
                "email": "owner@example.com",
                "selected_customer_id": "1",
                "user_memberships": [{"customer_id": 1, "customer_name": "Test Co", "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    @patch("apps.users.views.api_client")
    def test_data_processing_links_the_privacy_policy_and_shows_no_consent_state(self, api: MagicMock) -> None:
        api.get_customer_profile.return_value = {"accepts_marketing": False}
        api.get_consent_history_secure.return_value = {"success": True, "consent_history": []}
        policy = reverse("privacy_policy")

        for page in ("users:privacy_dashboard", "users:consent_history"):
            with self.subTest(page=page):
                response = self.client.get(reverse(page))
                self.assertEqual(response.status_code, 200)
                html = response.content.decode()
                card = re.search(r"Data Processing(.*?)Marketing Communications", html, flags=re.S)
                self.assertIsNotNone(card, "the data processing card renders before the marketing one")
                assert card is not None
                self.assertIn(f'href="{policy}"', card.group(1))
                self.assertNotIn("Inactive", card.group(1))
                self.assertNotIn("Active", card.group(1))
