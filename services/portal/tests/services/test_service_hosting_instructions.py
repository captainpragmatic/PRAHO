"""The service page shows the hosting name and the records to set, once Platform offers them (ADR-0061 P1.11)."""

import time
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

NAME = "h7k3p2q8.praho-sites.net"
HOSTING = {
    "account_name": NAME,
    "path": "external_dns",
    "records": [
        {"type": "CNAME", "name": "www.site.example.com", "value": NAME},
        {"type": "ALIAS", "name": "site.example.com", "value": NAME},
    ],
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class ServiceHostingInstructionsTests(SimpleTestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def page(self, hosting: dict | None) -> str:
        service = {
            "id": 5,
            "status": "active",
            "service_name": "Hosting",
            "domain": "site.example.com",
            "currency_code": "RON",
            "hosting": hosting,
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {}
            api.get_service_domains.return_value = []
            response = self.client.get(reverse("services:detail", kwargs={"service_id": 5}))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_a_live_name_is_shown_with_every_record_to_set(self) -> None:
        page = self.page(HOSTING)

        self.assertIn('data-testid="hosting-dns-instructions"', page)
        self.assertIn(NAME, page)
        self.assertIn("www.site.example.com", page)
        self.assertIn("ALIAS", page)
        self.assertIn("CNAME", page)

    def test_nothing_is_shown_until_platform_offers_a_name(self) -> None:
        page = self.page(None)

        self.assertNotIn('data-testid="hosting-dns-instructions"', page)
        self.assertIn("Hosting", page, "the page itself still rendered")
