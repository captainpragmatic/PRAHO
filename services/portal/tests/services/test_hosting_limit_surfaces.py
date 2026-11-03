"""Render assigned, requested and verified quota facts from the Platform receipt."""

import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings
from django.urls import reverse


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class HostingLimitTemplateTests(SimpleTestCase):
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

    def test_pending_limits_show_requested_and_operational_without_claiming_verification(self) -> None:
        service = {
            "id": 5,
            "status": "active",
            "service_name": "Pinned hosting",
            "domain": "example.com",
            "currency_code": "RON",
            "service_plan": {"name": "Twenty", "disk_space_gb": 10},
            "hosting_limits": {
                "state": "pending",
                "revision": 2,
                "assigned": {"disk_mib": 20480, "bandwidth_mib": 204800, "disk_gib": 20, "bandwidth_gib": 200},
                "operational": {
                    "revision": 1,
                    "disk_mib": 10240,
                    "disk_gib": 10,
                    "bandwidth_mib": 102400,
                    "bandwidth_gib": 100,
                },
                "verified": {
                    "revision": 1,
                    "disk_mib": 10240,
                    "disk_gib": 10,
                    "bandwidth_mib": 102400,
                    "bandwidth_gib": 100,
                },
            },
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {"current_usage": {}, "historical_usage": {}, "alerts": []}
            api.get_service_domains.return_value = []
            response = self.client.get(reverse("services:detail", kwargs={"service_id": 5}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Requested allowance")
        self.assertContains(response, "20 GiB")
        self.assertContains(response, "10 GiB")
        self.assertContains(response, "not yet verified")
        self.assertContains(response, "Last verified allowance")
        self.assertNotContains(response, "22 GiB")

    def test_service_cards_show_pending_state_without_advertising_requested_space_as_operational(self) -> None:
        service = {
            "id": 5,
            "service_name": "Pinned",
            "service_plan_name": "Twenty",
            "status": "active",
            "service_plan_type_display": "Shared hosting",
            "monthly_price": "10",
            "currency_code": "RON",
            "domain": "example.com",
            "next_billing_date": None,
            "hosting_limits": {"state": "pending", "operational": {"disk_mib": 10240, "disk_gib": 10}},
        }
        html = render_to_string("services/partials/services_table.html", {"services": [service]})
        self.assertIn("10 GiB", html)
        self.assertIn("Limits pending", html)

    def test_unknown_and_unlimited_are_labelled_separately(self) -> None:
        limits = {"state": "unknown", "operational": {"disk_mib": None, "bandwidth_mib": 0}, "verified": None}
        html = render_to_string("services/partials/hosting_limits.html", {"limits": limits})
        self.assertIn("Unknown", html)
        self.assertIn("Unlimited", html)
