"""Portal usage surfaces distinguish observations from missing and incomplete data."""

from __future__ import annotations

import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

SOURCE_TIME = "2026-10-29T10:15:00+00:00"


def observation(**changes: object) -> dict[str, object]:
    return {
        "disk_usage_gb": None,
        "disk_usage_percentage": None,
        "bandwidth_usage_gb": None,
        "bandwidth_usage_percentage": None,
        "databases_used": None,
        "email_accounts_used": None,
        "usage_as_of": None,
        "usage_state": "unknown",
        "usage_age_hours": None,
        "bandwidth_as_of": None,
        "bandwidth_state": "unknown",
        "bandwidth_age_hours": None,
        "disk_files_gb": None,
        "disk_db_gb": None,
        "disk_limit_gb": 10,
        "bandwidth_limit_gb": 100,
        "databases_limit": 5,
        "email_accounts_limit": 10,
        **changes,
    }


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"],
    LANGUAGE_CODE="en",
)
class UsageObservationTemplateTests(SimpleTestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update({
            "customer_id": 42,
            "user_id": 7,
            "user_memberships": [{"customer_id": 42, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def usage(self, current: dict[str, object], *, history: dict[str, object] | None = None) -> dict[str, object]:
        return {
            "current_usage": current,
            "historical_usage": {"disk_usage_trend": [], "uptime_percentage": None, **(history or {})},
            "alerts": [],
            "last_updated": current.get("usage_as_of"),
        }

    def page(self, current: dict[str, object], *, history: dict[str, object] | None = None) -> str:
        service = {
            "id": 5,
            "status": "active",
            "service_name": "Observed hosting",
            "domain": "example.com",
            "currency_code": "RON",
            "service_plan": {"disk_space_gb": 10, "bandwidth_gb": 100, "email_accounts": 10, "databases": 5},
            **current,
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = self.usage(current, history=history)
            api.get_service_domains.return_value = []
            response = self.client.get(reverse("services:detail", kwargs={"service_id": 5}))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def fragment(self, current: dict[str, object], *, history: dict[str, object] | None = None) -> str:
        return render_to_string(
            "services/partials/usage_chart.html",
            {"usage": self.usage(current, history=history), "period": "30d"},
        )

    def test_missing_readings_do_not_turn_into_zero_on_either_detail_surface(self) -> None:
        for current in (observation(), {}):
            with self.subTest(current=current):
                html = self.page(current)
                self.assertNotRegex(html, r"0[.,]0\s*GB")
                self.assertNotIn('style="width: 0%', html)
                self.assertEqual(html.count("Not available"), 8)

    def test_missing_fragment_readings_remain_visible_as_unknown(self) -> None:
        html = self.fragment(observation())
        self.assertEqual(html.count("Not available"), 4)
        self.assertNotIn('style="width: 0%', html)
        self.assertNotIn("Last Updated:", html)

    def test_measured_zero_is_preserved_on_detail_and_fragment(self) -> None:
        current = observation(
            disk_usage_gb=0,
            bandwidth_usage_gb=0,
            disk_usage_percentage=0,
            bandwidth_usage_percentage=0,
            databases_used=0,
            email_accounts_used=0,
            usage_state="fresh",
            bandwidth_state="fresh",
            usage_as_of=SOURCE_TIME,
            bandwidth_as_of=SOURCE_TIME,
            usage_age_hours=0,
            bandwidth_age_hours=0,
        )
        for html, expected_values in ((self.page(current), 4), (self.fragment(current), 2)):
            with self.subTest(expected_values=expected_values):
                self.assertEqual(html.count("0.0 GB"), expected_values)
                self.assertNotIn("Not available", html)
                self.assertIn("Less than 1 hour ago", html)

    def test_stale_disk_and_incomplete_bandwidth_have_independent_source_times(self) -> None:
        current = observation(
            disk_usage_gb=3.5,
            disk_usage_percentage=35,
            usage_as_of=SOURCE_TIME,
            usage_state="stale",
            usage_age_hours=9,
            bandwidth_as_of="2026-10-29T18:15:00+00:00",
            bandwidth_state="partial",
            bandwidth_age_hours=1,
        )
        for html in (self.page(current), self.fragment(current)):
            with self.subTest(fragment='<!DOCTYPE' not in html):
                self.assertIn("3.5 GB", html)
                self.assertIn("Stale reading", html)
                self.assertIn("9 hours ago", html)
                self.assertIn("Monthly bandwidth is incomplete", html)
                self.assertIn(f'datetime="{SOURCE_TIME}"', html)
                self.assertIn('datetime="2026-10-29T18:15:00+00:00"', html)

    def test_breakdown_and_actual_history_render_without_placeholder_uptime(self) -> None:
        current = observation(
            disk_usage_gb=3.5,
            disk_files_gb=3.2,
            disk_db_gb=0.3,
            usage_as_of=SOURCE_TIME,
            usage_state="fresh",
        )
        history = {
            "disk_sparkline": "0,60 150,30 300,0",
            "disk_usage_trend": [{"taken_at": SOURCE_TIME, "value": 3.5}],
        }
        for html in (self.page(current, history=history), self.fragment(current, history=history)):
            with self.subTest(fragment='<!DOCTYPE' not in html):
                self.assertIn("Files:", html)
                self.assertIn("3.20 GB", html)
                self.assertIn("Databases:", html)
                self.assertIn("0.30 GB", html)
                self.assertIn('<polyline', html)
                self.assertIn('points="0,60 150,30 300,0"', html)
                self.assertNotIn("Coming Soon", html)
                self.assertNotIn("Service Uptime", html)
                self.assertIn(f'datetime="{SOURCE_TIME}"', html)

    def test_history_is_not_fabricated_before_the_first_reading(self) -> None:
        for html in (self.page(observation()), self.fragment(observation())):
            with self.subTest(fragment='<!DOCTYPE' not in html):
                self.assertIn("No disk usage history is available yet", html)
                self.assertNotIn("<polyline", html)

    def test_service_age_is_not_labelled_as_measured_uptime(self) -> None:
        html = self.page(observation(service_age_days=5))
        self.assertIn("5 days", html)
        self.assertNotIn(">Uptime<", html)

    def test_small_database_measurement_does_not_round_to_zero_in_breakdown(self) -> None:
        current = observation(disk_usage_gb=0.31, disk_files_gb=0.29, disk_db_gb=0.02)
        for html in (self.page(current), self.fragment(current)):
            with self.subTest(fragment='<!DOCTYPE' not in html):
                self.assertIn("0.02 GB", html)
