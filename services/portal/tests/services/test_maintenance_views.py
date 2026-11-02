"""Customer maintenance attention uses real views/templates and external HTTP fixtures only."""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase
from django.urls import resolve
from django.utils import timezone, translation
from django.utils.translation import trans_real

from apps.common.localisation import DisplayLocalisation
from tests.services.test_maintenance_summary import envelope, window


class MaintenanceViewsTests(SimpleTestCase):
    def request(self, path="/services/12/"):
        request = RequestFactory().get(path, HTTP_HX_REQUEST="true")
        request.customer_id = 2
        request.user_id = 7
        request.localisation = DisplayLocalisation("en", "RO", "America/New_York", "%Y-%m-%d")
        request.session = {
            "customer_id": 1,
            "user_id": 7,
            "user_memberships": [{"customer_id": 2, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
            "account_health_data": {"customer_id": "2", "invoice": {}, "services": {}, "tickets": {}},
            "account_health_fetched_at": time.time(),
        }
        return request

    def transport(self, method, path, **kwargs):
        self.assertEqual(method, "POST")
        if path == "/services/12/":
            return {
                "success": True,
                "data": {
                    "service": {
                        "id": 12,
                        "service_name": "Example hosting",
                        "status": "active",
                        "service_plan": {},
                    }
                },
            }
        if path == "/services/12/usage/":
            return {"success": True, "data": {"usage": {}}}
        if path == "/services/12/domains/":
            return {"success": True, "data": {"domains": []}}
        if path == "/maintenance/summary/":
            return envelope()
        if path == "/maintenance/services/12/":
            self.assertEqual(kwargs["data"], {"customer_id": 2, "user_id": 7})
            return self.maintenance
        raise AssertionError(f"Unexpected external endpoint: {path}")

    def render(self, *, partial=False):
        path = "/services/12/maintenance/" if partial else "/services/12/"
        with patch("apps.api_client.services.PlatformAPIClient._make_request", side_effect=self.transport):
            response = resolve(path).func(self.request(path), service_id=12)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_service_page_shows_scoped_attention_in_viewer_zone_and_escapes_note(self):
        self.maintenance = envelope(window(customer_note="Updates <script>alert(1)</script>"))
        html = self.render()
        self.assertIn('id="maintenance-attention"', html)
        self.assertIn("Scheduled maintenance for your hosting", html)
        self.assertIn("2026-11-02 21:00", html)
        self.assertIn("America/New_York", html)
        self.assertIn("up to 10 minutes", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn('hx-get="/services/12/maintenance/"', html)

    def test_initially_empty_service_still_has_poll_target_without_empty_card(self):
        self.maintenance = envelope()
        html = self.render()
        self.assertIn('id="maintenance-attention"', html)
        self.assertIn('hx-trigger="every 30s"', html)
        self.assertNotIn("No maintenance scheduled", html)
        self.assertNotIn("Scheduled maintenance for your hosting", html)

    def test_running_and_overran_have_distinct_customer_copy(self):
        for state, text in [("running", "Maintenance is in progress"), ("overran", "taking longer than planned")]:
            with self.subTest(state=state):
                self.maintenance = envelope(window(status=state))
                self.assertIn(text, self.render(partial=True))

    def test_completed_note_is_neutral_escaped_and_expires_after_24h(self):
        finished = timezone.now() - timedelta(hours=1)
        self.maintenance = envelope(
            completed=window(
                status="completed",
                finished_at=finished.isoformat(),
                completion_source="operator",
                public_outcome="Ready <b>confirmed</b>",
            )
        )
        html = self.render(partial=True)
        self.assertIn("Maintenance completed", html)
        self.assertIn("Confirmed by an operator", html)
        self.assertIn("Ready &lt;b&gt;confirmed&lt;/b&gt;", html)
        self.assertNotIn('role="alert"', html)
        self.maintenance["data"]["maintenance"]["last_completed"]["finished_at"] = (
            timezone.now() - timedelta(hours=24, seconds=1)
        ).isoformat()
        self.assertNotIn("Maintenance completed", self.render(partial=True))

    def test_outcome_visibility_has_an_exact_24_hour_boundary_and_never_accepts_future_completion(self):
        now = timezone.now()
        for age, visible in (
            (timedelta(hours=24, seconds=-1), True),
            (timedelta(hours=24), False),
            (timedelta(hours=24, seconds=1), False),
            (timedelta(seconds=-1), False),
        ):
            with self.subTest(age=age), patch("apps.services.maintenance.timezone.now", return_value=now):
                self.maintenance = envelope(
                    completed=window(
                        status="completed",
                        finished_at=(now - age).isoformat(),
                        completion_source="job",
                    )
                )
                self.assertEqual("Maintenance completed" in self.render(partial=True), visible)

    def test_malformed_or_other_service_payload_shows_unknown_without_details(self):
        self.maintenance = envelope(window(service_ids=[999], customer_note="OTHER CUSTOMER SECRET"))
        html = self.render(partial=True)
        self.assertIn("Maintenance information is temporarily unavailable", html)
        self.assertNotIn("OTHER CUSTOMER SECRET", html)

    def test_rendering_uses_local_zone_without_activating_it_for_accounting(self):
        self.maintenance = envelope(window())
        before = timezone.get_current_timezone_name()
        self.render(partial=True)
        self.assertEqual(timezone.get_current_timezone_name(), before)

    def test_romanian_attention_copy_is_translated(self):
        self.maintenance = envelope(window())
        with translation.override("ro"):
            html = self.render(partial=True)
        self.assertIn("Mentenanță programată", html)

    def test_translated_operator_confirmation_is_text_even_with_hostile_catalog(self):
        self.maintenance = envelope(
            completed=window(
                status="completed",
                finished_at=timezone.now().isoformat(),
                completion_source="operator",
            )
        )
        hostile = '<img src=x onerror="alert(1)">'
        with translation.override("en"):
            active = trans_real._active.value
            original = active.gettext
            active.gettext = lambda message: hostile if message == "Confirmed by an operator." else original(message)
            try:
                html = self.render(partial=True)
            finally:
                active.gettext = original
        self.assertNotIn(hostile, html)
        self.assertIn("&lt;img", html)
