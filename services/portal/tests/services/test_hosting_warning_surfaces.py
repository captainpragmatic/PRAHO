"""Customer pages retain honest current and stale hosting warning conditions."""

import time
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.common.account_health import cached_account_health, evaluate_conditions, remember_account_health


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class HostingWarningSurfaceTests(SimpleTestCase):
    def page(
        self,
        *,
        availability: str = "fresh",
        condition: int | None = 100,
        managed=False,
        verified=False,
        raise_data=None,
    ) -> str:
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
        service = {
            "id": 5,
            "status": "active",
            "domain": "example.test",
            "service_name": "Warning hosting",
            "currency_code": "RON",
            "service_plan": {},
            "hosting_raise": raise_data,
            "hosting_limits": {
                "enforcement_state": "managed" if managed else "unknown",
                "state": "verified" if verified else "unverified",
            },
            "hosting_warnings": {
                "disk": {
                    "condition": condition,
                    "availability": availability,
                    "used_bytes": 1024**3,
                    "operational_allowance_mib": 1024,
                    "observed_at": "2026-11-04T10:00:00+00:00",
                }
            },
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_service_usage.return_value = {"current_usage": {}, "historical_usage": {}}
            api.get_service_domains.return_value = []
            response = self.client.get(reverse("services:detail", args=[5]))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_current_critical_condition_is_visible_with_support_and_without_unproven_enforcement(self) -> None:
        html = self.page()
        self.assertIn('data-hosting-warning="disk"', html)
        self.assertIn("Disk allowance reached", html)
        self.assertIn("Review usage or contact support", html)
        self.assertIn("/tickets/create/?service_id=5", html)
        self.assertNotIn("Writes may fail", html)

    def test_stale_condition_is_annotated_and_unknown_has_no_warning(self) -> None:
        self.assertIn("Last known warning", self.page(availability="stale"))
        self.assertNotIn('data-hosting-warning="disk"', self.page(availability="unknown", condition=None))

    def test_managed_without_current_verification_cannot_claim_native_write_enforcement(self) -> None:
        self.assertNotIn("Writes may fail", self.page(managed=True))
        self.assertIn("Writes may fail", self.page(managed=True, verified=True))

    def test_raise_states_keep_the_base_allowance_warning_visible(self) -> None:
        labels = {
            "requested": "Temporary disk relief requested",
            "verified": "Temporary disk relief verified",
            "expired_attention": "Temporary disk relief has expired",
            "expired": "Temporary disk relief removed",
        }
        for state, label in labels.items():
            with self.subTest(state=state):
                html = self.page(
                    raise_data={
                        "state": state,
                        "extra_mib": 1280,
                        "revision": 1,
                        "expires_at": "2026-11-07T10:00:00+00:00",
                    }
                )
                self.assertIn(label, html)
                self.assertIn("Disk allowance reached", html)
                if state in {"requested", "verified"}:
                    self.assertIn("1.25 GiB", html)

    def test_dashboard_counts_flow_through_existing_account_health_policy(self) -> None:
        conditions = evaluate_conditions({}, {"hosting_warning_counts": {"critical": 1, "warning": 2}}, {})
        self.assertEqual(
            [(item.key, item.severity, item.count) for item in conditions],
            [
                ("hosting_critical", "critical", 1),
                ("hosting_warning", "warning", 2),
            ],
        )
        self.assertEqual(conditions[0].cta_url, "/services/")

    def test_bandwidth_month_boundary_invalidates_an_otherwise_fresh_customer_summary(self) -> None:
        session = {}
        summaries = {"hosting_warning_counts": {"critical": 1, "warning": 0}}
        remember_account_health(session, 42, {}, summaries, {})
        self.assertIsNotNone(cached_account_health(session, 42))
        summaries["hosting_warning_counts_valid_until"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        self.assertIsNone(cached_account_health(session, 42))
