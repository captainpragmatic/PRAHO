"""Maintenance reads stay signed and refresh independently of account-health caches."""

from __future__ import annotations

import copy
import time
from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.common.account_health import evaluate_conditions, get_account_health
from apps.common.localisation import DisplayLocalisation
from apps.services.services import ServicesAPIClient


def window(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": "13f63473-30a9-42fd-a1aa-91032df36150",
        "kind": "reboot",
        "status": "scheduled",
        "starts_at": "2026-11-03T02:00:00+00:00",
        "ends_at": "2026-11-03T02:30:00+00:00",
        "started_at": None,
        "finished_at": None,
        "expects_downtime": True,
        "expected_downtime_minutes": 10,
        "customer_note": "Security updates and a restart.",
        "public_outcome": "",
        "completion_source": "",
        "was_overrun": False,
        "service_ids": [12],
    }
    result.update(changes)
    return result


def envelope(*windows: dict[str, object], completed: dict[str, object] | None = None) -> dict[str, object]:
    return {"success": True, "data": {"maintenance": {"windows": list(windows), "last_completed": completed}}}


class MaintenanceSummaryTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def request(self, customer: int = 1, session: dict | None = None):
        request = RequestFactory().get("/dashboard/")
        request.customer_id = customer
        request.localisation = DisplayLocalisation("en", "RO", "America/New_York", "%Y-%m-%d")
        request.session = (
            session
            if session is not None
            else {
                "customer_id": 1,
                "user_id": 7,
                "account_health_data": {"customer_id": str(customer), "invoice": {}, "services": {}, "tickets": {}},
                "account_health_fetched_at": time.time(),
            }
        )
        return request

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_existing_health_orchestrator_displays_maintenance_despite_fresh_other_summary_cache(self, transport):
        transport.return_value = envelope(window())
        request = self.request()

        banner = get_account_health(request)

        self.assertIsNotNone(banner)
        self.assertIn("Scheduled maintenance", banner.message)
        self.assertIn("2026-11-02 21:00", banner.message)
        self.assertIn("America/New_York", banner.message)
        self.assertEqual(banner.cta_url, "/services/12/#maintenance-attention")
        transport.assert_called_once_with(
            "POST",
            "/maintenance/summary/",
            user_id=7,
            data={"customer_id": 1, "user_id": 7},
            idempotent=True,
        )

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_next_request_clears_completed_window_without_waiting_for_other_cache(self, transport):
        transport.side_effect = [envelope(window()), envelope()]
        request = self.request()
        self.assertIsNotNone(get_account_health(request))
        next_request = self.request(session=request.session)
        self.assertIsNone(get_account_health(next_request))
        self.assertEqual(transport.call_count, 2)

    @patch("apps.api_client.services.PlatformAPIClient._make_request", return_value=envelope(window()))
    def test_maintenance_poll_does_not_write_session_and_race_company_switch(self, transport):
        request = self.request()
        before = copy.deepcopy(request.session)
        self.assertIsNotNone(get_account_health(request))
        self.assertEqual(request.session, before)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_authorization_refusal_never_reuses_last_known_customer_state(self, transport):
        transport.side_effect = [envelope(window()), PlatformAPIError("access denied", status_code=403)]
        request = self.request()
        self.assertIsNotNone(get_account_health(request))
        self.assertIsNone(get_account_health(self.request(session=request.session)))

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_failed_refresh_preserves_known_state_as_unknown_and_retries_next_poll(self, transport):
        transport.side_effect = [envelope(window()), PlatformAPIError("unavailable"), envelope()]
        request = self.request()
        first = get_account_health(request)
        failed = self.request(session=request.session)
        self.assertEqual(get_account_health(failed), first)
        self.assertTrue(failed.maintenance_unavailable)
        recovered = self.request(session=request.session)
        self.assertIsNone(get_account_health(recovered))
        self.assertFalse(recovered.maintenance_unavailable)
        self.assertEqual(transport.call_count, 3)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_prior_company_state_is_never_used_when_new_company_fetch_fails(self, transport):
        transport.side_effect = [envelope(window()), PlatformAPIError("unavailable")]
        first = self.request()
        self.assertIsNotNone(get_account_health(first))
        changed = self.request(customer=2, session=first.session)
        # Non-maintenance account summaries are a separate boundary here.
        changed.session["account_health_data"]["customer_id"] = "2"
        self.assertIsNone(get_account_health(changed))
        self.assertTrue(changed.maintenance_unavailable)
        self.assertEqual(transport.call_args.kwargs["data"]["customer_id"], 2)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_overrun_warns_but_invoice_stays_first(self, transport):
        transport.return_value = envelope(window(status="overran", was_overrun=True))
        request = self.request()
        request.session["account_health_data"]["invoice"] = {"overdue_invoices": 1}
        banner = get_account_health(request)
        self.assertEqual(banner.severity, "critical")
        self.assertTrue(banner.message.startswith("You have 1 overdue invoice."))
        self.assertIn("taking longer than planned", banner.message)
        self.assertEqual(banner.cta_url, "/billing/invoices/?status=overdue")

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_active_urgency_wins_over_an_earlier_scheduled_window_and_uses_its_details_link(self, transport):
        for status, severity, message in (
            ("overran", "warning", "taking longer than planned"),
            ("running", "info", "Maintenance is in progress"),
        ):
            with self.subTest(status=status):
                transport.return_value = envelope(
                    window(service_ids=[11]),
                    window(id="724976c3-41a1-4891-a29e-5b133c7dc21a", status=status, service_ids=[23]),
                )
                banner = get_account_health(self.request())
                self.assertEqual(banner.severity, severity)
                self.assertIn(message, banner.message)
                self.assertEqual(banner.cta_url, "/services/23/#maintenance-attention")
                summary = ServicesAPIClient().get_maintenance_summary(1, 7)
                self.assertEqual(evaluate_conditions({}, {}, {}, summary)[0].count, 2)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_same_status_selects_earliest_actual_start_with_stable_id_tie_break(self, transport):
        transport.return_value = envelope(
            window(starts_at="2026-11-03T02:00:00.001+00:00", service_ids=[11]),
            window(id="724976c3-41a1-4891-a29e-5b133c7dc21a", starts_at="2026-11-03T02:00:00Z", service_ids=[23]),
            window(id="00000000-0000-4000-8000-000000000001", starts_at="2026-11-03T02:00:00+00:00", service_ids=[44]),
        )
        banner = get_account_health(self.request())
        self.assertEqual(banner.cta_url, "/services/44/#maintenance-attention")

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_per_service_read_uses_current_identity_in_signed_post_body(self, transport):
        transport.return_value = envelope(window())
        result = ServicesAPIClient().get_service_maintenance(2, 7, 12)
        self.assertEqual(result["windows"][0]["service_ids"], [12])
        transport.assert_called_once_with(
            "POST",
            "/maintenance/services/12/",
            user_id=7,
            data={"customer_id": 2, "user_id": 7},
            idempotent=True,
        )

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_malformed_or_failed_receipts_never_become_valid_empty_state(self, transport):
        malformed = [
            {"success": False, "data": {"maintenance": {"windows": [], "last_completed": None}}},
            {"success": True, "data": {}},
            envelope(window(service_ids=[True])),
            envelope(window(starts_at="2026-11-03T02:00:00")),
            envelope(window(status="completed")),
            envelope(window(node_id=99)),
            envelope(window(expects_downtime="false")),
            envelope(window(expected_downtime_minutes=-1)),
        ]
        for response in malformed:
            with self.subTest(response=response):
                transport.return_value = copy.deepcopy(response)
                with self.assertRaises(PlatformAPIError):
                    ServicesAPIClient().get_maintenance_summary(1, 7)
