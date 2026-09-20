"""Real API envelopes and ISO dates must survive the Portal adapter and templates."""

from datetime import UTC, date, datetime
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils.translation import override

from apps.api_client.services import PlatformAPIError
from apps.services.services import ServicesAPIClient


class ServiceAPIContracts(SimpleTestCase):
    def test_search_is_signed_and_applied_before_pagination(self):
        api = ServicesAPIClient()
        payload = {
            "success": True,
            "data": {
                "services": [{"id": 25, "service_name": "Old service", "next_billing_date": "2026-09-19"}],
                "pagination": {"total": 1},
            },
        }
        with patch.object(api, "_make_request", return_value=payload) as request:
            result = api.get_customer_services(101, 7, search="old", page=2)
        request.assert_called_once_with(
            "POST",
            "/services/",
            user_id=7,
            idempotent=True,
            data={"customer_id": 101, "user_id": 7, "page": 2, "limit": 20, "search": "old"},
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["next_billing_date"], date(2026, 9, 19))

    def test_invalid_api_dates_propagate_instead_of_becoming_unscheduled(self):
        api = ServicesAPIClient()
        for value in ("2026-02-30", "not-a-date", ""):
            for detail in (False, True):
                with self.subTest(value=value, detail=detail):
                    service = {"id": 55, "next_billing_date": value}
                    data = {"service": service} if detail else {"services": [service]}
                    with (
                        patch.object(api, "_make_request", return_value={"success": True, "data": data}),
                        self.assertRaisesRegex(PlatformAPIError, "Invalid service date: next_billing_date"),
                    ):
                        if detail:
                            api.get_service_detail(101, 7, 55)
                        else:
                            api.get_customer_services(101, 7)

    def test_plans_read_the_platform_envelope(self):
        api = ServicesAPIClient()
        plans = [{"id": 9, "name": "Existing hosting plan"}]
        with patch.object(api, "_make_request", return_value={"success": True, "data": {"plans": plans}}):
            self.assertEqual(api.get_available_plans(101), plans)

    def test_service_detail_renders_api_dates_and_unknown_schedule_honestly(self):
        api = ServicesAPIClient()
        service = {
            "id": 55,
            "service_name": "Hosting",
            "status": "pending",
            "service_age_days": 0,
            "next_billing_date": "2026-09-19",
            "service_plan": {},
            "service_plan_type_display": "Hosting",
            "monthly_price": "100.00",
            "created_at": "2026-09-18T00:00:00Z",
        }
        with patch.object(api, "_make_request", return_value={"success": True, "data": {"service": service}}):
            detail = api.get_service_detail(101, 7, 55)
        self.assertEqual(detail["created_at"], datetime(2026, 9, 18, tzinfo=UTC))
        with override("en"):
            html = render_to_string("services/service_detail.html", {"service": detail, "service_id": 55})
            table = render_to_string("services/partials/services_table.html", {"services": [detail]})
        self.assertIn("Sep 19, 2026", html)
        self.assertIn("Sep 19, 2026", table)
        self.assertIn("0 days", html)
        self.assertNotIn("Calculating...", html)
        detail["next_billing_date"] = None
        html = render_to_string("services/service_detail.html", {"service": detail, "service_id": 55})
        self.assertIn("Not scheduled", html)
        self.assertNotIn("Calculating...", html)
