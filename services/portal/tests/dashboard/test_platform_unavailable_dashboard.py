"""The dashboard outage banner must render alongside unknown section counts."""

from __future__ import annotations

import json
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.http import HttpResponseBase
from django.template import Context
from django.test import Client, SimpleTestCase, override_settings
from django.test.utils import ContextList

from tests.common.test_maintenance_not_a_server_error import _authenticated_session
from tests.dashboard.test_maintenance_dashboard import tile_value

PLATFORM_DOWN_MESSAGE = "Platform service temporarily unavailable. Some features may be limited."


def _api_response(payload: dict[str, object], *, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(payload).encode()
    return response


def _billing_unreachable(method: str, url: str, **kwargs: object) -> requests.Response:
    if url.endswith("/billing/invoices/"):
        raise requests.exceptions.ConnectionError("offline")
    if url.endswith("/services/summary/"):
        return _api_response({"success": True, "data": {"summary": {"active_services": 3}}})
    if url.endswith("/tickets/summary/"):
        return _api_response({"success": True, "data": {"open_tickets": 2}})
    return _api_response(
        {"success": True, "customer": {"status": "active", "name": "Example customer"}, "profile": {}, "results": []}
    )


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_BASE_URL="https://platform.example.test/api",
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class DashboardPlatformUnavailableTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.client = Client()
        _authenticated_session(self.client, user_id=456, customer_id=123)

    def _assert_red_banner(self, response: HttpResponseBase) -> None:
        self.assertContains(response, PLATFORM_DOWN_MESSAGE)
        self.assertContains(response, "mb-6 bg-red-900 border border-red-700 rounded-lg p-4")
        self.assertContains(
            response,
            f'<span class="text-red-100 text-sm sm:text-base">{PLATFORM_DOWN_MESSAGE}</span>',
        )
        context: Context | ContextList | None = getattr(response, "context", None)
        assert context is not None
        self.assertIs(context["platform_available"], False)

    def _assert_all_counts_unknown(self, response: HttpResponseBase) -> None:
        context: Context | ContextList | None = getattr(response, "context", None)
        assert context is not None
        self.assertEqual(context["sections_unavailable"], {"billing", "customer", "tickets", "services"})
        for key in ("active_services", "open_tickets", "total_invoices"):
            with self.subTest(stat=key):
                self.assertEqual(context["dashboard_data"]["stats"][key], "—")
        body = response.content.decode()
        for label in ("My Services", "My Open Tickets"):
            with self.subTest(tile=label):
                self.assertEqual(tile_value(body, label), "—")
                self.assertNotEqual(tile_value(body, label), "0")

    def test_connection_error_shows_red_banner_and_dashes_instead_of_zero_counts(self) -> None:
        with patch(
            "apps.common.outbound_http._session.request",
            side_effect=requests.exceptions.ConnectionError("offline"),
        ):
            response = self.client.get("/dashboard/")

        self._assert_red_banner(response)
        self._assert_all_counts_unknown(response)

    def test_one_unreachable_section_shows_red_banner_and_preserves_healthy_counts(self) -> None:
        with patch("apps.common.outbound_http._session.request", side_effect=_billing_unreachable):
            response = self.client.get("/dashboard/")

        self._assert_red_banner(response)
        context: Context | ContextList | None = getattr(response, "context", None)
        assert context is not None
        self.assertEqual(context["sections_unavailable"], {"billing"})
        self.assertEqual(context["dashboard_data"]["stats"]["total_invoices"], "—")
        body = response.content.decode()
        self.assertEqual(tile_value(body, "My Services"), "3")
        self.assertEqual(tile_value(body, "My Open Tickets"), "2")

    def test_every_section_unavailable_shows_red_banner_and_dashes(self) -> None:
        unavailable = _api_response({"error": "unavailable"}, status=503)
        with patch("apps.common.outbound_http._session.request", return_value=unavailable):
            response = self.client.get("/dashboard/")

        self._assert_red_banner(response)
        self._assert_all_counts_unknown(response)
