"""Ticket role refresh outages render notices rather than an editable ticket."""

from __future__ import annotations

from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

from tests.common.test_role_decorator_outage import FAILURES, _api_response


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "ticket-role-check-outage",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
    PLATFORM_API_BASE_URL="https://platform.example.test/api",
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class TicketRoleCheckOutageTests(SimpleTestCase):
    def test_ticket_membership_outage_matrix(self) -> None:
        path = reverse("tickets:detail", args=[3])
        for state in ("cold", "expired"):
            for failure in FAILURES:
                for htmx in (False, True):
                    with self.subTest(state=state, failure=failure, htmx=htmx):
                        cache.clear()
                        client = Client(raise_request_exception=False)
                        session = client.session
                        session.update({"user_id": 456, "customer_id": 123, "selected_customer_id": 123})
                        if state == "expired":
                            session["user_memberships"] = [{"customer_id": 123, "role": "owner"}]
                            session["user_memberships_fetched_at"] = 1.0
                        session.save()
                        upstream = _api_response(
                            429 if failure == "rate_limit" else 503,
                            {"error": "rate_limited" if failure == "rate_limit" else "maintenance"},
                            retry_after=60,
                        )
                        with (
                            patch(
                                "apps.tickets.views.tickets_api.get_ticket_detail",
                                return_value={
                                    "id": 3,
                                    "title": "Private ticket detail",
                                    "status": "open",
                                    "comments": [],
                                },
                            ),
                            patch(
                                "apps.common.outbound_http._session.request",
                                side_effect=requests.exceptions.ConnectionError("offline")
                                if failure == "connection"
                                else None,
                                return_value=upstream,
                            ),
                        ):
                            response = client.get(path, headers={"HX-Request": "true"} if htmx else {})
                            status = 200 if htmx else 429 if failure == "rate_limit" else 503
                            self.assertEqual(response.status_code, status)
                            self.assertNotIn("Location", response)
                            self.assertNotContains(response, "Private ticket detail", status_code=status)
                            self.assertNotContains(response, "Role not found", status_code=status)
                            template = (
                                "components/rate_limit_inline_alert.html"
                                if failure == "rate_limit"
                                else "components/maintenance_inline_alert.html"
                            )
                            self.assertTemplateUsed(response, template)
                            heading = (
                                "Temporarily rate limited"
                                if failure == "rate_limit"
                                else "Scheduled maintenance"
                                if failure == "maintenance"
                                else "Temporarily unavailable"
                            )
                            self.assertContains(response, heading, status_code=status)
                            if failure == "connection":
                                self.assertNotIn("Retry-After", response)
                            else:
                                self.assertEqual(response["Retry-After"], "60")
                            if htmx:
                                self.assertTemplateNotUsed(response, "base.html")
                            else:
                                self.assertTemplateUsed(
                                    response,
                                    "common/rate_limited.html"
                                    if failure == "rate_limit"
                                    else "common/platform_unavailable.html",
                                )

                            with patch(
                                "apps.common.outbound_http._session.request",
                                return_value=_api_response(
                                    200, {"success": True, "results": [{"id": 123, "role": "viewer"}]}
                                ),
                            ):
                                recovered = client.get(path)
                            self.assertEqual(recovered.status_code, 200)
                            self.assertFalse(recovered.context["can_reply"])
