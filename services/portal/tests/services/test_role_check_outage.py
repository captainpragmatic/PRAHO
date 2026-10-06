"""Direct service role checks surface membership outages without granting access."""

from __future__ import annotations

from typing import Literal
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.http import HttpResponse
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils.html import escape

from tests.common.test_role_decorator_outage import FAILURES, Failure, _api_response

Endpoint = Literal["detail", "request_get", "request_post"]
SUBMISSION_ID = "11111111-1111-4111-8111-111111111111"
REASON = "Keep <my> hosting"


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "service-role-check-outage",
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
class ServiceRoleCheckOutageTests(SimpleTestCase):
    def _client(self, state: str) -> Client:
        cache.clear()
        client = Client(raise_request_exception=False)
        session = client.session
        session.update(
            {
                "user_id": 456,
                "customer_id": 123,
                "selected_customer_id": 123,
                "service_request_submissions": {"123:456:3": {"id": SUBMISSION_ID, "accepted": False}},
            }
        )
        if state == "expired":
            session["user_memberships"] = [{"customer_id": 123, "role": "owner"}]
            session["user_memberships_fetched_at"] = 1.0
        session.save()
        return client

    def _assert_response(self, response: HttpResponse, failure: Failure, *, htmx: bool, bound: bool) -> None:
        status = 200 if htmx else 429 if failure == "rate_limit" else 503
        self.assertEqual(response.status_code, status)
        self.assertNotIn("Location", response)
        self.assertNotContains(response, "Role not found", status_code=status)
        self.assertNotContains(response, "Private hosting detail", status_code=status)
        if bound and htmx and failure == "rate_limit":
            # The decorator throttles before the view runs; an HTMX POST gets a toast retargeted
            # outside the form so the customer's unsent input stays on the page.
            self.assertEqual(response["HX-Retarget"], "#toast-container")
            self.assertEqual(response["HX-Reswap"], "beforeend")
            self.assertTemplateUsed(response, "components/toast.html")
            self.assertContains(response, "Please try again in 60 seconds", status_code=status)
            return
        if failure == "connection":
            heading = "Temporarily unavailable"
            self.assertNotIn("Retry-After", response)
        else:
            heading = "Temporarily rate limited" if failure == "rate_limit" else "Scheduled maintenance"
            self.assertEqual(response["Retry-After"], "60")
        self.assertContains(response, heading, status_code=status)
        if bound and failure != "rate_limit":
            self.assertTemplateUsed(response, "services/service_request_action.html")
            self.assertContains(response, SUBMISSION_ID, status_code=status)
            self.assertContains(response, escape(REASON), status_code=status)
            self.assertEqual(response.context["selected_action"], "cancel_request")
            self.assertEqual(response.context["action_types"], [])
            self.assertTrue(response.context["service_details_unavailable"])
            self.assertNotContains(response, "Monthly Cost", status_code=status)
        else:
            template = (
                "components/rate_limit_inline_alert.html"
                if failure == "rate_limit"
                else "components/maintenance_inline_alert.html"
            )
            self.assertTemplateUsed(response, template)
            if htmx:
                self.assertTemplateNotUsed(response, "base.html")
            else:
                self.assertTemplateUsed(
                    response,
                    "common/rate_limited.html" if failure == "rate_limit" else "common/platform_unavailable.html",
                )

    def _assert_matrix(self, endpoint: Endpoint) -> None:
        path = reverse("services:detail" if endpoint == "detail" else "services:request_action", args=[3])
        for state in ("cold", "expired"):
            for failure in FAILURES:
                for htmx in (False, True):
                    with self.subTest(endpoint=endpoint, state=state, failure=failure, htmx=htmx):
                        client = self._client(state)
                        upstream = _api_response(
                            429 if failure == "rate_limit" else 503,
                            {"error": "rate_limited" if failure == "rate_limit" else "maintenance"},
                            retry_after=60,
                        )
                        with (
                            patch("apps.services.views.services_api") as services,
                            patch(
                                "apps.common.outbound_http._session.request",
                                side_effect=requests.exceptions.ConnectionError("offline")
                                if failure == "connection"
                                else None,
                                return_value=upstream,
                            ),
                        ):
                            services.get_service_detail.return_value = {
                                "id": 3,
                                "status": "active",
                                "service_name": "Private hosting detail",
                            }
                            services.get_service_usage.return_value = {}
                            services.get_service_domains.return_value = []
                            services.request_service_action.side_effect = AssertionError("Unverified role submitted")
                            headers = {"HX-Request": "true"} if htmx else {}
                            response = (
                                client.post(
                                    path,
                                    {"action": "cancel_request", "reason": REASON, "submission_id": SUBMISSION_ID},
                                    headers=headers,
                                )
                                if endpoint == "request_post"
                                else client.get(path, headers=headers)
                            )
                            self._assert_response(response, failure, htmx=htmx, bound=endpoint == "request_post")
                            services.request_service_action.assert_not_called()

                            # An authoritative viewer refresh must override the expired owner, even after an outage.
                            with patch(
                                "apps.common.outbound_http._session.request",
                                return_value=_api_response(
                                    200, {"success": True, "results": [{"id": 123, "role": "viewer"}]}
                                ),
                            ):
                                denied = client.get(path)
                            if endpoint == "detail":
                                self.assertEqual(denied.status_code, 200)
                                self.assertFalse(denied.context["can_manage"])
                            else:
                                self.assertContains(
                                    denied, "You do not have permission to request service changes.", status_code=403
                                )
                            services.request_service_action.assert_not_called()

    def test_detail_membership_outage_matrix(self) -> None:
        self._assert_matrix("detail")

    def test_request_get_membership_outage_matrix(self) -> None:
        self._assert_matrix("request_get")

    def test_request_post_membership_outage_matrix(self) -> None:
        self._assert_matrix("request_post")
