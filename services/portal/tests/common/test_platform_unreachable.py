"""Exercise WP1 callers through the real client, including full-page and HTMX requests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import ClassVar
from unittest.mock import patch

import requests
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseBase
from django.template import Context, Template
from django.test import Client, RequestFactory, SimpleTestCase, override_settings
from django.test.utils import ContextList

from apps.api_client.services import PlatformAPIError
from apps.common.rate_limit_feedback import render_platform_unavailable
from tests.common.test_maintenance_not_a_server_error import _authenticated_session

OUTAGE_HEADING = "Temporarily unavailable"
OUTAGE_MESSAGE = "This information is temporarily unavailable. Please try again shortly."
EMPTY_STATES = (
    "No Support Tickets Yet",
    "No support tickets yet",
    "No documents found",
    "No services found",
    "No services yet",
    "No recent documents found",
    "No recent support tickets",
    "No Plans Available",
    "No hosting plans are currently available.",
    "No team members yet",
    "No addresses yet",
    "No consent history available",
)


@dataclass(frozen=True)
class Caller:
    path: str
    status: int = 200
    post: bool = False
    json_response: bool = False


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_BASE_URL="https://platform.example.test/api",
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class PlatformUnreachableViewTests(SimpleTestCase):
    callers: ClassVar[tuple[Caller, ...]] = (
        Caller("/dashboard/"),
        Caller("/billing/invoices/"),
        Caller("/billing/invoices/search/"),
        Caller("/billing/invoices/INV-1/", 503),
        Caller("/billing/proformas/PRO-1/", 503),
        Caller("/billing/invoices/INV-1/pdf/", 503),
        Caller("/billing/proformas/PRO-1/pdf/", 503),
        Caller("/billing/dashboard-widget/", 503, json_response=True),
        Caller("/billing/sync/", 503, post=True, json_response=True),
        Caller("/tickets/"),
        Caller("/tickets/search/"),
        Caller("/tickets/widget/"),
        Caller("/tickets/3/", 503),
        Caller("/tickets/3/attachments/4/download/", 503),
        Caller("/api/tickets/3/attachments/4/download/", 503),
        Caller("/tickets/create/?service_id=3", 503),
        Caller("/tickets/3/reply/", 503, post=True),
        Caller("/services/"),
        Caller("/services/search/"),
        Caller("/services/widget/"),
        Caller("/services/plans/"),
        Caller("/services/3/", 503),
        Caller("/services/3/usage/"),
        Caller("/services/3/request-action/", 503),
        Caller("/services/3/request-action/", 503, post=True),
        Caller("/company/team/"),
        Caller("/company/addresses/"),
        Caller("/consent-history/"),
        Caller("/company/"),
    )

    def _client(self) -> Client:
        client = Client(raise_request_exception=False)
        _authenticated_session(client, user_id=456, customer_id=123)
        return client

    def _assert_outage(self, response: HttpResponseBase, caller: Caller, *, htmx: bool = False) -> None:
        status = 200 if htmx and not caller.json_response else caller.status
        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, status)
        self.assertNotIn("Location", response)
        self.assertContains(response, OUTAGE_MESSAGE, status_code=status)
        if not caller.json_response:
            self.assertContains(response, OUTAGE_HEADING, status_code=status)
        for empty_state in EMPTY_STATES:
            self.assertNotContains(response, empty_state, status_code=status)
        self.assertNotContains(response, "not found or access denied", status_code=status)
        self.assertNotContains(response, "Scheduled maintenance", status_code=status)
        context: Context | ContextList | None = getattr(response, "context", None)
        if context is not None:
            self.assertFalse(context.get("account_banner"))

    def test_every_caller_announces_connection_errors_and_timeouts(self) -> None:
        for failure_type in (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            for htmx in (False, True):
                for caller in self.callers:
                    with self.subTest(failure=failure_type.__name__, htmx=htmx, caller=caller):
                        cache.clear()
                        client = self._client()
                        headers = {"HX-Request": "true"} if htmx else {}
                        with patch("apps.common.outbound_http._send", side_effect=failure_type("offline")):
                            if caller.post and caller.json_response:
                                response = client.post(
                                    caller.path, "{}", content_type="application/json", headers=headers
                                )
                            elif caller.post:
                                response = client.post(
                                    caller.path,
                                    {"message": "A reply", "title": "Help", "description": "Service is unavailable"},
                                    headers=headers,
                                )
                            else:
                                response = client.get(caller.path, headers=headers)
                        self._assert_outage(response, caller, htmx=htmx)

    def test_unavailable_response_status_matches_htmx_swapping(self) -> None:
        error = PlatformAPIError("offline", is_unavailable=True, retry_after=60)
        factory = RequestFactory()
        for htmx, status in ((True, 200), (False, 503)):
            with self.subTest(htmx=htmx):
                headers = {"HX-Request": "true"} if htmx else {}
                request = factory.get("/tickets/3/", headers=headers)
                SessionMiddleware(lambda _request: HttpResponse()).process_request(request)
                response = render_platform_unavailable(request, error)
                self.assertEqual(response.status_code, status)
                self.assertContains(response, OUTAGE_HEADING, status_code=status)
                self.assertContains(response, "This information is temporarily unavailable.", status_code=status)
                self.assertEqual(response["Retry-After"], "60")

    def test_ticket_reply_htmx_outage_keeps_the_form_and_typed_message(self) -> None:
        message = "  Please keep <this> & my reply.\nSecond line.  "
        for failure_type in (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            with self.subTest(failure=failure_type.__name__):
                cache.clear()
                with patch("apps.common.outbound_http._send", side_effect=failure_type("offline")):
                    response = self._client().post(
                        "/tickets/3/reply/", {"message": message}, headers={"HX-Request": "true"}
                    )
                self.assertContains(response, 'id="reply-form"', status_code=response.status_code)
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "tickets/partials/status_and_comments.html")
                self.assertContains(response, OUTAGE_MESSAGE)
                self.assertContains(response, 'hx-post="/tickets/3/reply/"')
                self.assertContains(response, 'hx-target="#ticket-status-and-comments"')
                self.assertContains(response, "  Please keep &lt;this&gt; &amp; my reply.\nSecond line.  </textarea>")
                self.assertNotContains(response, 'aria-label="Try again"')
                self.assertNotContains(response, 'id="comments-container"')

    def test_inline_alert_retry_can_be_hidden_without_changing_the_default(self) -> None:
        template = Template('{% include "components/maintenance_inline_alert.html" with hide_retry=hide_retry %}')
        for hide_retry in (False, True):
            with self.subTest(hide_retry=hide_retry):
                html = template.render(
                    Context(
                        {
                            "hide_retry": hide_retry,
                            "request": RequestFactory().get("/services/"),
                            "maintenance_message": OUTAGE_MESSAGE,
                            "maintenance_retry_url": "/services/",
                        }
                    )
                )
                self.assertIn(OUTAGE_MESSAGE, html)
                if hide_retry:
                    self.assertNotIn('aria-label="Try again"', html)
                else:
                    self.assertIn('aria-label="Try again"', html)
                    self.assertIn('href="/services/"', html)

    def test_login_outage_has_no_get_retry_link(self) -> None:
        cache.clear()
        with patch("apps.common.outbound_http._send", side_effect=requests.exceptions.ConnectionError("offline")):
            response = Client().post("/login/", {"email": "someone@example.com", "password": "correct-horse"})
        self.assertContains(response, OUTAGE_MESSAGE)
        self.assertNotContains(response, 'aria-label="Try again"')
        self.assertContains(response, 'value="someone@example.com"')

    def test_later_service_fetches_cannot_render_missing_usage_or_domains(self) -> None:
        for suffix in ("/usage/", "/domains/"):
            for failure_type in (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                for htmx in (False, True):
                    with self.subTest(suffix=suffix, failure=failure_type.__name__, htmx=htmx):
                        cache.clear()
                        response = requests.Response()
                        response.status_code = 200
                        response.headers["Content-Type"] = "application/json"
                        response._content = json.dumps(
                            {"success": True, "data": {"service": {"id": 3, "status": "active"}, "usage": {}}}
                        ).encode()
                        # Detail succeeds; then usage or domains fails at the HTTP boundary.
                        replies = (
                            [response, failure_type("offline")]
                            if suffix == "/usage/"
                            else [response, response, failure_type("offline")]
                        )
                        headers = {"HX-Request": "true"} if htmx else {}
                        with patch("apps.common.outbound_http._send", side_effect=replies):
                            result = self._client().get("/services/3/", headers=headers)
                        self._assert_outage(result, Caller("/services/3/", 503), htmx=htmx)

    def test_service_request_outage_keeps_the_bound_form_and_submission_id(self) -> None:
        submission_id = "e9c8ab85-8b72-4d59-9f9b-94d43be6ec77"
        for failure_type in (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            for htmx in (False, True):
                with self.subTest(failure=failure_type.__name__, htmx=htmx):
                    cache.clear()
                    client = self._client()
                    session = client.session
                    session["service_request_submissions"] = {"123:456:3": {"id": submission_id, "accepted": False}}
                    session.save()
                    response = requests.Response()
                    response.status_code = 200
                    response._content = b'{"success": true, "data": {"service": {"id": 3, "status": "active"}}}'
                    headers = {"HX-Request": "true"} if htmx else {}
                    with patch(
                        "apps.common.outbound_http._send",
                        side_effect=[response, failure_type("offline")],
                    ):
                        result = client.post(
                            "/services/3/request-action/",
                            {"submission_id": submission_id, "action": "upgrade_request", "reason": "More storage"},
                            headers=headers,
                        )
                    # A failed submission keeps the bound form at 200 so the customer can retry safely
                    # (the contract in tests/services/test_service_requests.py); only the copy changes.
                    self._assert_outage(result, Caller("/services/3/request-action/", 200))
                    self.assertContains(result, submission_id)
                    self.assertContains(result, "More storage")
                    self.assertFalse(client.session["service_request_submissions"]["123:456:3"]["accepted"])

    def test_later_address_and_consent_fetches_show_the_outage(self) -> None:
        for path in ("/company/", "/consent-history/"):
            for failure_type in (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                for htmx in (False, True):
                    with self.subTest(path=path, failure=failure_type.__name__, htmx=htmx):
                        cache.clear()
                        response = requests.Response()
                        response.status_code = 200
                        response._content = b'{"success": true, "customer": {}, "profile": {}}'
                        headers = {"HX-Request": "true"} if htmx else {}
                        with patch(
                            "apps.common.outbound_http._send",
                            side_effect=[response, failure_type("offline")],
                        ):
                            result = self._client().get(path, headers=headers)
                        self._assert_outage(result, Caller(path))

    def test_detail_outage_fix_retains_authoritative_not_found_and_denied(self) -> None:
        for path, wording in (
            ("/billing/invoices/INV-1/", "Invoice not found or access denied."),
            ("/billing/proformas/PRO-1/", "Proforma not found or access denied."),
            ("/tickets/3/", "Ticket not found or access denied."),
            ("/services/3/", "Service not found or access denied."),
        ):
            for htmx in (False, True):
                with self.subTest(path=path, htmx=htmx):
                    cache.clear()
                    headers = {"HX-Request": "true"} if htmx else {}
                    with patch(
                        "apps.common.outbound_http._send",
                        side_effect=requests.exceptions.ConnectionError("offline"),
                    ):
                        self._assert_outage(self._client().get(path, headers=headers), Caller(path, 503), htmx=htmx)
                    for status in (403, 404):
                        response = requests.Response()
                        response.status_code = status
                        response._content = b'{"error": "not found or access denied"}'
                        with patch("apps.common.outbound_http._send", return_value=response):
                            result = self._client().get(path, follow=True, headers=headers)
                        self.assertNotEqual(result.status_code, 500)
                        self.assertNotEqual(result.status_code, 503)
                        # Invoices and proformas answer a missing or denied document with 404.
                        expected = 404 if path.startswith("/billing/") else 200
                        self.assertContains(result, wording, status_code=expected)
                        self.assertNotContains(result, OUTAGE_HEADING, status_code=expected)
