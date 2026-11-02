"""Real template/partial rendering must discover and clear windows without navigation."""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase
from django.urls import resolve
from django.utils import timezone

from apps.common.localisation import DisplayLocalisation
from apps.users.middleware import PortalAuthenticationMiddleware
from tests.services.test_maintenance_summary import envelope, window


class AccountStatusPartialTests(SimpleTestCase):
    def request(self, *, customer=1, user=7, htmx=True, session=None, path="/dashboard/account-status/"):
        request = RequestFactory().get(path, HTTP_HX_REQUEST="true" if htmx else "false")
        request.customer_id = customer
        request.user_id = user
        request.localisation = DisplayLocalisation("en", "RO", "America/New_York", "%Y-%m-%d")
        request.session = (
            session
            if session is not None
            else {
                "customer_id": 1,
                "user_id": user,
                "account_health_data": {"customer_id": str(customer), "invoice": {}, "services": {}, "tickets": {}},
                "account_health_fetched_at": time.time(),
            }
        )
        return request

    def partial(self, request):
        return resolve("/dashboard/account-status/").func(request)

    @patch("apps.api_client.services.PlatformAPIClient._make_request", return_value=envelope())
    def test_authenticated_base_retains_poll_target_when_initially_empty(self, transport):
        html = render_to_string("base.html", request=self.request())
        self.assertIn('id="account-status-region"', html)
        self.assertIn('hx-get="/dashboard/account-status/"', html)
        self.assertIn('hx-trigger="every 30s"', html)
        self.assertNotIn("No maintenance scheduled", html)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_same_cached_other_summaries_follow_empty_active_overran_and_cleared_polls(self, transport):
        transport.side_effect = [envelope(), envelope(window()), envelope(window(status="overran")), envelope()]
        session = self.request().session
        rendered = []
        for _ in range(4):
            response = self.partial(self.request(session=session))
            self.assertEqual(response.status_code, 200)
            self.assertIn("no-store", response.headers["Cache-Control"])
            self.assertIn("private", response.headers["Cache-Control"])
            self.assertIn("Cookie", response.headers["Vary"])
            rendered.append(response.content.decode())
        self.assertNotIn("Scheduled maintenance", rendered[0])
        self.assertIn("Scheduled maintenance", rendered[1])
        self.assertIn("taking longer than planned", rendered[2])
        self.assertNotIn('role="alert"', rendered[3])
        self.assertEqual(transport.call_count, 4)

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_current_selected_company_controls_signed_scope_not_query_or_login_company(self, transport):
        transport.return_value = envelope(window())
        request = self.request(customer=2)
        request.GET = {"customer_id": "999"}
        response = self.partial(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(transport.call_args.kwargs["data"], {"customer_id": 2, "user_id": 7})

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_real_company_switch_and_auth_middleware_scope_the_next_poll(self, transport):
        reads = []

        def answer(method, path, **kwargs):
            if path == "/maintenance/summary/":
                customer = kwargs["data"]["customer_id"]
                reads.append(customer)
                return envelope(window()) if customer == 1 else envelope()
            if path == "users/verify-customer-access/":
                return {
                    "success": True,
                    "data": {"has_access": True, "customer_name": "Second company", "role": "owner"},
                }
            if path == "users/customers/":
                return {"success": True, "results": [{"id": 1, "role": "owner"}, {"id": 2, "role": "owner"}]}
            if path == "/billing/summary/":
                return {"success": True, "summary": {}}
            if path == "/services/summary/":
                return {"success": True, "data": {"summary": {}}}
            if path == "/tickets/summary/":
                return {"success": True, "data": {"waiting_on_customer": 0}}
            raise AssertionError(f"Unexpected external endpoint: {path}")

        transport.side_effect = answer
        first = self.request()
        self.assertContains(self.partial(first), "Scheduled maintenance")
        switch = RequestFactory().post("/switch-customer/", {"customer_id": "2"})
        SessionMiddleware(lambda request: None).process_request(switch)
        switch.session.update(first.session)
        switch._messages = FallbackStorage(switch)
        switch._dont_enforce_csrf_checks = True  # Existing POST policy is covered separately; this test checks scope.
        response = resolve("/switch-customer/").func(switch)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(switch.session["selected_customer_id"], "2")
        next_poll = RequestFactory().get("/dashboard/account-status/", HTTP_HX_REQUEST="true")
        next_poll.session = switch.session
        now = timezone.now()
        next_poll.session.update(
            {
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=5)).isoformat(),
                "session_created_at": now.isoformat(),
                "session_auth_hash": "existing-platform-binding",
            }
        )
        next_poll.localisation = first.localisation
        response = PortalAuthenticationMiddleware(self.partial)(next_poll)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Scheduled maintenance")
        self.assertEqual(reads, [1, 2])

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_expired_or_unselected_identity_never_requests_business_data(self, transport):
        for request in [self.request(user=None), self.request(customer=None)]:
            with self.subTest(user=request.user_id, customer=request.customer_id):
                response = self.partial(request)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["HX-Redirect"], "/login/")
        transport.assert_not_called()

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_expired_poll_responses_are_empty_plain_text_with_private_login_redirect(self, transport):
        for path in ("/dashboard/account-status/", "/services/12/maintenance/"):
            for identity in ({"user": None}, {"customer": None}):
                with self.subTest(path=path, identity=identity):
                    request = self.request(path=path, **identity)
                    match = resolve(path)
                    response = match.func(request, **match.kwargs)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.content, b"")
                    self.assertEqual(response.headers["HX-Redirect"], "/login/")
                    self.assertIn("no-store", response.headers["Cache-Control"])
                    self.assertIn("private", response.headers["Cache-Control"])
                    self.assertIn("Cookie", response.headers["Vary"])
                    self.assertEqual(response.headers["Content-Type"].split(";", 1)[0], "text/plain")
                    self.assertEqual(response.charset.casefold(), "utf-8")
        transport.assert_not_called()

    @patch("apps.api_client.services.PlatformAPIClient._make_request")
    def test_unavailable_is_rendered_as_unknown_not_successful_empty(self, transport):
        transport.return_value = {"success": True, "data": {}}
        response = self.partial(self.request())
        self.assertContains(response, "Maintenance information is temporarily unavailable")

    @patch("apps.api_client.services.PlatformAPIClient._make_request", return_value=envelope())
    def test_unauthenticated_base_has_no_polling_business_endpoint(self, transport):
        request = self.request(customer=None, user=None)
        request.session = {}
        html = render_to_string("base.html", request=request)
        self.assertNotIn('id="account-status-region"', html)
        transport.assert_not_called()
