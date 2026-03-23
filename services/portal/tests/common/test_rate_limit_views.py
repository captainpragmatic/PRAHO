from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import Client, RequestFactory, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.dashboard.views import dashboard_view


@override_settings(ROOT_URLCONF="config.urls", SESSION_ENGINE="django.contrib.sessions.backends.cache")
class ListViewsRateLimitTests(SimpleTestCase):
    def setUp(self) -> None:
        self.client = Client()

    def _set_customer_session(self, include_membership: bool = False) -> None:
        session = self.client.session
        session["customer_id"] = "1"
        session["user_id"] = 15
        session["email"] = "customer@example.com"
        if include_membership:
            session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
            session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.services.views.services_api.get_customer_services")
    def test_services_list_shows_rate_limited_state(self, mock_get_services) -> None:
        self._set_customer_session()
        mock_get_services.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=9, is_rate_limited=True
        )

        response = self.client.get("/services/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Temporarily rate limited")
        self.assertTrue(response.context["rate_limited"])
        # Inline alert only — no duplicate Django toast message
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertFalse(any("many requests right now" in message.lower() for message in messages))

    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    def test_tickets_list_shows_rate_limited_state(self, mock_get_tickets) -> None:
        self._set_customer_session()
        mock_get_tickets.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=7, is_rate_limited=True
        )

        response = self.client.get("/tickets/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Temporarily rate limited")
        self.assertTrue(response.context["rate_limited"])
        # Inline alert only — no duplicate Django toast message
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertFalse(any("many requests right now" in message.lower() for message in messages))

    @patch("apps.billing.views._fetch_filtered_documents")
    def test_billing_list_shows_rate_limited_state(self, mock_fetch_documents) -> None:
        self._set_customer_session(include_membership=True)
        mock_fetch_documents.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=11, is_rate_limited=True
        )

        response = self.client.get("/billing/invoices/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Temporarily rate limited")
        self.assertTrue(response.context["rate_limited"])
        # Inline alert only — no duplicate Django toast message
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertFalse(any("many requests right now" in message.lower() for message in messages))


class DashboardRateLimitTests(SimpleTestCase):
    def _request(self):
        request = RequestFactory().get("/dashboard/")
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request._messages = FallbackStorage(request)
        request.session["customer_id"] = "1"
        request.session["email"] = "customer@example.com"
        request.user = SimpleNamespace(id=15)
        return request

    @patch("apps.dashboard.views._get_billing_data")
    @patch("apps.dashboard.views.render")
    def test_dashboard_sets_rate_limited_context(self, mock_render, mock_billing_data) -> None:
        request = self._request()
        mock_billing_data.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=6, is_rate_limited=True
        )

        captured_context = {}

        def _capture_render(_request, _template, context):
            captured_context.update(context)
            return HttpResponse("ok")

        mock_render.side_effect = _capture_render

        response = dashboard_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(captured_context["rate_limited"])
        self.assertIn("billing", captured_context["sections_rate_limited"])
        self.assertIn("Please try again in", captured_context["rate_limit_message"])
        # Inline alert only — no duplicate Django toast message
        queued = [str(message) for message in get_messages(request)]
        self.assertFalse(any("many requests right now" in message.lower() for message in queued))
