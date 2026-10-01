"""The tickets dashboard widget route, found untouched by any test.

`tickets_dashboard_widget` rendered `tickets/partials/dashboard_widget.html`, which did not
exist anywhere in the repo: the route was named, routable, and reachable, and every request to
it raised `TemplateDoesNotExist`. No test had ever requested this URL.
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.tickets.services import PlatformAPIError


class TicketsDashboardWidgetTests(TestCase):
    def setUp(self) -> None:
        # session_auth_hash/validated_at/next_validate_at keep PortalAuthenticationMiddleware inside
        # its soft-TTL window, so it skips revalidation entirely. Omitting them makes the middleware
        # call the UNMOCKED api_client.validate_session_secure on every request - whether that then
        # fails open or closed depends on exactly how the failure manifests, so a test relying on it
        # is really asserting "whatever fallback shape validate_session_secure happens to hit today."
        now = timezone.now()
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["session_auth_hash"] = "test-session"
        session["validated_at"] = now.isoformat()
        session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
        session.save()

    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    def test_the_open_count_the_platform_reports_is_shown(self, summary, tickets) -> None:
        summary.return_value = {"open_tickets": 2, "total_tickets": 7}
        tickets.return_value = {"results": []}

        response = self.client.get(reverse("tickets:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        # A bare "2"/"7" also matches Tailwind utility classes like gap-3 or p-3 anywhere on the
        # page, so it would still pass with the count forced to 0. The full stat-box fragment ties
        # the digit to the specific element it is meant to appear in.
        self.assertContains(response, '<div class="text-2xl font-bold text-white">2</div>', html=True)
        self.assertContains(response, '<div class="text-2xl font-bold text-white">7</div>', html=True)

    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    def test_a_recent_ticket_number_renders(self, summary, tickets) -> None:
        summary.return_value = {"open_tickets": 1, "total_tickets": 1}
        tickets.return_value = {
            "results": [{"id": 99, "ticket_number": "TCK-000099", "subject": "Invoice question"}]
        }

        response = self.client.get(reverse("tickets:dashboard_widget"))

        self.assertContains(response, "TCK-000099")
        self.assertContains(response, "Invoice question")

    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    def test_no_tickets_says_so_rather_than_nothing(self, summary, tickets) -> None:
        summary.return_value = {"open_tickets": 0, "total_tickets": 0}
        tickets.return_value = {"results": []}

        response = self.client.get(reverse("tickets:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No support tickets yet")

    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    def test_an_undeclared_platform_failure_says_so_rather_than_zero(self, summary) -> None:
        """A bare platform error (not rate-limited, not a declared outage) used to fall through to
        the same branch as a genuinely empty account - a real failure rendered as "no support
        tickets yet". Reverting the template's `error` arm makes this fail with that exact wrong
        text."""
        summary.side_effect = PlatformAPIError("Internal platform error", status_code=500)

        response = self.client.get(reverse("tickets:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unable to load your tickets right now.")
        self.assertNotContains(response, "No support tickets yet")

    def test_an_unauthenticated_request_is_redirected_not_rendered(self) -> None:
        self.client.session.flush()
        response = self.client.get(reverse("tickets:dashboard_widget"))
        self.assertEqual(response.status_code, 302)
