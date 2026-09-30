"""The tickets dashboard widget route, found untouched by any test.

`tickets_dashboard_widget` rendered `tickets/partials/dashboard_widget.html`, which did not
exist anywhere in the repo: the route was named, routable, and reachable, and every request to
it raised `TemplateDoesNotExist`. No test had ever requested this URL.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class TicketsDashboardWidgetTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    def test_the_open_count_the_platform_reports_is_shown(self, summary, tickets) -> None:
        summary.return_value = {"open_tickets": 2, "total_tickets": 7}
        tickets.return_value = {"results": []}

        response = self.client.get(reverse("tickets:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "2")
        self.assertContains(response, "7")

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

    def test_an_unauthenticated_request_is_redirected_not_rendered(self) -> None:
        self.client.session.flush()
        response = self.client.get(reverse("tickets:dashboard_widget"))
        self.assertEqual(response.status_code, 302)
