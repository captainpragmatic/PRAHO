"""The services dashboard widget route, found untouched by any test.

`services_dashboard_widget` rendered `services/partials/dashboard_widget.html`, which did not
exist anywhere in the repo: the route was named, routable, and reachable, and every request to
it raised `TemplateDoesNotExist`. No test had ever requested this URL.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class ServicesDashboardWidgetTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.services.views.services_api.get_customer_services")
    @patch("apps.services.views.services_api.get_services_summary")
    def test_the_active_count_the_platform_reports_is_shown(self, summary, services) -> None:
        summary.return_value = {"active_services": 3, "total_services": 5}
        services.return_value = {"results": []}

        response = self.client.get(reverse("services:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "3")
        self.assertContains(response, "5")

    @patch("apps.services.views.services_api.get_customer_services")
    @patch("apps.services.views.services_api.get_services_summary")
    def test_a_recent_service_name_renders(self, summary, services) -> None:
        summary.return_value = {"active_services": 1, "total_services": 1}
        services.return_value = {
            "results": [{"id": 42, "service_name": "web-hosting-plus", "domain": "example.com"}]
        }

        response = self.client.get(reverse("services:dashboard_widget"))

        self.assertContains(response, "web-hosting-plus")
        self.assertContains(response, "example.com")

    @patch("apps.services.views.services_api.get_customer_services")
    @patch("apps.services.views.services_api.get_services_summary")
    def test_no_services_says_so_rather_than_nothing(self, summary, services) -> None:
        summary.return_value = {"active_services": 0, "total_services": 0}
        services.return_value = {"results": []}

        response = self.client.get(reverse("services:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No services yet")

    def test_an_unauthenticated_request_is_redirected_not_rendered(self) -> None:
        self.client.session.flush()
        response = self.client.get(reverse("services:dashboard_widget"))
        self.assertEqual(response.status_code, 302)
