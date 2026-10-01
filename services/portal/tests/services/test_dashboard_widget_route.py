"""The services dashboard widget route, found untouched by any test.

`services_dashboard_widget` rendered `services/partials/dashboard_widget.html`, which did not
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

from apps.services.services import PlatformAPIError


class ServicesDashboardWidgetTests(TestCase):
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

    @patch("apps.services.views.services_api.get_customer_services")
    @patch("apps.services.views.services_api.get_services_summary")
    def test_the_active_count_the_platform_reports_is_shown(self, summary, services) -> None:
        summary.return_value = {"active_services": 3, "total_services": 5}
        services.return_value = {"results": []}

        response = self.client.get(reverse("services:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        # A bare "3"/"5" also matches Tailwind utility classes like gap-3 or p-3 anywhere on the
        # page, so it would still pass with the count forced to 0. The full stat-box fragment ties
        # the digit to the specific element it is meant to appear in.
        self.assertContains(response, '<div class="text-2xl font-bold text-white">3</div>', html=True)
        self.assertContains(response, '<div class="text-2xl font-bold text-white">5</div>', html=True)

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

    @patch("apps.services.views.services_api.get_services_summary")
    def test_an_undeclared_platform_failure_says_so_rather_than_zero(self, summary) -> None:
        """A bare platform error (not rate-limited, not a declared outage) used to fall through to
        the same branch as a genuinely empty account - a real failure rendered as "no services
        yet". Reverting the template's `error` arm makes this fail with that exact wrong text."""
        summary.side_effect = PlatformAPIError("Internal platform error", status_code=500)

        response = self.client.get(reverse("services:dashboard_widget"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unable to load your services right now.")
        self.assertNotContains(response, "No services yet")

    def test_an_unauthenticated_request_is_redirected_not_rendered(self) -> None:
        self.client.session.flush()
        response = self.client.get(reverse("services:dashboard_widget"))
        self.assertEqual(response.status_code, 302)
