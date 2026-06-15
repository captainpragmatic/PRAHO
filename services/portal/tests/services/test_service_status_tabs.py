"""Tests for My Services status filter tabs (#101).

Covers:
- SERVICE_STATUS_TABS exposes a tab for every real Service status and no longer
  carries the dead "cancelled" tab (no such platform status).
- The HTMX search/filter endpoint threads status_filter into the partial so the
  empty state can render a status-specific message.
"""
from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from apps.services.views import SERVICE_STATUS_TABS

# The platform Service.STATUS_CHOICES (provisioning/service_models.py).
PLATFORM_SERVICE_STATUSES = {
    "pending",
    "provisioning",
    "active",
    "suspended",
    "failed",
    "terminated",
    "expired",
}


class ServiceStatusTabConfigTests(TestCase):
    def test_every_real_status_has_a_tab(self) -> None:
        tab_values = {t["value"] for t in SERVICE_STATUS_TABS}
        missing = PLATFORM_SERVICE_STATUSES - tab_values
        self.assertEqual(missing, set(), f"statuses without a filter tab: {missing}")

    def test_includes_all_services_default_tab(self) -> None:
        self.assertEqual(SERVICE_STATUS_TABS[0]["value"], "", "first tab must be the 'All' default")

    def test_no_dead_cancelled_tab(self) -> None:
        # "cancelled" is not a Service status — it would be a permanently-empty tab.
        tab_values = {t["value"] for t in SERVICE_STATUS_TABS}
        self.assertNotIn("cancelled", tab_values)

    def test_each_tab_has_styling_keys(self) -> None:
        for tab in SERVICE_STATUS_TABS:
            self.assertIn("label", tab)
            self.assertIn("border_class", tab)
            self.assertIn("text_class", tab)


class ServiceSearchStatusEmptyStateTests(TestCase):
    """The HTMX filter endpoint renders a status-aware empty state."""

    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session.save()

    @patch("apps.services.views.services_api.get_customer_services")
    def test_filtered_empty_state_names_the_status(self, mock_get: object) -> None:
        mock_get.return_value = {"results": [], "count": 0}

        resp = self.client.get(reverse("services:search_api"), {"status": "expired"})

        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        # status-aware empty state (status_label title-cases "expired" -> "Expired")
        self.assertIn("No Expired services", body)
        self.assertIn("View all services", body)
        # the API was filtered by the requested status
        self.assertEqual(mock_get.call_args.kwargs.get("status"), "expired")
