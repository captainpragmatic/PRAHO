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

    def test_tab_set_exactly_mirrors_platform_statuses(self) -> None:
        """Drift guardrail: the tab list is exactly All + the 7 platform statuses.

        If the platform Service.STATUS_CHOICES gains or loses a status, update
        BOTH the PLATFORM_SERVICE_STATUSES mirror above and SERVICE_STATUS_TABS —
        this exact-set + count assertion fails on any one-sided edit, including
        a re-introduced dead tab (e.g. "cancelled").
        """
        tab_values = [t["value"] for t in SERVICE_STATUS_TABS]
        self.assertEqual(len(tab_values), len(set(tab_values)), "duplicate tab values")
        self.assertEqual(set(tab_values), PLATFORM_SERVICE_STATUSES | {""})
        self.assertEqual(len(tab_values), len(PLATFORM_SERVICE_STATUSES) + 1)

    def test_newest_platform_status_has_a_tab(self) -> None:
        # Canary pinned to the LAST entry of the platform STATUS_CHOICES tuple
        # (provisioning/service_models.py). If a status is appended there, this
        # name documents where to look when the mirror set needs updating.
        self.assertIn("expired", {t["value"] for t in SERVICE_STATUS_TABS})

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

    @patch("apps.services.views.services_api.get_services_summary")
    @patch("apps.services.views.services_api.get_customer_services")
    def test_list_tabs_include_all_and_per_status_counts(self, mock_get: object, mock_summary: object) -> None:
        mock_get.return_value = {"results": [], "count": 0}
        mock_summary.return_value = {
            "active_services": 2,
            "total_services": 3,
            "status_counts": {
                "pending": 1,
                "provisioning": 0,
                "active": 2,
                "suspended": 0,
                "failed": 0,
                "terminated": 0,
                "expired": 0,
            },
        }

        response = self.client.get(reverse("services:list"))

        self.assertEqual(response.status_code, 200)
        tabs = response.context["filter_tabs"]
        self.assertEqual(
            {tab["value"]: tab["count"] for tab in tabs},
            {
                "": 3,
                "active": 2,
                "pending": 1,
                "provisioning": 0,
                "suspended": 0,
                "failed": 0,
                "terminated": 0,
                "expired": 0,
            },
        )
        self.assertTrue(all(tab["show_count"] for tab in tabs))
        content = response.content.decode()
        tab_count = content.count('role="tab" data-tab-value=')
        self.assertEqual(content.count('aria-controls="services-content"'), tab_count)
        self.assertEqual(content.count('onkeydown="handleTabKeydown(event, this)"'), tab_count)
        self.assertIn(
            'id="services-content" role="tabpanel" tabindex="0" aria-label="Filtered results"',
            content,
        )

        self.assertContains(response, 'data-tab-count="0"')

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

    @patch("apps.services.views.services_api.get_customer_services")
    def test_search_no_match_shows_search_empty_not_status_empty(self, mock_get: object) -> None:
        """A status tab WITH services + a search term matching none of them must
        say the search returned nothing — not that the status tab is empty.

        Regression: with status_filter set, an empty *search* result rendered the
        status-tab-empty heading ('No <Status> services'), which is misleading —
        the tab does have services, the query just matched none.
        """
        # API returns a real service for the "active" tab; the search term below
        # matches none of its fields, so _filter_services_by_query empties the list.
        mock_get.return_value = {
            "results": [{"service_name": "Web Hosting", "status": "active", "domain": "example.com"}],
            "count": 1,
        }

        resp = self.client.get(
            reverse("services:search_api"),
            {"status": "active", "q": "zzz-no-such-service"},
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertNotIn("No Active services", body)
        self.assertIn("No services match", body)
        self.assertIn("zzz-no-such-service", body)

    @patch("apps.services.views.services_api.get_customer_services")
    def test_search_empty_state_escapes_query(self, mock_get: object) -> None:
        """The echoed search term is user input — it must be autoescaped."""
        mock_get.return_value = {"results": [], "count": 0}

        resp = self.client.get(reverse("services:search_api"), {"q": "<script>alert(2)</script>"})

        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertIn("No services match", body)
        self.assertNotIn("<script>alert(2)</script>", body)

    @patch("apps.services.views.services_api.get_customer_services")
    def test_unknown_status_is_not_reflected_in_search_partial(self, mock_get: object) -> None:
        """?status= is attacker-influenced; unknown values must not be echoed.

        Output is autoescaped, so this is content spoofing rather than XSS —
        but 'No Visit Evil.Com Now services' in an authenticated page is still
        a real reflection. Unknown statuses fall back to the All tab.
        """
        mock_get.return_value = {"results": [], "count": 0}

        resp = self.client.get(reverse("services:search_api"), {"status": "visit_evil.com_now"})

        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertNotIn("Evil", body)
        self.assertNotIn("visit_evil", body)
        # the bogus value is not forwarded to the platform API either
        self.assertEqual(mock_get.call_args.kwargs.get("status"), "")

    @patch("apps.services.views.services_api.get_services_summary")
    @patch("apps.services.views.services_api.get_customer_services")
    def test_unknown_status_is_dropped_on_list_view(self, mock_get: object, mock_summary: object) -> None:
        mock_get.return_value = {"results": [], "count": 0}
        mock_summary.return_value = {"active_services": 0, "total_services": 0}

        resp = self.client.get(reverse("services:list"), {"status": "<script>alert(1)</script>"})

        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertNotIn("alert(1)", body)
        self.assertEqual(mock_get.call_args.kwargs.get("status"), "")
