"""Ticket list view: status-param clamping and tab-label laziness.

The shared filter component gives only the active tab tabindex="0" (roving
tabindex). An unvalidated ?status= that matches no tab would leave every tab
tabindex="-1" — the whole tablist becomes unreachable by keyboard — so the view
must clamp unknown values to the All tab, mirroring the services view's
_validated_status_filter.
"""
from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils.functional import Promise

from apps.tickets.views import TICKET_STATUS_TABS


class TicketStatusTabConfigTests(TestCase):
    def test_tab_labels_are_lazy_for_per_request_language(self) -> None:
        """Module-level labels must be lazy or they freeze to the import-time locale."""
        for tab in TICKET_STATUS_TABS:
            self.assertIsInstance(tab["label"], Promise, f"tab {tab['value']!r} label is not lazy")


class TicketListStatusClampTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 2
        session.save()

    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    def test_unknown_status_falls_back_to_all_tab(self, mock_get: object, mock_summary: object) -> None:
        mock_get.return_value = {"results": [], "count": 0}
        mock_summary.return_value = {"open_tickets": 0}

        response = self.client.get(reverse("tickets:list"), {"status": "bogus"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["status_filter"], "")
        # The All tab is selected on both the desktop and mobile tablists, so
        # the roving tabindex keeps the widget keyboard-reachable.
        self.assertEqual(response.content.decode().count('aria-selected="true"'), 2)

    @patch("apps.tickets.views.tickets_api.get_tickets_summary")
    @patch("apps.tickets.views.tickets_api.get_customer_tickets")
    def test_known_status_is_preserved(self, mock_get: object, mock_summary: object) -> None:
        mock_get.return_value = {"results": [], "count": 0}
        mock_summary.return_value = {"open_tickets": 0}

        response = self.client.get(reverse("tickets:list"), {"status": "open"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["status_filter"], "open")
