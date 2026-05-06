from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.tickets.services import TicketsAPIClient

# Canonical shape returned by the platform /tickets/summary/ endpoint after the
# C2 fix that adds waiting_on_customer. Both fallback paths in
# TicketsAPIClient.get_tickets_summary MUST return a dict with exactly this key
# set so consumers (dashboard, account_health) get a stable schema regardless
# of whether the platform call succeeded, returned an unexpected envelope, or
# raised a non-rate-limit error.
CANONICAL_TICKETS_SUMMARY_KEYS = {
    "total_tickets",
    "open_tickets",
    "pending_tickets",
    "resolved_tickets",
    "waiting_on_customer",
    "average_response_time_hours",
    "satisfaction_rating",
    "recent_tickets",
}


class TicketsAPIClientRateLimitTests(SimpleTestCase):
    @patch("apps.tickets.services.TicketsAPIClient._make_request")
    def test_get_tickets_summary_reraises_rate_limit_error(self, mock_make_request) -> None:
        mock_make_request.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=8, is_rate_limited=True
        )
        client = TicketsAPIClient()

        with self.assertRaises(PlatformAPIError):
            client.get_tickets_summary(customer_id=1, user_id=2)


class TicketsAPIClientSummaryShapeTests(SimpleTestCase):
    """The success path and both fallback paths must return the same key set
    so consumers don't need to handle multiple shapes (regression of PR #164
    review finding H5)."""

    @patch("apps.tickets.services.TicketsAPIClient._make_request")
    def test_unexpected_response_format_fallback_matches_canonical(self, mock_make_request) -> None:
        mock_make_request.return_value = {"success": False, "weird": "envelope"}
        result = TicketsAPIClient().get_tickets_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_TICKETS_SUMMARY_KEYS)

    @patch("apps.tickets.services.TicketsAPIClient._make_request")
    def test_platform_api_error_fallback_matches_canonical(self, mock_make_request) -> None:
        mock_make_request.side_effect = PlatformAPIError(
            "platform down", status_code=500, is_rate_limited=False
        )
        result = TicketsAPIClient().get_tickets_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_TICKETS_SUMMARY_KEYS)

    @patch("apps.tickets.services.TicketsAPIClient._make_request")
    def test_success_response_passes_through_canonical_shape(self, mock_make_request) -> None:
        canonical = dict.fromkeys(CANONICAL_TICKETS_SUMMARY_KEYS, 0)
        canonical["recent_tickets"] = []
        canonical["average_response_time_hours"] = 0.0
        canonical["satisfaction_rating"] = 0.0
        mock_make_request.return_value = {"success": True, "data": canonical}
        result = TicketsAPIClient().get_tickets_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_TICKETS_SUMMARY_KEYS)
