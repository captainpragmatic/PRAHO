from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.services.services import ServicesAPIClient

# Canonical shape emitted by the platform /services/summary/ handler at
# services/platform/apps/api/services/views.py:264-277. Both portal-side
# fallback paths MUST return a dict with this exact key set so account_health
# (which reads expiring_soon, suspended_services) and dashboard (which reads
# active_services) don't degrade silently when the platform call falls back.
CANONICAL_SERVICES_SUMMARY_KEYS = {
    "total_services",
    "active_services",
    "suspended_services",
    "pending_services",
    "overdue",
    "expiring_soon",
    "status_counts",
    "total_monthly_cost",
    "total_monthly_cost_with_vat",
    "total_disk_usage_gb",
    "total_bandwidth_usage_gb",
    "service_types",
    "recent_services",
}
SERVICE_STATUS_COUNT_KEYS = {
    "pending",
    "provisioning",
    "active",
    "suspended",
    "failed",
    "terminated",
    "expired",
}


class ServicesAPIClientRateLimitTests(SimpleTestCase):
    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_get_services_summary_reraises_rate_limit_error(self, mock_make_request) -> None:
        mock_make_request.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=8, is_rate_limited=True
        )
        client = ServicesAPIClient()

        with self.assertRaises(PlatformAPIError):
            client.get_services_summary(customer_id=1, user_id=2)


class ServicesAPIClientSummaryShapeTests(SimpleTestCase):
    """Success path and both fallback paths must return the canonical key set
    (PR #164 review finding H6)."""

    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_unexpected_response_format_fallback_matches_canonical(self, mock_make_request) -> None:
        mock_make_request.return_value = {"success": False, "weird": "envelope"}
        result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_SERVICES_SUMMARY_KEYS)

        # Unknown counts are None (badges hidden), never a fabricated all-zero dict.
        self.assertIsNone(result["status_counts"])

    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_platform_api_error_fallback_matches_canonical(self, mock_make_request) -> None:
        mock_make_request.side_effect = PlatformAPIError(
            "platform down", status_code=500, is_rate_limited=False
        )
        result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_SERVICES_SUMMARY_KEYS)

    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_success_response_passes_through_canonical_shape(self, mock_make_request) -> None:
        canonical = dict.fromkeys(CANONICAL_SERVICES_SUMMARY_KEYS, 0)
        canonical["service_types"] = {}
        canonical["recent_services"] = []
        canonical["status_counts"] = dict.fromkeys(SERVICE_STATUS_COUNT_KEYS, 0)
        canonical["total_monthly_cost"] = 0.0
        canonical["total_monthly_cost_with_vat"] = 0.0
        canonical["total_disk_usage_gb"] = 0.0
        canonical["total_bandwidth_usage_gb"] = 0.0
        mock_make_request.return_value = {"success": True, "data": {"summary": canonical}}
        result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_SERVICES_SUMMARY_KEYS)

    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_success_without_status_counts_normalizes_to_none(self, mock_make_request) -> None:
        """Deploy skew: an older platform doesn't send status_counts yet.

        The client must surface None (badges hidden) instead of letting the
        view fabricate all-zero badges next to a real total.
        """
        summary = dict.fromkeys(CANONICAL_SERVICES_SUMMARY_KEYS - {"status_counts"}, 0)
        summary["service_types"] = {}
        summary["recent_services"] = []
        mock_make_request.return_value = {"success": True, "data": {"summary": summary}}

        result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)

        self.assertIn("status_counts", result)
        self.assertIsNone(result["status_counts"])

    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_success_with_invalid_status_counts_normalizes_to_none(self, mock_make_request) -> None:
        """A malformed status_counts must never reach the view as a non-dict."""
        for bad in (None, ["active"], "active", 7):
            with self.subTest(bad=bad):
                summary = dict.fromkeys(CANONICAL_SERVICES_SUMMARY_KEYS, 0)
                summary["service_types"] = {}
                summary["recent_services"] = []
                summary["status_counts"] = bad
                mock_make_request.return_value = {"success": True, "data": {"summary": summary}}

                result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)

                self.assertIsNone(result["status_counts"])
