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
    "total_monthly_cost",
    "total_monthly_cost_with_vat",
    "total_disk_usage_gb",
    "total_bandwidth_usage_gb",
    "service_types",
    "recent_services",
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
        canonical["total_monthly_cost"] = 0.0
        canonical["total_monthly_cost_with_vat"] = 0.0
        canonical["total_disk_usage_gb"] = 0.0
        canonical["total_bandwidth_usage_gb"] = 0.0
        mock_make_request.return_value = {"success": True, "data": {"summary": canonical}}
        result = ServicesAPIClient().get_services_summary(customer_id=1, user_id=2)
        self.assertEqual(set(result.keys()), CANONICAL_SERVICES_SUMMARY_KEYS)
