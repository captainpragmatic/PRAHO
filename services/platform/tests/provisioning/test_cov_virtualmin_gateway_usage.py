"""Coverage additions for Virtualmin usage returned through the real gateway."""

from __future__ import annotations

from collections.abc import Mapping
from unittest.mock import patch

import requests
from django.test import TestCase

from apps.common.types import Err, Retriability, retriability_of
from tests.fixtures.virtualmin.responses import list_bandwidth, list_domains
from tests.provisioning.test_cov_virtualmin_gateway_listing import gateway, http_response


def domain_payload(values: Mapping[str, object]) -> dict[str, object]:
    return {"status": "success", "data": [{"name": "alpha.example.test", "values": dict(values)}]}


class VirtualminGatewayUsageCoverageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.gateway = gateway()

    def usage(self, payload: Mapping[str, object]) -> dict[str, object]:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[http_response(payload), http_response(list_bandwidth.empty()), http_response(payload)],
        ):
            result = self.gateway.get_domain_info("alpha.example.test")
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def test_existing_multiline_fixture_reports_usage_and_unlimited_bandwidth(self) -> None:
        result = self.usage(
            list_domains.single_domain(
                domain="alpha.example.test",
                disk_quota="Unlimited",
                bandwidth_quota="Unlimited",
            )
        )
        self.assertEqual(
            result,
            {
                "disk_usage_mb": 150,
                "disk_quota_mb": None,
                "bandwidth_usage_mb": 500,
                "bandwidth_quota_mb": -1,
            },
        )

    def test_disk_field_priority_uses_database_then_home_then_generic_fields(self) -> None:
        for values, expected in (
            ({"databases_size": ["2G"], "home_size": "3G", "disk_usage": "4G"}, 2048),
            ({"db_size": "0M", "mysql_size": "3M"}, 3),
            ({"postgresql_size": "4M"}, 4),
            ({"databases_size": None, "home_directory_size": "512M"}, 512),
            ({"home_size": "", "directory_size": "6M"}, 6),
            ({"byte_size": "9M", "disk_limit": "8M", "disk_usage": "7M"}, 7),
            ({"description": "9M", "disk_usage": "invalid"}, 0),
        ):
            with self.subTest(values=values):
                self.assertEqual(self.usage(domain_payload(values))["disk_usage_mb"], expected)

    def test_disk_quota_priority_and_generic_fallback(self) -> None:
        for values, expected in (
            ({"disk_quota": "2G", "disk_limit": "3G"}, 2048),
            ({"disk_quota": "-", "quota_limit": "4M"}, 4),
            ({"size_limit": "5M"}, 5),
            ({"disk_limit": "6M"}, 6),
            ({"disk_quota": "Unlimited", "custom_disk_quota": "7M"}, 7),
            ({"custom_disk_quota": "Unlimited"}, None),
        ):
            with self.subTest(values=values):
                self.assertEqual(self.usage(domain_payload(values))["disk_quota_mb"], expected)

    def test_numeric_list_empty_and_malformed_disk_values(self) -> None:
        for value, expected in (
            (2097152, 2),
            (3145728.0, 3),
            (-1, 0),
            ([], 0),
            (["1.5G", "ignored"], 1536),
            (None, 0),
            ("broken", 0),
            ("..M", 0),
            ("1024K", 1),
            ("0.001T", 1048),
            ("unlimited", 0),
            ("-", 0),
        ):
            with self.subTest(value=value):
                self.assertEqual(self.usage(domain_payload({"db_size": value}))["disk_usage_mb"], expected)

    def test_malformed_disk_envelopes_return_zero_usage_without_inventing_quotas(self) -> None:
        payload: Mapping[str, object]
        for payload in (
            {"status": "success"},
            {"data": {}},
            {"data": []},
            {"data": [{"name": "alpha.example.test"}]},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(
                    self.usage(payload),
                    {
                        "disk_usage_mb": 0,
                        "disk_quota_mb": None,
                        "bandwidth_usage_mb": 0,
                        "bandwidth_quota_mb": None,
                    },
                )

    def test_multiple_domain_rows_use_first_row_with_usage_or_quota(self) -> None:
        payload = {
            "data": [
                "ignored",
                {"values": {}},
                {"name": "empty"},
                {"values": {"disk_quota": "5M"}},
                {"values": {"db_size": "9M"}},
            ]
        }
        self.assertEqual(self.usage(payload)["disk_quota_mb"], 5)
        self.assertEqual(self.usage(payload)["disk_usage_mb"], 0)

    def test_bandwidth_api_aggregates_matching_fields_and_avoids_fallback(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[
                http_response(domain_payload({"db_size": "2M"})),
                http_response({"bandwidth_in": "1G", "bandwidth_out": "512M", "description": "9G"}),
            ],
        ):
            result = self.gateway.get_domain_info("alpha.example.test")
        self.assertEqual(
            result.unwrap(),
            {
                "disk_usage_mb": 2,
                "disk_quota_mb": None,
                "bandwidth_usage_mb": 1536,
                "bandwidth_quota_mb": None,
            },
        )

    def test_bandwidth_failure_falls_back_to_domain_usage_and_quota(self) -> None:
        for failure in (
            http_response({"status": "failure", "error": "unknown command"}),
            requests.exceptions.SSLError("fixture"),
            RuntimeError("transport fixture"),
        ):
            with (
                self.subTest(failure=failure),
                patch(
                    "apps.provisioning.virtualmin_gateway.safe_request",
                    side_effect=[
                        http_response(domain_payload({"db_size": "1M"})),
                        failure,
                        http_response(domain_payload({"Traffic used": ["2G"], "Bandwidth quota bytes": ["3145728"]})),
                    ],
                ),
            ):
                result = self.gateway.get_domain_info("alpha.example.test")
            self.assertEqual(
                result.unwrap(),
                {
                    "disk_usage_mb": 1,
                    "disk_quota_mb": None,
                    "bandwidth_usage_mb": 2048,
                    "bandwidth_quota_mb": 3,
                },
            )

    def test_bandwidth_fallback_ignores_invalid_quota_and_uses_next_valid_field(self) -> None:
        result = self.usage(
            domain_payload(
                {
                    "Traffic usage": "nonsense",
                    "Transfer used": "3M",
                    "Bandwidth quota bytes": "invalid",
                    "Bandwidth limit": "4G",
                }
            )
        )
        self.assertEqual(result["bandwidth_usage_mb"], 3)
        self.assertEqual(result["bandwidth_quota_mb"], 4096)

    def test_failed_fallback_keeps_successful_disk_information(self) -> None:
        for fallback in (
            requests.exceptions.SSLError("fixture"),
            http_response({"status": "failure", "error": "invalid domain"}),
        ):
            with (
                self.subTest(fallback=fallback),
                patch(
                    "apps.provisioning.virtualmin_gateway.safe_request",
                    side_effect=[
                        http_response(domain_payload({"home_size": "7M"})),
                        http_response(list_bandwidth.empty()),
                        fallback,
                    ],
                ),
            ):
                result = self.gateway.get_domain_info("alpha.example.test")
            self.assertEqual(
                result.unwrap(),
                {
                    "disk_usage_mb": 7,
                    "disk_quota_mb": None,
                    "bandwidth_usage_mb": 0,
                    "bandwidth_quota_mb": None,
                },
            )

    def test_failed_disk_query_returns_error_instead_of_usage(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "failure", "error": "quota exceeded"}),
        ):
            result = self.gateway.get_domain_info("alpha.example.test")
        self.assertIsInstance(result, Err)
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertIn("Failed to get disk usage: quota exceeded", result.unwrap_err())
