"""Coverage additions for live Virtualmin listing and reconciliation paths."""

from __future__ import annotations

import json
from collections.abc import Mapping
from unittest.mock import patch

import requests
from django.test import TestCase

from apps.common.types import Err, Retriability, retriability_of
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from tests.provisioning.test_virtualmin_credentials import create_test_virtualmin_server


def gateway() -> VirtualminGateway:
    server = create_test_virtualmin_server(hostname="coverage.example.test", status="active")
    return VirtualminGateway(VirtualminConfig(server=server, use_credential_vault=False))


def http_response(payload: Mapping[str, object] | str, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.encoding = "utf-8"
    response._content = (payload if isinstance(payload, str) else json.dumps(dict(payload))).encode()
    response._content_consumed = True
    return response


class VirtualminGatewayListingCoverageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.gateway = gateway()

    def test_domain_table_filters_headers_and_preserves_description(self) -> None:
        payload = {
            "status": "success",
            "data": [
                {"name": "Domain Username Description"},
                {"name": "--- --- ---"},
                {"name": " "},
                {"name": "incomplete"},
                {"name": "alpha.example.test alice Premium hosting"},
                {"name": "beta.example.test bob"},
                {"id": 7},
            ],
        }
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)):
            full = self.gateway.list_domains()
            names = self.gateway.list_domains(name_only=True)
        self.assertEqual(
            full.unwrap(),
            [
                {"domain": "alpha.example.test", "username": "alice", "description": "Premium hosting"},
                {"domain": "beta.example.test", "username": "bob", "description": ""},
            ],
        )
        self.assertEqual(names.unwrap(), ["alpha.example.test", "beta.example.test"])

    def test_explicit_domain_collection_and_empty_payload(self) -> None:
        domains = [{"domain": "alpha.example.test", "username": "alice"}]
        for payload, expected in (
            ({"status": "success", "domains": domains}, domains),
            ({"status": "success"}, []),
        ):
            with (
                self.subTest(payload=payload),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)),
            ):
                self.assertEqual(self.gateway.list_domains().unwrap(), expected)

    def test_templates_accept_documented_collections_and_filter_table_headers(self) -> None:
        for payload, expected in (
            ({"templates": [" Basic ", {"name": "Premium Hosting"}]}, ["Basic", "Premium Hosting"]),
            ({"data": [{"name": "Template ID"}, {"name": "---"}, {"name": "Premium Hosting"}]}, ["Premium Hosting"]),
            ({"raw_response": " Basic\n\n Premium Hosting \n"}, ["Basic", "Premium Hosting"]),
            ({"templates": []}, []),
        ):
            with (
                self.subTest(payload=payload),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)),
            ):
                self.assertEqual(self.gateway.list_templates().unwrap(), expected)

    def test_templates_refuse_malformed_or_unrecognized_payloads(self) -> None:
        payload: Mapping[str, object]
        for payload in (
            {"templates": {}},
            {"data": {}},
            {"raw_response": ""},
            {"templates": [7]},
            {"templates": [" "]},
            {"data": [{"id": 7}]},
            {},
        ):
            with (
                self.subTest(payload=payload),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)),
            ):
                result = self.gateway.list_templates()
            self.assertIsInstance(result, Err)
            self.assertIn("unrecognized response shape", result.unwrap_err())

    def test_owner_listing_normalizes_scalar_list_and_missing_usernames(self) -> None:
        payload = {
            "data": [
                {"name": "alpha.example.test", "values": {"Username": ["alice"]}},
                {"name": "beta.example.test", "values": {"Username": "bob"}},
                {"name": "gamma.example.test", "values": {"Username": []}},
                {"name": "delta.example.test", "values": None},
                {"values": {}},
                "ignored",
            ]
        }
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)):
            result = self.gateway.list_domains_with_owners()
        self.assertEqual(
            result.unwrap(),
            [
                {"domain": "alpha.example.test", "username": "alice"},
                {"domain": "beta.example.test", "username": "bob"},
                {"domain": "gamma.example.test", "username": ""},
                {"domain": "delta.example.test", "username": ""},
            ],
        )

    def test_state_and_owner_distinguish_absent_disabled_and_indeterminate(self) -> None:
        domain = "alpha.example.test"
        for values, enabled, owner in (
            ({"Status": ["Enabled"], "Username": ["alice"]}, True, "alice"),
            ({"Status": "Disabled", "Username": "bob"}, False, "bob"),
            ({"Status": [], "Username": []}, None, ""),
            ({}, None, ""),
        ):
            payload = {"data": [{"name": "other.example.test"}, {"name": domain, "values": values}]}
            with (
                self.subTest(values=values),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)),
            ):
                self.assertEqual(
                    self.gateway.get_domain_state(domain).unwrap(),
                    {
                        "exists": True,
                        "enabled": enabled,
                        "owner": owner,
                    },
                )
                self.assertEqual(self.gateway.get_domain_owner(domain).unwrap(), owner)
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"data": [{"name": "other.example.test"}, "ignored"]}),
        ):
            self.assertEqual(
                self.gateway.get_domain_state(domain).unwrap(),
                {
                    "exists": False,
                    "enabled": None,
                    "owner": "",
                },
            )
            self.assertIsNone(self.gateway.get_domain_owner(domain).unwrap())

    def test_reconciliation_probes_refuse_unrecognized_shapes(self) -> None:
        payload: Mapping[str, object]
        for payload in ({}, {"data": {}}, {"data": None}):
            for operation in (
                self.gateway.list_domains_with_owners,
                lambda: self.gateway.get_domain_state("alpha.example.test"),
                lambda: self.gateway.get_domain_owner("alpha.example.test"),
            ):
                with (
                    self.subTest(payload=payload, operation=operation),
                    patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload)),
                ):
                    result = operation()
                self.assertIsInstance(result, Err)
                self.assertIn("unrecognized response shape", result.unwrap_err())

    def test_read_wrappers_preserve_transport_and_application_retriability(self) -> None:
        operations = (
            self.gateway.get_server_info,
            self.gateway.list_domains,
            self.gateway.list_templates,
            self.gateway.list_domains_with_owners,
            lambda: self.gateway.get_domain_state("alpha.example.test"),
            lambda: self.gateway.get_domain_owner("alpha.example.test"),
            lambda: self.gateway.get_domain_info("alpha.example.test"),
        )
        for operation in operations:
            for failure, signal, detail in (
                (requests.exceptions.SSLError("certificate rejected"), Retriability.NOT_RETRIABLE, "SSL error"),
                (
                    http_response({"status": "failure", "error": "server busy", "code": "503"}),
                    Retriability.RETRIABLE,
                    "server busy",
                ),
                (
                    http_response({"status": "failure", "error": "invalid domain", "error_code": "400"}),
                    Retriability.NOT_RETRIABLE,
                    "invalid domain",
                ),
                (
                    http_response({"status": "failure", "error": "unclassified refusal"}),
                    Retriability.UNKNOWN,
                    "unclassified refusal",
                ),
            ):
                with (
                    self.subTest(operation=operation, detail=detail),
                    patch(
                        "apps.provisioning.virtualmin_gateway.safe_request",
                        side_effect=failure if isinstance(failure, Exception) else None,
                        return_value=failure,
                    ),
                ):
                    result = operation()
                self.assertIsInstance(result, Err)
                self.assertEqual(retriability_of(result), signal)
                self.assertIn(detail, result.unwrap_err())

    def test_health_probe_returns_remote_information_and_transport_failure(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "success", "hostname": "remote.example.test"}),
        ):
            result = self.gateway.test_connection().unwrap()
            self.assertTrue(result["healthy"])
            self.assertEqual(result["server"], "coverage.example.test")
            self.assertEqual(result["data"]["hostname"], "remote.example.test")
            self.assertGreaterEqual(result["response_time"], 0)
            self.assertTrue(self.gateway.ping_server())
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request", side_effect=requests.exceptions.SSLError("fixture")
        ):
            failed = self.gateway.test_connection()
            self.assertFalse(self.gateway.ping_server())
        self.assertIsInstance(failed, Err)
        self.assertEqual(retriability_of(failed), Retriability.NOT_RETRIABLE)
        self.assertIn("Connection test failed", failed.unwrap_err())
