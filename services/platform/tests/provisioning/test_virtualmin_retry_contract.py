"""Retry contract for Virtualmin API calls.

Mutations must only be replayed when the failure proves the request was not
accepted. Read-only operations may also retry ambiguous transient failures.
"""

from unittest.mock import patch

import requests
from django.test import SimpleTestCase

from apps.common.outbound_http import OutboundSecurityError
from apps.common.types import Err, Retriability
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminServer


def _gateway() -> VirtualminGateway:
    server = VirtualminServer(
        hostname="retry.example.com", status="active", use_ssl=False, api_username="retry-api"
    )
    server.set_api_password("retry-pw")
    # use_credential_vault=False: these tests exercise the RETRY contract with _execute_http_request
    # mocked, so the credential must resolve from the server field (no vault/DB) — call() now resolves
    # auth fail-closed BEFORE the retry loop, and SimpleTestCase has no DB for a vault lookup.
    return VirtualminGateway(VirtualminConfig(server=server, verify_ssl=False, use_credential_vault=False))


def _response(status_code: int) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = b"{}"
    response._content_consumed = True
    return response


class VirtualminRetryContractTests(SimpleTestCase):
    def test_connect_timeout_retries_mutation_and_preserves_retriable(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway,
                "_execute_http_request",
                side_effect=requests.exceptions.ConnectTimeout("connect timeout"),
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("create-domain", {"domain": "example.com"})

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
        self.assertEqual(request_mock.call_count, 3)

    def test_read_timeout_does_not_replay_mutation(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway,
                "_execute_http_request",
                side_effect=requests.exceptions.ReadTimeout("response lost"),
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("create-domain", {"domain": "example.com"})

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        request_mock.assert_called_once()

    def test_read_timeout_retries_read_only_operation(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway,
                "_execute_http_request",
                side_effect=requests.exceptions.ReadTimeout("response lost"),
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("info")

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        self.assertEqual(request_mock.call_count, 3)

    def test_server_error_does_not_replay_mutation(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway, "_execute_http_request", side_effect=lambda _params, auth=None: _response(503)
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("delete-domain", {"domain": "example.com"})

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        request_mock.assert_called_once()

    def test_server_error_retries_read_only_operation(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway, "_execute_http_request", side_effect=lambda _params, auth=None: _response(503)
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("list-domains")

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        self.assertEqual(request_mock.call_count, 3)

    def test_client_error_is_not_retried(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(gateway, "_execute_http_request", return_value=_response(400)) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("info")

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)
        request_mock.assert_called_once()

    def test_generic_request_error_does_not_escape_or_replay_mutation(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway,
                "_execute_http_request",
                side_effect=requests.exceptions.RequestException("transport failed"),
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("modify-domain", {"domain": "example.com"})

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
        request_mock.assert_called_once()

    def test_outbound_security_error_does_not_escape_or_retry(self) -> None:
        gateway = _gateway()

        with (
            patch.object(gateway, "_check_rate_limit", return_value=True),
            patch.object(
                gateway,
                "_execute_http_request",
                side_effect=OutboundSecurityError("blocked destination"),
            ) as request_mock,
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = gateway.call("list-domains")

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)
        request_mock.assert_called_once()
