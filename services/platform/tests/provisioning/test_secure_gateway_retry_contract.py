"""Operation-aware retries for the generic secure server gateway."""

from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase

from apps.common.outbound_http import OutboundSecurityError
from apps.provisioning.secure_gateway import SecureServerGateway


def _server() -> MagicMock:
    server = MagicMock()
    server.id = "server-1"
    server.name = "server-one"
    server.management_api_url = "https://api.virtualmin.com"
    server.get_management_api_credentials.return_value = ("key", "secret")
    return server


def _response(status_code: int) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.text = "upstream response"
    return response


class SecureServerGatewayRetryContractTests(SimpleTestCase):
    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_client_error_is_not_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.return_value = _response(400)

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        safe_request.assert_called_once()

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_server_error_is_not_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.return_value = _response(503)

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        safe_request.assert_called_once()

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_read_timeout_is_not_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.side_effect = requests.exceptions.ReadTimeout("response lost")

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        safe_request.assert_called_once()

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_connect_timeout_is_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.side_effect = requests.exceptions.ConnectTimeout("not connected")

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        self.assertEqual(safe_request.call_count, 3)

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_get_server_error_is_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.return_value = _response(503)

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "GET", "/resources", {})

        self.assertFalse(success)
        self.assertEqual(safe_request.call_count, 3)

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_get_read_timeout_is_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.side_effect = requests.exceptions.ReadTimeout("response lost")

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "GET", "/resources", {})

        self.assertFalse(success)
        self.assertEqual(safe_request.call_count, 3)

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_connection_error_is_not_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.side_effect = requests.exceptions.ConnectionError("connection dropped")

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        safe_request.assert_called_once()

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_post_rate_limit_is_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.return_value = _response(429)

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        self.assertEqual(safe_request.call_count, 3)

    @patch("apps.provisioning.secure_gateway.time.sleep")
    @patch(
        "apps.provisioning.secure_gateway.get_api_timeouts",
        return_value={"REQUEST_TIMEOUT": 30, "MAX_RETRIES": 3},
    )
    @patch("apps.provisioning.secure_gateway.safe_request")
    def test_outbound_security_error_is_not_retried(self, safe_request, _timeouts, _sleep) -> None:
        safe_request.side_effect = OutboundSecurityError("blocked destination")

        success, _payload = SecureServerGateway._make_secure_server_call(_server(), "POST", "/create", {})

        self.assertFalse(success)
        safe_request.assert_called_once()
