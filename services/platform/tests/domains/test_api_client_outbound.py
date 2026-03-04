"""Tests for domains API client migration to safe_request()."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.outbound_http import OutboundSecurityError
from apps.domains.api_client import SecureAPIClient


class DomainsAPIClientOutboundTests(TestCase):
    """Verify domain registrar API client uses safe_request()."""

    def _make_registrar(self, api_endpoint: str = "https://api.registrar.com") -> MagicMock:
        registrar = MagicMock()
        registrar.api_endpoint = api_endpoint
        registrar.get_api_credentials.return_value = ("api-key", "api-secret")
        return registrar

    @patch("apps.domains.api_client.safe_request")
    def test_uses_safe_request(self, mock_safe_request: MagicMock) -> None:
        """make_secure_request() must use safe_request()."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_safe_request.return_value = mock_response

        registrar = self._make_registrar()
        success, _data = SecureAPIClient.make_secure_request(
            registrar,
            "POST",
            "/domains/check",
            {"domain": "example.com"},
        )

        self.assertTrue(success)
        mock_safe_request.assert_called()

    @patch("apps.domains.api_client.safe_request")
    def test_private_ip_registrar_rejected(self, mock_safe_request: MagicMock) -> None:
        """Registrar endpoints pointing to private IPs must be rejected."""
        mock_safe_request.side_effect = OutboundSecurityError("blocked")

        registrar = self._make_registrar("https://10.0.0.1/api")
        success, _data = SecureAPIClient.make_secure_request(
            registrar,
            "GET",
            "/status",
            {},
        )

        self.assertFalse(success)

    @patch("apps.domains.api_client.safe_request")
    def test_auth_headers_preserved(self, mock_safe_request: MagicMock) -> None:
        """Authorization and X-API-Secret headers must be preserved."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_safe_request.return_value = mock_response

        registrar = self._make_registrar()
        SecureAPIClient.make_secure_request(registrar, "GET", "/test", {})

        call_kwargs = mock_safe_request.call_args
        headers = call_kwargs[1].get("headers", {})
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer api-key")
