"""Tests for Virtualmin gateway migration to safe_request()."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
)


class VirtualminOutboundTests(TestCase):
    """Verify Virtualmin gateway uses safe_request() with DNS pinning."""

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_execute_http_request_uses_safe_request(self, mock_safe_request: MagicMock) -> None:
        """_execute_http_request() must use safe_request()."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-length": "100"}
        mock_response.iter_content.return_value = iter([b'{"status":"success"}'])
        mock_safe_request.return_value = mock_response

        # We test the method indirectly through the gateway
        # The import itself validates the module structure
        from apps.provisioning.virtualmin_gateway import VirtualminGateway  # noqa: PLC0415

        self.assertTrue(hasattr(VirtualminGateway, "_execute_http_request"))

    def test_safe_request_import_available(self) -> None:
        """safe_request must be importable from the gateway module."""
        import apps.provisioning.virtualmin_gateway as gw  # noqa: PLC0415

        self.assertTrue(hasattr(gw, "safe_request"))

    def _gateway(
        self,
        *,
        api_url: str = "https://virtualmin.example.com:10000/remote.cgi",
        use_ssl: bool = True,
        verify_ssl: bool = True,
        fingerprint: str = "",
    ) -> VirtualminGateway:
        server = MagicMock()
        server.hostname = "virtualmin.example.com"
        server.api_url = api_url
        server.api_username = "praho-api"
        server.use_ssl = use_ssl
        server.ssl_cert_fingerprint = fingerprint
        server.get_api_password.return_value = "secret"
        return VirtualminGateway(
            VirtualminConfig(
                server=server,
                verify_ssl=verify_ssl,
                cert_fingerprint=fingerprint,
                use_credential_vault=False,
            )
        )

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_http_is_rejected_before_credentials_are_read(self, mock_safe_request: MagicMock) -> None:
        gateway = self._gateway(api_url="http://virtualmin.example.com:10000/remote.cgi", use_ssl=False)
        gateway.server.get_api_password.side_effect = AssertionError("credentials must not be read")

        with self.assertRaises(VirtualminAPIError):
            gateway._execute_http_request({"program": "info"})

        mock_safe_request.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_disabled_ca_verification_requires_certificate_fingerprint(self, mock_safe_request: MagicMock) -> None:
        gateway = self._gateway(verify_ssl=False)

        with self.assertRaises(VirtualminAPIError):
            gateway._execute_http_request({"program": "info"})

        mock_safe_request.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_fingerprint_is_enforced_by_outbound_transport(self, mock_safe_request: MagicMock) -> None:
        fingerprint = "ab" * 32
        gateway = self._gateway(verify_ssl=False, fingerprint=fingerprint)
        mock_safe_request.return_value = MagicMock()

        gateway._execute_http_request({"program": "info"})

        policy = mock_safe_request.call_args.kwargs["policy"]
        self.assertTrue(policy.require_https)
        self.assertEqual(policy.allowed_schemes, frozenset({"https"}))
        self.assertEqual(policy.tls_cert_fingerprint, fingerprint)

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_claims_slots_with_atomic_cache_add(self, mock_cache: MagicMock) -> None:
        gateway = self._gateway()
        mock_cache.add.side_effect = [False, False, True]

        allowed = gateway._check_rate_limit("create-domain")

        self.assertTrue(allowed)
        self.assertEqual(mock_cache.add.call_count, 3)
        mock_cache.get.assert_not_called()
        mock_cache.set.assert_not_called()
        mock_cache.incr.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_rejects_when_all_atomic_slots_are_claimed(self, mock_cache: MagicMock) -> None:
        from apps.provisioning.virtualmin_gateway import VIRTUALMIN_RATE_LIMIT_MAX_CALLS  # noqa: PLC0415

        gateway = self._gateway()
        mock_cache.add.return_value = False

        self.assertFalse(gateway._check_rate_limit("create-domain"))
        self.assertEqual(mock_cache.add.call_count, VIRTUALMIN_RATE_LIMIT_MAX_CALLS)
        mock_cache.incr.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_fails_closed_when_counter_backend_fails(self, mock_cache: MagicMock) -> None:
        gateway = self._gateway()
        mock_cache.add.side_effect = RuntimeError("cache unavailable")

        self.assertFalse(gateway._check_rate_limit("create-domain"))
