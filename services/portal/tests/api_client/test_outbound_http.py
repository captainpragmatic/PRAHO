"""Tests for portal outbound HTTP wrapper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.common.outbound_http import OutboundSecurityError, portal_request


class PortalRequestHTTPSEnforcementTest(SimpleTestCase):
    """portal_request() must enforce HTTPS in production."""

    @override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=False)
    def test_rejects_http_in_production(self):
        with self.assertRaises(OutboundSecurityError):
            portal_request("GET", "http://platform.example.com/api/test/")

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_allows_http_in_debug(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "http://localhost:8700/api/test/")
        self.assertEqual(resp.status_code, 200)

    @override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_allows_http_with_insecure_setting(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "http://platform.example.com/api/test/")
        self.assertEqual(resp.status_code, 200)

    @override_settings(DEBUG=False)
    @patch("apps.common.outbound_http.requests.request")
    def test_allows_https_in_production(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "https://platform.example.com/api/test/")
        self.assertEqual(resp.status_code, 200)


class PortalRequestRedirectTest(SimpleTestCase):
    """portal_request() must block redirects."""

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_sets_allow_redirects_false(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertFalse(kwargs["allow_redirects"])

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_overrides_caller_allow_redirects(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", allow_redirects=True)
        _, kwargs = mock_request.call_args
        self.assertFalse(kwargs["allow_redirects"])


class PortalRequestTimeoutTest(SimpleTestCase):
    """portal_request() must always set a timeout."""

    @override_settings(DEBUG=True, PLATFORM_API_TIMEOUT=15)
    @patch("apps.common.outbound_http.requests.request")
    def test_uses_settings_timeout(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 15)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_uses_explicit_timeout(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", timeout=5.0)
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 5.0)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_default_timeout_when_no_setting(self, mock_request):
        """Falls back to PORTAL_DEFAULT_TIMEOUT (30s) when setting is absent."""
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertIsNotNone(kwargs["timeout"])
        self.assertGreater(kwargs["timeout"], 0)


class PortalRequestTLSVerificationTest(SimpleTestCase):
    """portal_request() must always verify TLS."""

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_always_sets_verify_true(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertTrue(kwargs["verify"])

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_overrides_caller_verify_false(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", verify=False)
        _, kwargs = mock_request.call_args
        self.assertTrue(kwargs["verify"])


class PortalRequestHMACPreservationTest(SimpleTestCase):
    """portal_request() must not alter URL or headers — HMAC must stay intact."""

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_url_passed_unchanged(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        url = "http://localhost:8700/api/users/login/"
        portal_request("POST", url, headers={"X-Signature": "abc123"})
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["url"], url)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http.requests.request")
    def test_headers_passed_through(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        custom_headers = {"X-Portal-Id": "portal-1", "X-Signature": "sig123", "X-Nonce": "nonce"}
        portal_request("POST", "http://localhost:8700/api/test/", headers=custom_headers)
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["headers"], custom_headers)
