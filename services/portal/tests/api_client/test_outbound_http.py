"""Tests for portal outbound HTTP wrapper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common.outbound_http import OutboundSecurityError, _session, portal_request


class PortalRequestHTTPSEnforcementTest(SimpleTestCase):
    """portal_request() must enforce HTTPS in production."""

    @override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=False)
    def test_rejects_http_in_production(self):
        with self.assertRaises(OutboundSecurityError):
            portal_request("GET", "http://platform.example.com/api/test/")

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_allows_http_in_debug(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "http://localhost:8700/api/test/")
        self.assertEqual(resp.status_code, 200)

    @override_settings(DEBUG=False, PLATFORM_API_ALLOW_INSECURE_HTTP=True)
    @patch("apps.common.outbound_http._session.request")
    def test_allows_http_with_insecure_setting(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "http://platform.example.com/api/test/")
        self.assertEqual(resp.status_code, 200)

    @override_settings(DEBUG=False)
    @patch("apps.common.outbound_http._session.request")
    def test_allows_https_in_production(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        resp = portal_request("GET", "https://platform.example.com/api/test/")
        self.assertEqual(resp.status_code, 200)


class PortalRequestRedirectTest(SimpleTestCase):
    """portal_request() must block redirects."""

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_sets_allow_redirects_false(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertFalse(kwargs["allow_redirects"])

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_overrides_caller_allow_redirects(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", allow_redirects=True)
        _, kwargs = mock_request.call_args
        self.assertFalse(kwargs["allow_redirects"])


class PortalRequestTimeoutTest(SimpleTestCase):
    """portal_request() must always set a timeout."""

    @override_settings(DEBUG=True, PLATFORM_API_TIMEOUT=15)
    @patch("apps.common.outbound_http._session.request")
    def test_uses_settings_timeout(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 15)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_uses_explicit_timeout(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", timeout=5.0)
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 5.0)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
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
    @patch("apps.common.outbound_http._session.request")
    def test_always_sets_verify_true(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertTrue(kwargs["verify"])

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_overrides_caller_verify_false(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/", verify=False)
        _, kwargs = mock_request.call_args
        self.assertTrue(kwargs["verify"])


class PortalRequestHMACPreservationTest(SimpleTestCase):
    """portal_request() must not alter URL or headers — HMAC must stay intact."""

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_url_passed_unchanged(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        url = "http://localhost:8700/api/users/login/"
        portal_request("POST", url, headers={"X-Signature": "abc123"})
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["url"], url)

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_headers_passed_through(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        custom_headers = {"X-Portal-Id": "portal-1", "X-Signature": "sig123", "X-Nonce": "nonce"}
        portal_request("POST", "http://localhost:8700/api/test/", headers=custom_headers)
        _, kwargs = mock_request.call_args
        # portal_request merges in User-Agent; verify custom headers are present
        for key, value in custom_headers.items():
            self.assertEqual(kwargs["headers"][key], value)


class PortalRequestCookieIsolationTest(SimpleTestCase):
    """portal_request() must not let cookies leak across calls on the shared _session.

    requests.Session persists Set-Cookie response cookies and merges session.cookies
    into every outbound request. For inter-service HMAC traffic across tenants, this
    is a cross-tenant leakage risk: a Set-Cookie from one Platform response would ride
    on the next portal_request() call regardless of caller.
    """

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_passes_empty_cookies_kwarg(self, mock_request):
        """Per-call cookies={} suppresses any session-level cookie merge for this request."""
        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs.get("cookies"), {})

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_clears_session_cookies_after_call(self, mock_request):
        """_session.cookies is cleared after every call so a Set-Cookie from one
        response cannot ride on the next portal_request() call."""
        # Simulate a previously-set cookie (e.g., from a prior Set-Cookie response).
        _session.cookies.set("leak", "yes")
        self.assertEqual(_session.cookies.get("leak"), "yes")

        mock_request.return_value = MagicMock(status_code=200)
        portal_request("GET", "http://localhost:8700/api/test/")

        self.assertEqual(len(_session.cookies), 0)
        self.assertIsNone(_session.cookies.get("leak"))

    @override_settings(DEBUG=True)
    @patch("apps.common.outbound_http._session.request")
    def test_clears_session_cookies_even_when_request_raises(self, mock_request):
        """Exception path must still clean up to avoid stale cookies leaking on retry."""
        _session.cookies.set("leak", "yes")
        mock_request.side_effect = requests.exceptions.ConnectionError("boom")

        with self.assertRaises(requests.exceptions.ConnectionError):
            portal_request("GET", "http://localhost:8700/api/test/")

        self.assertEqual(len(_session.cookies), 0)


class PlatformAPIClientSecurityErrorTest(SimpleTestCase):
    """OutboundSecurityError must be caught and wrapped as PlatformAPIError."""

    @override_settings(
        PLATFORM_API_URL="http://localhost:8700",
        PLATFORM_API_KEY="test-key",
        PLATFORM_API_SECRET="test-secret",
        DEBUG=True,
    )
    @patch("apps.api_client.services.portal_request", side_effect=OutboundSecurityError("SSRF blocked"))
    def test_outbound_security_error_wrapped_as_platform_api_error(self, _mock_request):
        client = PlatformAPIClient()
        with self.assertRaises(PlatformAPIError) as ctx:
            client._make_request("GET", "/api/test/")
        self.assertIn("Security policy violation", str(ctx.exception))
