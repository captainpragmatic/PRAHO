"""Tests for outbound HTTP transport — PinnedIPAdapter, safe_request, safe_urlopen."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.outbound_http import (
    OutboundPolicy,
    OutboundSecurityError,
    PinnedIPAdapter,
    safe_request,
    safe_urlopen,
)

MOCK_PUBLIC_IP = "93.184.216.34"
MOCK_PUBLIC_IP_2 = "93.184.216.35"


def _mock_getaddrinfo_public(host, port, family=0, type_=0, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (MOCK_PUBLIC_IP, port or 443))]


def _mock_getaddrinfo_public_2(host, port, family=0, type_=0, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (MOCK_PUBLIC_IP_2, port or 443))]


def _mock_getaddrinfo_private(host, port, family=0, type_=0, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port or 443))]


class TestPinnedIPAdapter(TestCase):
    """Task 0.2: PinnedIPAdapter unit tests."""

    def test_adapter_stores_pinned_ip(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="example.com")
        self.assertEqual(adapter._pinned_ip, MOCK_PUBLIC_IP)
        self.assertEqual(adapter._hostname, "example.com")

    def test_init_poolmanager_sets_server_hostname(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="example.com")
        with patch.object(adapter.__class__.__bases__[0], "init_poolmanager") as mock_init:
            adapter.init_poolmanager(1, 2, block=True)
            _, kwargs = mock_init.call_args
            self.assertEqual(kwargs["server_hostname"], "example.com")

    def test_send_rewrites_url_to_pinned_ip(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="example.com")
        mock_request = MagicMock()
        mock_request.url = "https://example.com:443/api"
        mock_request.headers = {}

        with patch.object(adapter.__class__.__bases__[0], "send", return_value=MagicMock()) as mock_send:
            adapter.send(mock_request)
            # URL should now point to the pinned IP
            self.assertIn(MOCK_PUBLIC_IP, mock_request.url)
            self.assertEqual(mock_request.headers["Host"], "example.com")
            mock_send.assert_called_once()

    def test_send_preserves_existing_host_header(self):
        adapter = PinnedIPAdapter(pinned_ip=MOCK_PUBLIC_IP, hostname="example.com")
        mock_request = MagicMock()
        mock_request.url = "https://example.com:443/api"
        mock_request.headers = {"Host": "custom.example.com"}

        with patch.object(adapter.__class__.__bases__[0], "send", return_value=MagicMock()):
            adapter.send(mock_request)
            self.assertEqual(mock_request.headers["Host"], "custom.example.com")


class TestSafeRequest(TestCase):
    """Task 0.2: safe_request() transport tests."""

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_private)
    def test_rejects_private_ip_target(self):
        with self.assertRaises(OutboundSecurityError):
            safe_request("GET", "https://evil.example.com/")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_forces_verify_tls_true(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.send.return_value = mock_response
        mock_session.prepare_request.return_value = MagicMock()

        safe_request("GET", "https://example.com/")
        call_kwargs = mock_session.send.call_args[1]
        self.assertTrue(call_kwargs["verify"])

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_forces_allow_redirects_false(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.send.return_value = mock_response
        mock_session.prepare_request.return_value = MagicMock()

        safe_request("GET", "https://example.com/")
        call_kwargs = mock_session.send.call_args[1]
        self.assertFalse(call_kwargs["allow_redirects"])

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_always_sets_timeout(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.send.return_value = mock_response
        mock_session.prepare_request.return_value = MagicMock()

        safe_request("GET", "https://example.com/")
        call_kwargs = mock_session.send.call_args[1]
        self.assertIsNotNone(call_kwargs["timeout"])
        self.assertEqual(call_kwargs["timeout"], (10.0, 30.0))

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_mounts_pinned_adapter(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.send.return_value = mock_response
        mock_session.prepare_request.return_value = MagicMock()

        safe_request("GET", "https://example.com/")
        # Verify mount was called with a PinnedIPAdapter
        mock_session.mount.assert_called_once()
        adapter = mock_session.mount.call_args[0][1] if len(mock_session.mount.call_args[0]) > 1 else None
        self.assertIsInstance(adapter, PinnedIPAdapter)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_redirect_revalidation(self, mock_session_cls):
        """When redirects enabled, each hop is re-validated."""
        policy = OutboundPolicy(
            name="redirect_test",
            allow_redirects=True,
            max_redirects=2,
        )

        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.prepare_request.return_value = MagicMock()

        # First response: 302 redirect
        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://other.example.com/final"}
        redirect_response.url = "https://example.com/"

        # Final response: 200
        final_response = MagicMock()
        final_response.status_code = 200

        mock_session.send.side_effect = [redirect_response, final_response]

        resp = safe_request("GET", "https://example.com/", policy=policy)
        self.assertEqual(resp.status_code, 200)

    @patch("apps.common.outbound_http.socket.getaddrinfo")
    @patch("apps.common.outbound_http.requests.Session")
    def test_redirect_to_private_ip_blocked(self, mock_session_cls, mock_dns):
        """Redirect to a URL resolving to private IP should be blocked."""
        policy = OutboundPolicy(
            name="redirect_test",
            allow_redirects=True,
            max_redirects=2,
        )

        # First call resolves to public, second to private
        mock_dns.side_effect = [
            [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (MOCK_PUBLIC_IP, 443))],
            [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))],
        ]

        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.prepare_request.return_value = MagicMock()

        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://evil-internal.example.com/steal"}
        redirect_response.url = "https://example.com/"
        mock_session.send.return_value = redirect_response

        with self.assertRaises(OutboundSecurityError):
            safe_request("GET", "https://example.com/", policy=policy)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.requests.Session")
    def test_session_is_closed(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.send.return_value = mock_response
        mock_session.prepare_request.return_value = MagicMock()

        safe_request("GET", "https://example.com/")
        mock_session.close.assert_called_once()

    def test_deny_log_on_block(self):
        """Blocked requests emit a warning log."""
        with (
            self.assertLogs("apps.common.outbound_http", level="WARNING") as cm,
            self.assertRaises(OutboundSecurityError),
        ):
            safe_request("GET", "https://127.0.0.1/")
        self.assertTrue(any("Blocked" in msg for msg in cm.output))


class TestSafeUrlopen(TestCase):
    """Task 0.2: safe_urlopen() tests."""

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_private)
    def test_rejects_private_ip(self):
        with self.assertRaises(OutboundSecurityError):
            safe_urlopen("https://evil.example.com/")

    def test_rejects_blocked_scheme(self):
        with self.assertRaises(OutboundSecurityError):
            safe_urlopen("ftp://example.com/file")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.urllib.request.urlopen")
    def test_calls_urlopen_with_timeout(self, mock_urlopen):
        mock_urlopen.return_value = MagicMock()
        safe_urlopen("https://example.com/", timeout=15.0)
        call_kwargs = mock_urlopen.call_args[1]
        self.assertEqual(call_kwargs["timeout"], 15.0)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.urllib.request.urlopen")
    def test_uses_policy_timeout_by_default(self, mock_urlopen):
        mock_urlopen.return_value = MagicMock()
        safe_urlopen("https://example.com/")
        call_kwargs = mock_urlopen.call_args[1]
        self.assertEqual(call_kwargs["timeout"], 30.0)

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.urllib.request.urlopen")
    def test_sets_host_header(self, mock_urlopen):
        mock_urlopen.return_value = MagicMock()
        safe_urlopen("https://example.com/path")
        req_arg = mock_urlopen.call_args[0][0]
        self.assertEqual(req_arg.get_header("Host"), "example.com")

    @patch("apps.common.outbound_http.socket.getaddrinfo", _mock_getaddrinfo_public)
    @patch("apps.common.outbound_http.urllib.request.urlopen")
    def test_pins_to_resolved_ip(self, mock_urlopen):
        mock_urlopen.return_value = MagicMock()
        safe_urlopen("https://example.com/path")
        req_arg = mock_urlopen.call_args[0][0]
        self.assertIn(MOCK_PUBLIC_IP, req_arg.full_url)
