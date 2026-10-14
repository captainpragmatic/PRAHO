"""A request that may have reached the server must never be sent a second time.

``requests`` raises ``ConnectionError`` both when the TCP connect failed (nothing was sent)
and when the peer reset the connection after the body went out. ``PinnedIPAdapter`` used to
re-resolve DNS and resend on either, so a lost reply to a POST became a second POST to a
different address. For a fiscal or payment API that is a duplicate document.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase

from apps.billing.efactura.client import EFACTURA_POLICY
from apps.billing.issuers.smartbill.client import SMARTBILL_POLICY
from apps.common.outbound_http import (
    STRICT_EXTERNAL,
    OutboundPolicy,
    PinnedIPAdapter,
    safe_request,
)
from apps.infrastructure.dns_gateway import CLOUDFLARE_POLICY
from apps.infrastructure.vultr_service import VULTR_POLICY

FIRST_IP = "93.184.216.34"
SECOND_IP = "104.16.132.229"


def _reset_after_send() -> requests.ConnectionError:
    return requests.ConnectionError("Connection aborted: RemoteDisconnected")


class _NoReplayBase(SimpleTestCase):
    """Drive ``safe_request`` against a peer that resets the connection after the body."""

    def assert_single_send(self, policy: OutboundPolicy, method: str, url: str) -> None:
        with (
            patch("apps.common.outbound_http._resolve_dns", side_effect=[[FIRST_IP], [SECOND_IP]]) as dns,
            patch("requests.adapters.HTTPAdapter.send", side_effect=_reset_after_send()) as send,
            self.assertRaises(requests.ConnectionError),
        ):
            safe_request(method, url, policy=policy, data=b"payload")

        self.assertEqual(send.call_count, 1, "the request was sent more than once")
        self.assertEqual(dns.call_count, 1, "DNS was re-resolved to find another address to replay to")


class FiscalAndPaymentPoliciesDoNotReplayTests(_NoReplayBase):
    def test_smartbill_post_not_replayed_after_connection_reset(self) -> None:
        self.assert_single_send(SMARTBILL_POLICY, "POST", "https://ws.smartbill.ro/SBORO/api/invoice/v2")
        self.assertFalse(SMARTBILL_POLICY.retry_connection_errors)

    def test_efactura_post_not_replayed_after_connection_reset(self) -> None:
        self.assert_single_send(EFACTURA_POLICY, "POST", "https://api.anaf.ro/prod/FCTEL/rest/upload")
        self.assertFalse(EFACTURA_POLICY.retry_connection_errors)

    def test_cloudflare_post_not_replayed_after_connection_reset(self) -> None:
        """The gateway's default policy, not only the variant built when a timeout is passed."""
        self.assert_single_send(CLOUDFLARE_POLICY, "POST", "https://api.cloudflare.com/client/v4/zones/z/dns_records")
        self.assertFalse(CLOUDFLARE_POLICY.retry_connection_errors)

    def test_vultr_post_not_replayed_after_connection_reset(self) -> None:
        self.assert_single_send(VULTR_POLICY, "POST", "https://api.vultr.com/v2/instances")
        self.assertFalse(VULTR_POLICY.retry_connection_errors)


class AdapterNeverReplaysUnsafeMethodsTests(SimpleTestCase):
    """The adapter protects every policy, including ones that keep the default flag."""

    def _send(self, method: str, *, retry: bool = True) -> tuple[MagicMock, MagicMock]:
        adapter = PinnedIPAdapter(
            pinned_ip=FIRST_IP,
            hostname="api.example.com",
            port=443,
            retry_connection_errors=retry,
        )
        request = requests.PreparedRequest()
        request.prepare(method=method, url="https://api.example.com/v1/things", data=b"x")
        with (
            patch("requests.adapters.HTTPAdapter.send", side_effect=_reset_after_send()) as send,
            patch("apps.common.outbound_http._resolve_dns", return_value=[SECOND_IP]) as dns,
            patch("apps.common.outbound_http._log_dns_fallback"),
            self.assertRaises(requests.ConnectionError),
        ):
            adapter.send(request)
        return send, dns

    def test_unsafe_methods_are_sent_once_even_when_the_policy_allows_retry(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                send, dns = self._send(method, retry=True)
                self.assertEqual(send.call_count, 1)
                dns.assert_not_called()

    def test_default_policy_does_not_replay_a_post(self) -> None:
        self.assertEqual(self._send("POST", retry=STRICT_EXTERNAL.retry_connection_errors)[0].call_count, 1)

    def test_safe_methods_still_fall_back_to_a_fresh_address(self) -> None:
        for method in ("GET", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                adapter = PinnedIPAdapter(pinned_ip=FIRST_IP, hostname="api.example.com", port=443)
                request = requests.PreparedRequest()
                request.prepare(method=method, url="https://api.example.com/v1/things")
                ok = MagicMock(status_code=200)
                with (
                    patch("requests.adapters.HTTPAdapter.send", side_effect=[_reset_after_send(), ok]) as send,
                    patch("apps.common.outbound_http._resolve_dns", return_value=[SECOND_IP]),
                    patch("apps.common.outbound_http._log_dns_fallback"),
                ):
                    response = adapter.send(request)
                self.assertIs(response, ok)
                self.assertEqual(send.call_count, 2)
