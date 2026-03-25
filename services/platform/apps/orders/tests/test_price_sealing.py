from __future__ import annotations

import uuid

from django.http import HttpRequest
from django.test import TestCase, override_settings

from apps.common.request_ip import get_safe_client_ip
from apps.orders.price_sealing import PriceData, PriceSealingService


class TestGetSafeClientIpForPriceSealing(TestCase):
    """Verify that price sealing uses the trusted-proxy-aware IP extraction."""

    def _make_request(self, **meta: str) -> HttpRequest:
        request = HttpRequest()
        request.META = meta
        return request

    def test_ignores_forwarded_host_even_with_valid_ip(self) -> None:
        """X-Forwarded-Host is never an IP source, even when it contains a valid IP."""
        request = self._make_request(
            REMOTE_ADDR="203.0.113.8",
            HTTP_X_FORWARDED_HOST="198.51.100.99",
        )

        ip = get_safe_client_ip(request)

        self.assertEqual(ip, "203.0.113.8")

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=[])
    def test_untrusted_source_xff_ignored(self) -> None:
        """With no trusted proxies, X-Forwarded-For is completely ignored."""
        request = self._make_request(
            REMOTE_ADDR="203.0.113.8",
            HTTP_X_FORWARDED_FOR="198.51.100.25",
        )

        ip = get_safe_client_ip(request)

        self.assertEqual(ip, "203.0.113.8")

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=["10.0.0.0/8"])
    def test_trusted_proxy_xff_used(self) -> None:
        """When REMOTE_ADDR is a trusted proxy, XFF is honoured."""
        request = self._make_request(
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_FOR="198.51.100.25",
        )

        ip = get_safe_client_ip(request)

        self.assertEqual(ip, "198.51.100.25")

    @override_settings(IPWARE_TRUSTED_PROXY_LIST=["10.0.0.0/8"])
    def test_leftmost_xff_not_trusted(self) -> None:
        """Rightmost-trusted-hop must return the rightmost untrusted IP, not the leftmost."""
        request = self._make_request(
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_FOR="198.51.100.99, 198.51.100.25",
        )

        ip = get_safe_client_ip(request)

        # Rightmost untrusted IP is 198.51.100.25, NOT the leftmost 198.51.100.99
        self.assertEqual(ip, "198.51.100.25")


class TestPriceSealingWithSafeIp(TestCase):
    """Integration tests: price sealing flow with secure IP extraction."""

    def _make_price_data(self) -> PriceData:
        return PriceData(
            product_price_id=uuid.uuid4(),
            amount_cents=9900,
            setup_cents=0,
            currency_code="RON",
            billing_period="monthly",
            product_slug="shared-hosting-starter",
        )

    @override_settings(DEBUG=True)
    def test_seal_unseal_roundtrip(self) -> None:
        """Seal and unseal roundtrip succeeds."""
        price_data = self._make_price_data()
        client_ip = "203.0.113.10"

        token = PriceSealingService.seal_price(price_data, client_ip)
        unsealed = PriceSealingService.unseal_price(token)

        self.assertEqual(unsealed["amount_cents"], 9900)
        self.assertEqual(unsealed["client_ip"], client_ip)

    @override_settings(DEBUG=True)
    def test_unseal_different_ip_still_succeeds(self) -> None:
        """Unsealing from a different IP succeeds (IP binding removed per #126)."""
        price_data = self._make_price_data()

        token = PriceSealingService.seal_price(price_data, "203.0.113.10")
        unsealed = PriceSealingService.unseal_price(token)
        self.assertEqual(unsealed["amount_cents"], 9900)
