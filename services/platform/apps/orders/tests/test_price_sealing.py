from __future__ import annotations

from django.test import RequestFactory, TestCase

from apps.orders.price_sealing import get_client_ip


class TestGetClientIp(TestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def test_ignores_forwarded_host_header_for_ip_extraction(self) -> None:
        request = self.factory.get(
            "/orders/",
            HTTP_X_FORWARDED_HOST="example.com",
            REMOTE_ADDR="203.0.113.8",
        )

        ip = get_client_ip(request)

        self.assertEqual(ip, "203.0.113.8")

    def test_prefers_x_forwarded_for_when_valid(self) -> None:
        request = self.factory.get(
            "/orders/",
            HTTP_X_FORWARDED_FOR="198.51.100.25, 10.0.0.1",
            REMOTE_ADDR="203.0.113.8",
        )

        ip = get_client_ip(request)

        self.assertEqual(ip, "198.51.100.25")
