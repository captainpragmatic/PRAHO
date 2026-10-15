"""A Hetzner node's IPv6 is stored as its host address, not as the /64 block (ADR-0061 P0.3).

The hcloud SDK documents ``public_net.ipv6.ip`` as the network "in CIDR notation"
(``2a01:4f8:c17:1234::/64``). Stored as is, the deployment's AAAA record was published with a
CIDR as its content, which no DNS provider accepts. Hetzner answers on ``::1`` of the block.
"""

from __future__ import annotations

import ipaddress
from unittest import mock

from django.test import SimpleTestCase
from hcloud.servers.domain import IPv4Address, IPv6Network

from apps.infrastructure.cloud_gateway import ServerCreateRequest
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.panel_cert_probes import public_address

BLOCK = "2a01:4f8:c17:1234::/64"
HOST = "2a01:4f8:c17:1234::1"


def hcloud_server(ipv6_block: str | None = BLOCK) -> mock.Mock:
    """A server whose public_net is the real SDK domain object, so the documented CIDR shape is exercised."""
    server = mock.Mock()
    server.id = 42
    server.name = "node"
    server.status = "running"
    server.server_type.name = "cpx21"
    server.location.name = "fsn1"
    server.labels = {}
    server.public_net.ipv4 = IPv4Address(ip="198.51.100.4", blocked=False, dns_ptr="")
    server.public_net.ipv6 = IPv6Network(ip=ipv6_block, blocked=False, dns_ptr=[]) if ipv6_block else None
    return server


def service_with_client() -> tuple[HcloudService, mock.Mock]:
    with mock.patch("apps.infrastructure.hcloud_service.Client") as client_cls:
        client = mock.Mock()
        client_cls.return_value = client
        return HcloudService(token="fake-token"), client


class IPv6HostAddressTests(SimpleTestCase):
    def test_extracted_ipv6_is_the_host_address_of_the_block(self) -> None:
        ipv4, ipv6 = HcloudService._extract_ips(hcloud_server())

        self.assertEqual(ipv4, "198.51.100.4")
        self.assertEqual(ipv6, HOST)
        ipaddress.IPv6Address(ipv6)  # an address, not a network
        self.assertEqual(public_address(ipv6, 6), HOST)

    def test_gateway_info_carries_the_host_address(self) -> None:
        service, _client = service_with_client()

        info = service._server_to_gateway_info(hcloud_server())

        self.assertEqual(info.ipv6_address, HOST)

    def test_create_server_returns_the_host_address(self) -> None:
        service, client = service_with_client()
        response = mock.Mock()
        response.server = hcloud_server()
        response.root_password = None
        client.servers.create.return_value = response

        result = service.create_server(
            ServerCreateRequest(name="node", server_type="cpx21", location="fsn1", ssh_keys=["key"], labels={})
        )

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().ipv6_address, HOST)

    def test_a_server_without_ipv6_stays_empty(self) -> None:
        self.assertEqual(HcloudService._extract_ips(hcloud_server(None))[1], "")

    def test_a_block_that_is_not_a_public_ipv6_is_not_published(self) -> None:
        for block in ("fe80::/64", "fd00::/64", "2001:db8::/64", "not-an-address/64", "198.51.100.0/24"):
            with self.subTest(block=block):
                self.assertEqual(HcloudService._extract_ips(hcloud_server(block))[1], "")
