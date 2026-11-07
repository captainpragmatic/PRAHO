"""The native acceptance FQDN check reads the published DNS records, not what this host's stack would connect to.

macOS leaves AAAA answers out of getaddrinfo when the host has no global IPv6, so an operator machine without IPv6
saw only the IPv4 address and refused a correctly published node.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import dns.resolver
from django.test import SimpleTestCase

from apps.infrastructure.native_workflow import require_fixture_dns

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

FQDN = "dev-sha-het-de-fsn1-001.native-acc.example.test"
IPV4 = "203.0.113.10"
IPV6 = "2001:db8::1"


class _Resolver:
    def __init__(self, records: dict[str, list[str]] | None) -> None:
        self.records = records
        self.asked: list[tuple[str, str]] = []

    def resolve(self, name: str, rdtype: str, **_kwargs: object) -> list[SimpleNamespace]:
        self.asked.append((name, rdtype))
        if self.records is None:
            raise dns.resolver.NXDOMAIN
        if not self.records.get(rdtype):
            raise dns.resolver.NoAnswer
        return [SimpleNamespace(address=address) for address in self.records[rdtype]]


def _check(records: dict[str, list[str]] | None, ipv6: str = IPV6) -> _Resolver:
    resolver = _Resolver(records)
    deployment = SimpleNamespace(fqdn=FQDN, ipv6_address=ipv6)
    # This host's stack returns only IPv4, as macOS does without global IPv6.
    ipv4_only = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (IPV4, 10000))]
    with (
        patch("apps.infrastructure.native_workflow.dns.resolver.Resolver", return_value=resolver),
        patch("socket.getaddrinfo", return_value=ipv4_only),
    ):
        require_fixture_dns(cast("NodeDeployment", deployment), IPV4)
    return resolver


class NativeFixtureDNSTests(SimpleTestCase):
    def test_published_a_and_aaaa_pass_on_a_host_without_ipv6(self) -> None:
        resolver = _check({"A": [IPV4], "AAAA": [IPV6]})
        self.assertEqual(sorted(resolver.asked), [(FQDN, "A"), (FQDN, "AAAA")])

    def test_an_ipv4_only_node_needs_no_aaaa(self) -> None:
        _check({"A": [IPV4]}, ipv6="")

    def test_a_foreign_or_missing_address_is_refused(self) -> None:
        for records in (
            {"A": [IPV4, "198.51.100.7"], "AAAA": [IPV6]},
            {"A": [IPV4], "AAAA": [IPV6, "2001:db8::2"]},
            {"A": [IPV4]},
            {"AAAA": [IPV6]},
        ):
            with self.subTest(records=records), self.assertRaisesRegex(ValueError, "exact owned VM addresses"):
                _check(records)

    def test_an_unpublished_name_is_unresolved(self) -> None:
        with self.assertRaisesRegex(ValueError, "unresolved"):
            _check(None)
