"""Answer the acceptance FQDN check's A and AAAA queries from a fixed record set."""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver


class PublishedRecords:
    def __init__(self, *addresses: str) -> None:
        self.by_type: dict[str, list[str]] = {"A": [], "AAAA": []}
        for address in addresses:
            self.by_type["A" if isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address) else "AAAA"].append(
                address
            )
        self.asked: list[tuple[str, str]] = []

    def resolve(self, name: str, rdtype: str, **_kwargs: object) -> list[SimpleNamespace]:
        self.asked.append((name, rdtype))
        if not any(self.by_type.values()):
            raise dns.resolver.NXDOMAIN
        if not self.by_type[rdtype]:
            raise dns.resolver.NoAnswer
        return [SimpleNamespace(address=address) for address in self.by_type[rdtype]]


def published_dns(*addresses: str):  # noqa: ANN201  # the patch context manager
    return patch("apps.infrastructure.native_workflow.dns.resolver.Resolver", return_value=PublishedRecords(*addresses))
