"""Canonical fixed-width address ordering shared by mirrors and customer observations."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class AddressBounds:
    address_family: int
    network_start: bytes
    network_end: bytes


def pack_address(value: str) -> tuple[int, bytes]:
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None):
        raise ValueError("Scoped addresses are not portable security identities")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.version, address.packed.rjust(16, b"\0")


def address_bounds(scope: str, value: str) -> AddressBounds:
    if scope == "ip":
        family, packed = pack_address(value)
        return AddressBounds(family, packed, packed)
    if scope != "range":
        raise ValueError("Only IP and canonical CIDR scopes have address bounds")
    network = ipaddress.ip_network(value, strict=True)
    return AddressBounds(
        network.version,
        network.network_address.packed.rjust(16, b"\0"),
        network.broadcast_address.packed.rjust(16, b"\0"),
    )
