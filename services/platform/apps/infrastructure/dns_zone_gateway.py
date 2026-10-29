"""Separate typed customer-zone provider seam; node/name reconciliation stays independent."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast
from uuid import UUID

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.rdtypes.ANY.CAA import CAA

from apps.common.types import Err, Ok, Result, Retriability

ZoneRecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"]
ZONE_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"})
OWNER_PREFIX = "praho:hosted-zone-record:"
MIN_RECORD_TTL = 60
MAX_RECORD_TTL = 86400
MAX_OWNER_LENGTH = 253
MAX_WIRE_RDATA = 4096
RR_HEADER_BYTES = 10


@dataclass(frozen=True)
class ZoneBinding:
    provider: str
    account_id: str
    zone_id: str
    name: str


@dataclass(frozen=True)
class ZoneIdentity:
    binding: ZoneBinding
    status: str
    nameservers: tuple[str, ...]
    plan: str = "free"


@dataclass(frozen=True)
class ZoneRecordSpec:
    local_id: str
    name: str
    record_type: ZoneRecordType
    ttl: int
    rdata: str
    owner_tag: str
    proxied: bool = False


@dataclass(frozen=True)
class ProviderZoneRecord:
    id: str
    spec: ZoneRecordSpec


@dataclass(frozen=True)
class ZoneInventory:
    identity: ZoneIdentity
    records: tuple[ProviderZoneRecord, ...]


@dataclass(frozen=True)
class DnssecStatus:
    status: str
    ds: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def canonical_dns_name(value: str) -> str:
    """DNS owner grammar includes service labels; preserve labels the provider can represent."""
    if not isinstance(value, str) or not value or len(value) > MAX_OWNER_LENGTH:
        raise ValueError("A bounded absolute DNS name is required")
    parsed = dns.name.from_text(value).canonicalize()
    if parsed == dns.name.root or not parsed.is_absolute():
        raise ValueError("A non-root DNS name is required")
    result = parsed.to_text(omit_final_dot=True)
    # Cloudflare's JSON API accepts text DNS labels, not arbitrary escaped label octets.
    if re.fullmatch(r"[a-z0-9_*](?:[a-z0-9_.*-]*[a-z0-9_*])?", result) is None:
        raise ValueError("This DNS owner cannot be represented by the zone provider")
    return result


def owned_local_id(owner_tag: str) -> str:
    if not isinstance(owner_tag, str) or not owner_tag.startswith(OWNER_PREFIX):
        raise ValueError("The record has no PRAHO customer-zone owner")
    value = owner_tag.removeprefix(OWNER_PREFIX)
    identifier = str(UUID(value))
    if value != identifier:
        raise ValueError("The record owner must contain its canonical local UUID")
    return identifier


def canonical_rdata(kind: str, text: str, *, origin: str | None = None) -> str:
    if kind not in ZONE_RECORD_TYPES or not isinstance(text, str):
        raise ValueError("Unsupported customer DNS record type")
    record = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.from_text(kind),
        text,
        origin=dns.name.from_text(origin or "."),
        relativize=False,
    )
    wire = record.to_wire()
    if wire is None or len(wire) > MAX_WIRE_RDATA:
        raise ValueError("The DNS record exceeds the provider wire limit")
    if kind == "CAA":
        caa = cast(CAA, record)
        tag = caa.tag.decode("ascii").lower()
        if tag not in {"issue", "issuewild", "iodef"}:
            raise ValueError("Unsupported CAA property tag")
        caa.value.decode("utf-8")
        record = caa.replace(tag=tag.encode("ascii"))
    return record.to_text(origin=None, relativize=False)


def validate_record_spec(spec: ZoneRecordSpec, *, zone_name: str | None = None) -> Result[ZoneRecordSpec, str]:
    """Pure complete-manifest preflight; never discovers capability errors after a partial import."""
    try:
        name = canonical_dns_name(spec.name)
        zone = canonical_dns_name(zone_name) if zone_name is not None else None
        if zone is not None and not dns.name.from_text(name).is_subdomain(dns.name.from_text(zone)):
            raise ValueError("The record owner is outside its customer zone")
        if spec.record_type == "CNAME" and name == zone:
            raise ValueError("A customer zone apex cannot be a CNAME")
        if type(spec.ttl) is not int or not MIN_RECORD_TTL <= spec.ttl <= MAX_RECORD_TTL or spec.proxied is not False:
            raise ValueError("Customer records require DNS-only routing and an explicit TTL from 60 to 86400")
        if owned_local_id(spec.owner_tag) != str(UUID(spec.local_id)):
            raise ValueError("The provider owner tag does not match the local record")
        text = canonical_rdata(spec.record_type, spec.rdata, origin=zone)
        record = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.from_text(spec.record_type),
            text,
            origin=dns.name.from_text(zone or "."),
            relativize=False,
        )
        owner_wire = dns.name.from_text(name).to_wire()
        rdata_wire = record.to_wire()
        if (
            owner_wire is None
            or rdata_wire is None
            or len(owner_wire) + RR_HEADER_BYTES + len(rdata_wire) > MAX_WIRE_RDATA
        ):
            raise ValueError("The complete DNS record exceeds the provider wire limit")
        return Ok(replace(spec, name=name, rdata=text))
    except (ValueError, TypeError, AttributeError, UnicodeError, dns.exception.DNSException) as error:
        return Err(str(error), retriability=Retriability.NOT_RETRIABLE)


class ZoneGateway(ABC):
    @abstractmethod
    def create_zone(self, account_id: str, name: str) -> Result[ZoneIdentity, str]: ...
    @abstractmethod
    def read_zone(self, binding: ZoneBinding) -> Result[ZoneIdentity, str]: ...
    @abstractmethod
    def list_zones(self, account_id: str, name: str) -> Result[tuple[ZoneIdentity, ...], str]: ...
    @abstractmethod
    def delete_zone(
        self, binding: ZoneBinding, *, expected_records: tuple[ZoneRecordSpec, ...] | None = None
    ) -> Result[None, str]: ...
    @abstractmethod
    def trigger_activation(self, binding: ZoneBinding) -> Result[None, str]: ...
    @abstractmethod
    def list_records(self, binding: ZoneBinding) -> Result[ZoneInventory, str]: ...
    @abstractmethod
    def get_record(
        self, binding: ZoneBinding, record_id: str, *, expected_owner_tag: str | None = None
    ) -> Result[ProviderZoneRecord, str]: ...
    @abstractmethod
    def create_record(self, binding: ZoneBinding, spec: ZoneRecordSpec) -> Result[ProviderZoneRecord, str]: ...
    @abstractmethod
    def update_record(
        self, binding: ZoneBinding, record_id: str, spec: ZoneRecordSpec
    ) -> Result[ProviderZoneRecord, str]: ...
    @abstractmethod
    def delete_record(self, binding: ZoneBinding, record_id: str, *, expected_owner_tag: str) -> Result[None, str]: ...
    @abstractmethod
    def get_dnssec(self, binding: ZoneBinding) -> Result[DnssecStatus, str]: ...


_REGISTRY: dict[str, Callable[[], ZoneGateway]] = {}


def register_zone_gateway(provider: str, factory: Callable[[], ZoneGateway]) -> None:
    _REGISTRY[provider] = factory


def get_zone_gateway(provider: str = "cloudflare") -> ZoneGateway:
    if provider in _REGISTRY:
        return _REGISTRY[provider]()
    if provider != "cloudflare":
        raise ValueError("Unknown customer-zone provider")
    from apps.settings.services import SettingsService  # noqa: PLC0415

    from .dns_zone_cloudflare import CloudflareZoneGateway  # noqa: PLC0415

    return CloudflareZoneGateway(
        token=str(SettingsService.get_setting("dns.cloudflare_account_api_token", "") or ""),
        account_id=str(SettingsService.get_setting("dns.cloudflare_account_id", "") or ""),
    )
