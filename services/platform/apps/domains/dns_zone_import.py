"""Complete, bounded DNS-zone staging before any provider call is permitted."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.transaction
import dns.zone
import dns.zonefile
import idna

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_EXPORT_BYTES = MAX_UPLOAD_BYTES
MAX_RECORDS = 2000
MAX_RECORD_BYTES = 4096
MIN_DOMAIN_LABELS_WITH_ROOT = 3
MAX_DOMAIN_LENGTH = 253
MIN_RECORD_TTL = 60
MAX_RECORD_TTL = 86400
SUPPORTED_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"})


def normalize_zone_name(value: str) -> str:
    text = value.strip()
    if text.endswith("."):
        text = text[:-1]
    ascii_name = idna.encode(text, uts46=True).decode("ascii").lower()
    name = dns.name.from_text(ascii_name)
    if (
        len(name.labels) < MIN_DOMAIN_LABELS_WITH_ROOT
        or len(ascii_name) > MAX_DOMAIN_LENGTH
        or any(not label for label in name.labels[:-1])
    ):
        raise ValueError("A complete hosting domain is required")
    return name.canonicalize().to_text(omit_final_dot=True)


def make_record_data(record_type: str, text: str, *, origin: str | None = None) -> dict[str, str]:
    """One canonical wire/text representation; TXT octets and string boundaries are retained."""
    name = dns.name.from_text(origin) if origin else dns.name.root
    value = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.from_text(record_type), text, origin=name, relativize=False
    )
    wire = value.to_digestable()
    canonical = dns.rdata.from_wire(dns.rdataclass.IN, value.rdtype, wire, 0, len(wire))
    return {"text": canonical.to_text(origin=name, relativize=False), "wire": wire.hex()}


def record_text(data: dict[str, Any]) -> str:
    return str(data["text"])


def render_zone_file(name: str, records: list[dict[str, Any]], *, infrastructure: list[dict[str, Any]]) -> bytes:
    """A bounded self-importable export; provider infrastructure remains an explicit replacement."""
    lines = [
        f"$ORIGIN {normalize_zone_name(name)}.\n",
        "$TTL 300\n",
        "; SOA and apex NS are provider infrastructure and must be reviewed at the receiving provider.\n",
    ]
    lines.extend(
        f"{row['name']}. {int(row['ttl'])} IN {row['record_type']} {row['rdata']['text']}\n"
        for row in [*infrastructure, *records]
    )
    raw = "".join(lines).encode("utf-8")
    if len(raw) > MAX_EXPORT_BYTES:
        raise ZoneImportError("canonical_zone_limit")
    return raw


@dataclass(frozen=True)
class ParsedZoneRecord:
    name: str
    record_type: str
    ttl: int
    rdata: str
    wire: str
    digest: str
    line: int
    infrastructure: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "record_type": self.record_type,
            "ttl": self.ttl,
            "rdata": {"text": self.rdata, "wire": self.wire},
            "rdata_digest": self.digest,
            "line": self.line,
            "infrastructure": self.infrastructure,
        }


@dataclass(frozen=True)
class ParsedZoneFile:
    name: str
    records: tuple[ParsedZoneRecord, ...]
    duplicates: tuple[ParsedZoneRecord, ...]
    source_count: int
    raw_digest: str
    digest: str

    @property
    def replacements(self) -> tuple[ParsedZoneRecord, ...]:
        return tuple(record for record in self.records if record.infrastructure)


class ZoneImportError(ValueError):
    def __init__(self, code: str, *, line: int = 0, records: tuple[ParsedZoneRecord, ...] = ()) -> None:
        # Never include arbitrary record values, parser tokens or file paths in logs/errors.
        super().__init__(f"{code} (line {line})")
        self.code = code
        self.line = line
        self.records = records


class _Capture:
    """Reader adapter captures each add before dnspython's union/dedup/TTL normalization."""

    def __init__(self, wrapped: dns.transaction.Transaction, origin: dns.name.Name) -> None:
        self.wrapped = wrapped
        self.manager = wrapped.manager
        self.origin = origin
        self.records: list[ParsedZoneRecord] = []
        self.line = 0
        self.ttls: dict[tuple[str, str], int] = {}

    def check_put_rdataset(self, callback: Any) -> None:
        self.wrapped.check_put_rdataset(callback)

    def _set_origin(self, origin: dns.name.Name) -> None:
        cast(Callable[[dns.name.Name], None], self.wrapped._set_origin)(origin)

    def add(self, owner: dns.name.Name, ttl: int, value: dns.rdata.Rdata) -> None:
        name = owner.canonicalize().to_text(omit_final_dot=True)
        kind = dns.rdatatype.to_text(value.rdtype)
        wire = value.to_digestable()
        canonical = dns.rdata.from_wire(dns.rdataclass.IN, value.rdtype, wire, 0, len(wire))
        infrastructure = owner == self.origin and kind in {"SOA", "NS"}
        item = ParsedZoneRecord(
            name,
            kind,
            ttl,
            canonical.to_text(relativize=False),
            wire.hex(),
            hashlib.sha256(wire).hexdigest(),
            self.line,
            infrastructure,
        )
        self.records.append(item)
        reason = (
            "out_of_zone_owner"
            if not owner.is_subdomain(self.origin)
            else "soa_not_apex"
            if kind == "SOA" and owner != self.origin
            else "apex_cname"
            if kind == "CNAME" and owner == self.origin
            else "record_limit"
            if len(self.records) > MAX_RECORDS
            else "record_too_large"
            if len(wire) > MAX_RECORD_BYTES
            else ""
        )
        if reason:
            raise ZoneImportError(reason, line=self.line, records=tuple(self.records))
        key = (name, kind)
        if key in self.ttls and self.ttls[key] != ttl:
            raise ZoneImportError("conflicting_rrset_ttl", line=self.line, records=tuple(self.records))
        self.ttls[key] = ttl
        self.wrapped.add(owner, ttl, value)


class _Reader(dns.zonefile.Reader):
    def _rr_line(self) -> None:
        capture = cast(_Capture, self.txn)
        capture.line = self.tok.where()[1]
        cast(Callable[[], None], super()._rr_line)()


def _finish(name: str, raw: bytes, records: list[ParsedZoneRecord]) -> ParsedZoneFile:
    unsupported = [item for item in records if item.record_type not in SUPPORTED_TYPES and not item.infrastructure]
    if unsupported:
        raise ZoneImportError("unsupported_records", line=unsupported[0].line, records=tuple(records))
    invalid_ttl = next(
        (item for item in records if not item.infrastructure and not MIN_RECORD_TTL <= item.ttl <= MAX_RECORD_TTL), None
    )
    if invalid_ttl:
        raise ZoneImportError("ttl_out_of_range", line=invalid_ttl.line, records=tuple(records))
    if not {"SOA", "NS"}.issubset({item.record_type for item in records if item.infrastructure}):
        raise ZoneImportError("missing_apex_infrastructure", records=tuple(records))
    unique: dict[tuple[str, str, str], ParsedZoneRecord] = {}
    duplicates = []
    for item in records:
        key = item.name, item.record_type, item.digest
        if key in unique:
            duplicates.append(item)
        else:
            unique[key] = item
    inventory = tuple(sorted(unique.values(), key=lambda item: (item.name, item.record_type, item.digest)))
    semantic = [(item.name, item.record_type, item.ttl, item.wire) for item in inventory]
    digest = hashlib.sha256(json.dumps(semantic, separators=(",", ":")).encode()).hexdigest()
    return ParsedZoneFile(name, inventory, tuple(duplicates), len(records), hashlib.sha256(raw).hexdigest(), digest)


def parse_zone_file(raw: bytes, zone_name: str) -> ParsedZoneFile:
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ZoneImportError("upload_limit")
    try:
        name = normalize_zone_name(zone_name)
        text = raw.decode("utf-8-sig")
    except (ValueError, UnicodeError, dns.exception.DNSException) as error:
        raise ZoneImportError("invalid_zone_file") from error
    origin = dns.name.from_text(name)
    zone = dns.zone.Zone(origin, relativize=False)
    with zone.writer() as transaction:
        capture = _Capture(transaction, origin)
        tokenizer = dns.tokenizer.Tokenizer(text, "upload")
        reader = _Reader(
            tokenizer,
            dns.rdataclass.IN,
            cast(dns.transaction.Transaction, capture),
            allow_include=False,
            allow_directives=("$ORIGIN", "$TTL"),
        )
        # Reader normally discards out-of-zone owners before txn.add. Accept the
        # DNS root here, then explicitly enforce the requested boundary in add.
        reader.zone_origin = dns.name.root
        reader.current_origin = origin
        reader.last_name = origin
        reader.relativize = False
        try:
            reader.read()
        except ZoneImportError:
            raise
        except (dns.exception.DNSException, ValueError, UnicodeError) as error:
            raise ZoneImportError(
                "invalid_zone_file", line=capture.line or tokenizer.where()[1], records=tuple(capture.records)
            ) from error
        return _finish(name, raw, capture.records)
