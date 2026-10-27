"""Pure, snapshot-bound mail DNS proposals; no discovery, publication or readiness claims.

SPF selection/TXT joining and fallback semantics follow RFC7208 sections3.2-3.3,
4.6.4,5.1 and6.1. DKIM selector uniqueness follows RFC6376 section3.6.2.2.
Recursive SPF evaluation and positive/negative DNS cache evidence belong to later workers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Literal, cast

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.TXT import TXT

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_zone_gateway import (
    MAX_RECORD_TTL,
    MAX_WIRE_RDATA,
    MIN_RECORD_TTL,
    RR_HEADER_BYTES,
    canonical_dns_name,
    canonical_rdata,
    owned_local_id,
)

from .virtualmin_mail_service import MIN_DKIM_RSA_BITS, MailDkimObservation

MAX_RECORDS = 2000
MAX_RRSET_RECORDS = 128
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_CONSENT_BYTES = 64 * 1024
MAX_SPF_LOOKUPS = 10
MAX_TXT_CHUNK = 255
MAX_SELECTOR_LENGTH = 63
MAX_OWNER_TAG_LENGTH = 253
MAX_IPV4_PREFIX = 32
MAX_IPV6_PREFIX = 128
MIN_PRINTABLE_ASCII = 32
MAX_PRINTABLE_ASCII = 127
type MailDnsScope = Literal["zone", "rrsets"]
type MailDnsCoverage = tuple[tuple[str, str], ...]
_DIGEST = re.compile(r"[a-f0-9]{64}")
_CIDR = re.compile(r"(?::(?P<domain>[^/]+))?(?:/(?P<v4>[0-9]{1,3}))?(?://(?P<v6>[0-9]{1,3}))?")


class _PlanError(ValueError):
    """A fixed refusal code, never raw provider/native material."""


@dataclass(frozen=True)
class MailDnsRecord:
    name: str
    record_type: str
    ttl: int
    rdata: str
    owner_tag: str = ""
    proxied: bool = False


@dataclass(frozen=True)
class MailDnsSnapshot:
    """Zone scope is a complete P4 inventory; RRset scope lists only explicitly complete observations."""

    zone_name: str
    revision: int
    digest: str
    records: tuple[MailDnsRecord, ...]
    scope: MailDnsScope = "zone"
    covered_rrsets: MailDnsCoverage = ()


@dataclass(frozen=True)
class MailDnsChange:
    slot: str
    before: tuple[MailDnsRecord, ...]
    after: tuple[MailDnsRecord, ...]


def _public(record: MailDnsRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "record_type": record.record_type,
        "ttl": record.ttl,
        "rdata": record.rdata,
        "proxied": record.proxied,
    }


@dataclass(frozen=True)
class MailDnsPlan:
    """Observed inventories describe input scope only. Publishers apply changes, never replace a zone."""

    domain: str
    account_hostname: str
    zone_name: str
    snapshot_revision: int
    snapshot_digest: str
    scope: MailDnsScope
    covered_rrsets: MailDnsCoverage
    observed_before_records: tuple[MailDnsRecord, ...]
    observed_after_records: tuple[MailDnsRecord, ...]
    changes: tuple[MailDnsChange, ...]
    spf_lookup_terms: int

    def to_consent(self) -> dict[str, Any]:
        """Only exact reviewed mail changes cross the public boundary; provider ownership stays private."""
        return {
            "version": 1,
            "kind": "hosted_mail_dns",
            "domain": self.domain,
            "account_hostname": self.account_hostname,
            "source": {
                "zone_name": self.zone_name,
                "revision": self.snapshot_revision,
                "digest": self.snapshot_digest,
                "scope": self.scope,
                "covered_rrsets": [{"name": name, "record_type": kind} for name, kind in self.covered_rrsets],
            },
            "changes": [
                {
                    "slot": item.slot,
                    "before": [_public(row) for row in item.before],
                    "after": [_public(row) for row in item.after],
                }
                for item in self.changes
            ],
            "preserved_observed_records": len(self.observed_before_records)
            - sum(len(item.before) for item in self.changes),
            "spf_local_lookup_terms": self.spf_lookup_terms,
            "checks": {
                "recursive_spf_lookups": "unverified",
                "cache_lifetimes": "unverified",
                "negative_ttl": "unverified",
            },
        }


def _records(zone: str, records: tuple[MailDnsRecord, ...]) -> tuple[MailDnsRecord, ...]:
    if not isinstance(records, tuple) or len(records) > MAX_RECORDS:
        raise _PlanError("mail_dns_snapshot_invalid")
    origin = dns.name.from_text(zone)
    normalized = []
    counts: dict[tuple[str, str], int] = {}
    for row in records:
        if not isinstance(row, MailDnsRecord):
            raise _PlanError("mail_dns_snapshot_invalid")
        name = canonical_dns_name(row.name)
        if (
            not dns.name.from_text(name).is_subdomain(origin)
            or type(row.ttl) is not int
            or not 0 <= row.ttl <= 2**31 - 1
            or type(row.proxied) is not bool
            or not isinstance(row.owner_tag, str)
            or len(row.owner_tag) > MAX_OWNER_TAG_LENGTH
        ):
            raise _PlanError("mail_dns_snapshot_invalid")
        record = replace(row, name=name, rdata=canonical_rdata(row.record_type, row.rdata, origin=zone))
        parsed = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(record.record_type), record.rdata)
        owner_wire, data_wire = dns.name.from_text(name).to_wire(), parsed.to_wire()
        if (
            owner_wire is None
            or data_wire is None
            or len(owner_wire) + RR_HEADER_BYTES + len(data_wire) > MAX_WIRE_RDATA
            or (record.proxied and record.record_type not in {"A", "AAAA", "CNAME"})
        ):
            raise _PlanError("mail_dns_snapshot_invalid")
        key = (name, row.record_type)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > MAX_RRSET_RECORDS:
            raise _PlanError("mail_dns_snapshot_invalid")
        normalized.append(record)
    return tuple(normalized)


def _coverage(scope: str, covered: MailDnsCoverage, zone: str) -> MailDnsCoverage:
    if scope not in {"zone", "rrsets"} or not isinstance(covered, tuple) or len(covered) > MAX_RECORDS:
        raise _PlanError("mail_dns_snapshot_invalid")
    if scope == "zone" and covered:
        raise _PlanError("mail_dns_snapshot_invalid")
    result = []
    for name, kind in covered:
        canonical = canonical_dns_name(name)
        if not dns.name.from_text(canonical).is_subdomain(dns.name.from_text(zone)) or kind not in {
            "A",
            "AAAA",
            "MX",
            "TXT",
            "CNAME",
            "SRV",
            "CAA",
        }:
            raise _PlanError("mail_dns_snapshot_invalid")
        result.append((canonical, kind))
    if len(set(result)) != len(result):
        raise _PlanError("mail_dns_snapshot_invalid")
    return tuple(sorted(result))


def _snapshot_payload(
    zone: str, revision: int, records: tuple[MailDnsRecord, ...], scope: str, covered: MailDnsCoverage
) -> bytes:
    if type(revision) is not int or revision < 1:
        raise _PlanError("mail_dns_snapshot_invalid")
    rows = sorted((asdict(row) for row in records), key=lambda row: json.dumps(row, sort_keys=True))
    wire = json.dumps(
        {
            "version": 1,
            "zone_name": zone,
            "revision": revision,
            "scope": scope,
            "covered_rrsets": covered,
            "records": rows,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    if len(wire) > MAX_SNAPSHOT_BYTES:
        raise _PlanError("mail_dns_snapshot_invalid")
    return wire


def mail_dns_snapshot_digest(
    zone_name: str,
    revision: int,
    records: tuple[MailDnsRecord, ...],
    *,
    scope: MailDnsScope = "zone",
    covered_rrsets: MailDnsCoverage = (),
) -> str:
    """Digest the full current manifest, including TTL/proxy/ownership, not the original import upload."""
    zone = canonical_dns_name(zone_name)
    covered = _coverage(scope, covered_rrsets, zone)
    return hashlib.sha256(_snapshot_payload(zone, revision, _records(zone, records), scope, covered)).hexdigest()


def _snapshot(snapshot: MailDnsSnapshot) -> tuple[str, tuple[MailDnsRecord, ...]]:
    if not isinstance(snapshot.digest, str) or _DIGEST.fullmatch(snapshot.digest) is None:
        raise _PlanError("mail_dns_snapshot_stale")
    zone = canonical_dns_name(snapshot.zone_name)
    records = _records(zone, snapshot.records)
    covered = _coverage(snapshot.scope, snapshot.covered_rrsets, zone)
    digest = hashlib.sha256(_snapshot_payload(zone, snapshot.revision, records, snapshot.scope, covered)).hexdigest()
    if not hmac.compare_digest(digest, snapshot.digest):
        raise _PlanError("mail_dns_snapshot_stale")
    return zone, records


def _txt_octets(record: MailDnsRecord) -> bytes:
    parsed = cast(TXT, dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, record.rdata))
    return b"".join(parsed.strings)


def _txt(value: str) -> str:
    raw = value.encode("ascii")
    strings = tuple(raw[index : index + MAX_TXT_CHUNK] for index in range(0, len(raw), MAX_TXT_CHUNK))
    return TXT(dns.rdataclass.IN, dns.rdatatype.TXT, strings or (b"",)).to_text()


def _literal(value: str) -> str:
    if not value or "%" in value or "*" in value:
        raise _PlanError("mail_spf_policy_unsupported")
    return canonical_dns_name(value)


def _hostname(value: str) -> str:
    name = canonical_dns_name(value)
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")):
        raise _PlanError("mail_dns_preparation_required")
    return name


def _public_dkim(observed: MailDkimObservation | None, domain: str) -> tuple[str, str]:
    try:
        if not isinstance(observed, MailDkimObservation) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", observed.selector
        ):
            raise ValueError("missing observed selector")
        name = canonical_dns_name(observed.record_name)
        if name != canonical_dns_name(f"{observed.selector}._domainkey.{domain}"):
            raise ValueError("foreign observed key")
        prefix = "v=DKIM1; k=rsa; p="
        if not observed.record_value.startswith(prefix) or len(observed.record_value) > MAX_WIRE_RDATA:
            raise ValueError("missing observed public key")
        key = serialization.load_der_public_key(base64.b64decode(observed.record_value[len(prefix) :], validate=True))
        if not isinstance(key, RSAPublicKey) or key.key_size < MIN_DKIM_RSA_BITS:
            raise ValueError("unsupported observed key")
        return name, observed.record_value
    except (ValueError, TypeError, AttributeError, UnicodeError, dns.exception.DNSException) as error:
        raise _PlanError("mail_dkim_preparation_required") from error


def _mx_targets(records: tuple[MailDnsRecord, ...]) -> set[str]:
    targets = set()
    for row in records:
        parsed = cast(MX, dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, row.rdata))
        exchange = parsed.exchange.to_text(omit_final_dot=True)
        if exchange:
            targets.add(exchange.lower())
    return targets


def _mechanism(term: str, domain: str, include: str) -> tuple[int, bool, bool]:
    qualifier = term[0] if term[:1] in {"+", "-", "~", "?"} else "+"
    body = term[1:] if term[:1] in {"+", "-", "~", "?"} else term
    match = re.fullmatch(r"([A-Za-z0-9]+)(.*)", body)
    if match is None:
        raise _PlanError("mail_spf_policy_unsupported")
    name, suffix = match.group(1).lower(), match.group(2)
    if name in {"ip4", "ip6"}:
        network = ipaddress.ip_network(suffix.removeprefix(":"), strict=False) if suffix.startswith(":") else None
        if network is None or network.version != (4 if name == "ip4" else 6):
            raise _PlanError("mail_spf_policy_unsupported")
        return 0, False, False
    if name in {"a", "mx"}:
        parsed = _CIDR.fullmatch(suffix)
        if (
            parsed is None
            or (parsed["v4"] is not None and int(parsed["v4"]) > MAX_IPV4_PREFIX)
            or (parsed["v6"] is not None and int(parsed["v6"]) > MAX_IPV6_PREFIX)
        ):
            raise _PlanError("mail_spf_policy_unsupported")
        target = _literal(parsed["domain"]) if parsed["domain"] else domain
        return 1, False, name == "mx" and target == domain
    if name in {"include", "exists", "ptr"}:
        target = _literal(suffix[1:]) if suffix.startswith(":") else domain if name == "ptr" and not suffix else ""
        if not target or (name == "include" and target == domain):
            raise _PlanError("mail_spf_policy_unsupported")
        if name == "include" and target == include and qualifier != "+":
            raise _PlanError("mail_spf_include_conflict")
        return 1, name == "include" and target == include, False
    raise _PlanError("mail_spf_policy_unsupported")


@dataclass
class _SpfTerms:
    mechanisms: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    terminal: str | None = None
    redirect: bool = False
    seen_include: bool = False
    lookups: int = 0


def _modifier(term: str, previous: list[str], domain: str) -> bool:
    name, _, target = term.partition("=")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", name):
        raise _PlanError("mail_spf_policy_unsupported")
    if name.lower() not in {"redirect", "exp"}:
        return False  # RFC7208 section6 requires unknown modifiers to be ignored.
    if any(item.partition("=")[0].lower() == name.lower() for item in previous):
        raise _PlanError("mail_spf_policy_unsupported")
    target_name = _literal(target)
    if name.lower() == "redirect" and target_name == domain:
        raise _PlanError("mail_spf_policy_unsupported")
    return name.lower() == "redirect"


def _spf_term(policy: _SpfTerms, term: str, domain: str, include: str, external_mx: bool) -> None:
    if "=" in term:
        redirected = _modifier(term, policy.modifiers, domain)
        policy.redirect = policy.redirect or redirected
        policy.lookups += int(redirected)
        policy.modifiers.append(term)
        return
    if policy.terminal is not None:
        raise _PlanError("mail_spf_policy_unsupported")
    if term.lower() in {"all", "+all", "-all", "~all", "?all"}:
        if term.lower() in {"all", "+all"}:
            raise _PlanError("mail_spf_policy_unsupported")
        policy.terminal = term
        return
    cost, present, current_mx = _mechanism(term, domain, include)
    if current_mx and external_mx:
        raise _PlanError("mail_spf_mx_dependency")
    policy.mechanisms.append(term)
    policy.seen_include = policy.seen_include or present
    policy.lookups += cost


def _merge_spf(value: str | None, domain: str, include: str, external_mx: bool) -> tuple[str, int]:
    if value is None:
        return f"v=spf1 include:{include} ?all", 1
    if any(not MIN_PRINTABLE_ASCII <= ord(character) < MAX_PRINTABLE_ASCII for character in value) or "%" in value:
        raise _PlanError("mail_spf_policy_unsupported")
    policy = _SpfTerms()
    for term in (term for term in value.split(" ")[1:] if term):
        _spf_term(policy, term, domain, include, external_mx)
    if policy.terminal is not None and policy.redirect:
        raise _PlanError("mail_spf_policy_unsupported")
    if not policy.seen_include:
        policy.mechanisms.append(f"include:{include}")
        policy.lookups += 1
    if policy.lookups > MAX_SPF_LOOKUPS:
        raise _PlanError("mail_spf_lookup_limit")
    if policy.seen_include:
        return value, policy.lookups
    return " ".join(
        ["v=spf1", *policy.mechanisms, *([policy.terminal] if policy.terminal else []), *policy.modifiers]
    ), policy.lookups


def _changed_record(name: str, kind: str, value: str, ttl: int, previous: MailDnsRecord | None = None) -> MailDnsRecord:
    desired_ttl = previous.ttl if previous is not None and MIN_RECORD_TTL <= previous.ttl <= MAX_RECORD_TTL else ttl
    return MailDnsRecord(name, kind, desired_ttl, canonical_rdata(kind, value), previous.owner_tag if previous else "")


def _spf_change(
    records: tuple[MailDnsRecord, ...], domain: str, include: str, account_name: str, ttl: int
) -> tuple[MailDnsChange | None, int]:
    selected = [
        row
        for row in records
        if row.name == domain and row.record_type == "TXT" and re.match(rb"^v=spf1(?: |$)", _txt_octets(row), re.I)
    ]
    if len(selected) > 1:
        raise _PlanError("mail_spf_ambiguous")
    previous = selected[0] if selected else None
    old = _txt_octets(previous).decode("ascii") if previous else None
    mx = tuple(row for row in records if row.name == domain and row.record_type == "MX")
    merged, lookups = _merge_spf(old, domain, include, bool(_mx_targets(mx) - {account_name}))
    if previous is not None and merged == old:
        return None, lookups
    after = _changed_record(domain, "TXT", _txt(merged), ttl, previous)
    return MailDnsChange("spf", tuple(selected), (after,)), lookups


def _dkim_change(
    records: tuple[MailDnsRecord, ...], name: str, value: str, ttl: int, owned: str
) -> MailDnsChange | None:
    if owned:
        owned_local_id(owned)
    selected = tuple(row for row in records if row.name == name and row.record_type in {"TXT", "CNAME"})
    if any(row.record_type == "CNAME" for row in selected) or len(selected) > 1:
        raise _PlanError("mail_dkim_conflict")
    previous = selected[0] if selected else None
    if previous is not None:
        if _txt_octets(previous) == value.encode("ascii"):
            return None
        if not owned or previous.owner_tag != owned:
            raise _PlanError("mail_dkim_conflict")
    after = _changed_record(name, "TXT", _txt(value), ttl, previous)
    return MailDnsChange("dkim", selected, (after,))


def _require_observations(snapshot: MailDnsSnapshot, domain: str, dkim_name: str) -> MailDnsCoverage:
    covered = _coverage(snapshot.scope, snapshot.covered_rrsets, snapshot.zone_name)
    required = {(domain, "MX"), (domain, "TXT"), (domain, "CNAME"), (dkim_name, "TXT"), (dkim_name, "CNAME")}
    if snapshot.scope == "rrsets" and not required.issubset(covered):
        raise _PlanError("mail_dns_observation_incomplete")
    return covered


def build_mail_dns_plan(  # noqa: PLR0913  # Independent snapshot and prepared public-mail inputs.
    snapshot: MailDnsSnapshot,
    *,
    domain: str,
    account_hostname: str,
    spf_include: str,
    dkim: MailDkimObservation | None,
    ttl: int = 300,
    owned_dkim_tag: str = "",
) -> Result[MailDnsPlan, str]:
    """Plan only the named domain's mail records inside the supplied containing DNS scope."""
    try:
        zone, records = _snapshot(snapshot)
        domain, account_name, include = canonical_dns_name(domain), _hostname(account_hostname), _literal(spf_include)
        contained = dns.name.from_text(domain).is_subdomain(dns.name.from_text(zone))
        if not contained or include == domain or type(ttl) is not int or not MIN_RECORD_TTL <= ttl <= MAX_RECORD_TTL:
            raise _PlanError("mail_dns_preparation_required")
        if any(row.record_type == "CNAME" and row.name == domain for row in records):
            raise _PlanError("mail_dns_cname_conflict")
        if any(row.proxied and (row.name == domain and row.record_type in {"MX", "TXT"}) for row in records):
            raise _PlanError("mail_dns_snapshot_invalid")
        dkim_name, dkim_value = _public_dkim(dkim, domain)
        covered = _require_observations(snapshot, domain, dkim_name)
        before_mx = tuple(row for row in records if row.name == domain and row.record_type == "MX")
        after_mx = _changed_record(domain, "MX", f"10 {account_name}.", ttl)
        mx_change = (
            None
            if len(before_mx) == 1 and before_mx[0].rdata == after_mx.rdata
            else MailDnsChange("mx", before_mx, (after_mx,))
        )
        spf_change, lookups = _spf_change(records, domain, include, account_name, ttl)
        dkim_change = _dkim_change(records, dkim_name, dkim_value, ttl, owned_dkim_tag)
        changes = tuple(change for change in (mx_change, spf_change, dkim_change) if change is not None)
        removed = {row for change in changes for row in change.before}
        after = _records(
            zone,
            tuple(row for row in records if row not in removed)
            + tuple(row for change in changes for row in change.after),
        )
        _snapshot_payload(zone, snapshot.revision, after, snapshot.scope, covered)
        plan = MailDnsPlan(
            domain=domain,
            account_hostname=account_name,
            zone_name=zone,
            snapshot_revision=snapshot.revision,
            snapshot_digest=snapshot.digest,
            scope=snapshot.scope,
            covered_rrsets=covered,
            observed_before_records=records,
            observed_after_records=after,
            changes=changes,
            spf_lookup_terms=lookups,
        )
        if len(json.dumps(plan.to_consent(), ensure_ascii=True).encode()) > MAX_CONSENT_BYTES:
            raise _PlanError("mail_dns_plan_limit")
        return Ok(plan)
    except _PlanError as error:
        return Err(str(error))
    except (ValueError, TypeError, AttributeError, UnicodeError, dns.exception.DNSException):
        return Err("mail_dns_preparation_invalid")


def check_mail_dns_plan(plan: MailDnsPlan, current_snapshot: MailDnsSnapshot) -> Result[None, str]:
    """Before the first write, match fresh observations of exactly the plan's declared scope.

    The caller supplies a complete P4 inventory or the declared complete RRsets, and retains
    account/provider authorization. This check performs no DNS enumeration or discovery.
    """
    try:
        zone, _records_now = _snapshot(current_snapshot)
        coverage = _coverage(current_snapshot.scope, current_snapshot.covered_rrsets, zone)
        if (zone, current_snapshot.revision, current_snapshot.digest, current_snapshot.scope, coverage) != (
            plan.zone_name,
            plan.snapshot_revision,
            plan.snapshot_digest,
            plan.scope,
            plan.covered_rrsets,
        ):
            raise _PlanError("mail_dns_snapshot_stale")
        return Ok(None)
    except (_PlanError, ValueError, TypeError, AttributeError, dns.exception.DNSException):
        return Err("mail_dns_snapshot_stale")
