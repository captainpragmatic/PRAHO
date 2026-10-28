"""Bounded read-only customer DNS diagnostics; no request-path or customer HTTP calls.

All discovery and authoritative TCP questions share one clock and wire-query ledger.
DNSSEC here compares parent DS and child DNSKEY only: it does not validate signatures.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any, Literal, TypedDict, cast

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.dnssecalgs import get_algorithm_cls_from_dnskey
from dns.rdtypes.ANY.CAA import CAA
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.MX import MX

from apps.infrastructure.panel_cert_probes import public_address

from .dns_caa import parse_caa_issue

MAX_NAMESERVERS = 8
MAX_CNAME_HOPS = 8
MAX_DISCOVERY_LABELS = 32
MIN_DNS_LABELS = 2
MAX_RECORDS = 128
MAX_RRSETS = 64
MAX_RECORD_BYTES = 4096
MAX_EVIDENCE_RECORDS = 8
MAX_EVIDENCE_TEXT = 256
MAX_COMPONENT_EVIDENCE = 8192
QUERY_TIMEOUT = 3.0
DNSSEC_ZONE_FLAG = 256
DNSSEC_REVOKED_FLAG = 128
DNSSEC_PROTOCOL = 3

ProbeState = Literal["healthy", "broken", "unknown", "not_applicable"]


class ComponentObservation(TypedDict):
    state: ProbeState
    code: str
    name: str
    record_type: str
    checked_at: str
    ttl: int | None
    evidence: dict[str, Any]


class ProbeReport(TypedDict):
    version: Literal[1]
    dns_path: str
    components: dict[str, ComponentObservation]


@dataclass(frozen=True)
class ProbeTarget:
    domain: str
    account_hostname: str
    ipv4: str
    ipv6: str | None = None
    hosted_mail: bool = False


class ProbeError(Exception):
    def __init__(self, code: str, *, state: ProbeState = "unknown", evidence: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.state = state
        self.evidence = evidence or {}


@dataclass
class ProbeBudget:
    seconds: float = 90.0
    max_queries: int = 96
    clock: Callable[[], float] = time.monotonic
    queries: int = field(default=0, init=False)
    deadline: float = field(init=False)

    def __post_init__(self) -> None:
        self.deadline = self.clock() + min(max(self.seconds, 0.0), 90.0)
        self.max_queries = min(max(self.max_queries, 0), 96)

    def check(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise ProbeError("probe_budget_exhausted")
        return min(QUERY_TIMEOUT, remaining)

    def dispatch(self) -> float:
        timeout = self.check()
        if self.queries >= self.max_queries:
            raise ProbeError("probe_budget_exhausted")
        self.queries += 1
        return timeout


@dataclass(frozen=True)
class WireQuestion:
    name: str
    record_type: str
    server: str
    recursive: bool
    timeout: float
    zone: str = ""


@dataclass(frozen=True)
class Records:
    name: str
    record_type: str
    zone: str
    values: tuple[dns.rdata.Rdata, ...] = ()
    alias: str = ""
    negative: str = ""
    ttl: int | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "zone": self.zone,
            "records": [value.to_text()[:MAX_EVIDENCE_TEXT] for value in self.values[:MAX_EVIDENCE_RECORDS]],
            "records_truncated": len(self.values) > MAX_EVIDENCE_RECORDS
            or any(len(value.to_text()) > MAX_EVIDENCE_TEXT for value in self.values),
            "alias": self.alias,
            "negative": self.negative,
            "ttl": self.ttl,
        }


def _name(value: str) -> str:
    parsed = dns.name.from_text(value).canonicalize()
    if len(parsed.labels) < MIN_DNS_LABELS or len(parsed.labels) > MAX_DISCOVERY_LABELS or b"*" in parsed.labels:
        raise ProbeError("invalid_dns_name")
    return parsed.to_text(omit_final_dot=True)


def _parent(value: str) -> str:
    """The parent name, or "" above a TLD: no climb asks the DNS root (RFC 8659 stops at the TLD).

    The root renders as ".", which is truthy, so a `while current:` climb needs this to end.
    """
    parent = dns.name.from_text(value).parent()
    return "" if parent == dns.name.root else parent.to_text(omit_final_dot=True)


def _tcp_question(question: WireQuestion) -> dns.message.Message:
    query = dns.message.make_query(question.name, question.record_type, want_dnssec=True)
    if not question.recursive:
        query.flags &= ~dns.flags.RD
    return dns.query.tcp(query, question.server, timeout=question.timeout)


class DnsProbeTransport:
    """Memoized all-authority queries with explicit discovery and a single wire budget."""

    def __init__(
        self,
        *,
        budget: ProbeBudget | None = None,
        query: Callable[[WireQuestion], dns.message.Message] | None = None,
        recursive_servers: tuple[str, ...] | None = None,
    ) -> None:
        self.budget = budget or ProbeBudget()
        self._wire = query or _tcp_question
        # System recursive servers are operator configuration, not customer NS destinations.
        configured = (
            recursive_servers
            if recursive_servers is not None
            else tuple(str(ns) for ns in dns.resolver.Resolver().nameservers)
        )
        self._recursive_servers = tuple(str(ipaddress.ip_address(server)) for server in configured[:2])
        self._cache: dict[tuple[str, str, bool], Records] = {}
        self._zones: dict[str, str] = {}
        self._authorities: dict[str, tuple[str, ...]] = {}
        self._addresses: dict[str, str] = {}

    def _ask(self, name: str, kind: str, server: str, *, recursive: bool, zone: str = "") -> dns.message.Message:
        question = WireQuestion(name, kind, server, recursive, self.budget.dispatch(), zone)
        try:
            response = self._wire(question)
        except (dns.exception.DNSException, OSError, ValueError) as error:
            raise ProbeError("dns_query_failed", evidence={"name": name, "type": kind, "server": server}) from error
        self.budget.check()
        expected = dns.message.make_query(name, kind).question
        if response.question != expected or response.flags & dns.flags.TC:
            raise ProbeError("dns_response_invalid")
        rrsets = [*response.answer, *response.authority, *response.additional]
        if any(rrset.rdclass != dns.rdataclass.IN for rrset in rrsets):
            raise ProbeError("dns_response_invalid")
        if len(rrsets) > MAX_RRSETS or sum(len(rrset) for rrset in rrsets) > MAX_RECORDS:
            raise ProbeError("dns_response_too_large")
        if any(len(record.to_wire()) > MAX_RECORD_BYTES for rrset in rrsets for record in rrset):
            raise ProbeError("dns_response_too_large")
        if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            code = f"dns_rcode_{dns.rcode.to_text(response.rcode()).lower()}"
            raise ProbeError(code)
        if not recursive and not response.flags & dns.flags.AA:
            raise ProbeError("dns_not_authoritative")
        return response

    def _recursive(self, name: str, kind: str) -> dns.message.Message:
        if not self._recursive_servers:
            raise ProbeError("dns_discovery_unavailable")
        # One explicit bounded question: no resolver-internal retries outside our ledger.
        return self._ask(name, kind, self._recursive_servers[0], recursive=True)

    def zone(self, name: str) -> str:
        self.budget.check()
        name = _name(name)
        if name in self._zones:
            return self._zones[name]
        current = name
        while current:
            response = self._recursive(current, "SOA")
            candidates = [
                rrset.name
                for rrset in [*response.answer, *response.authority]
                if rrset.rdtype == dns.rdatatype.SOA and dns.name.from_text(current).is_subdomain(rrset.name)
            ]
            if candidates:
                closest = max(candidates, key=lambda candidate: len(candidate.labels))
                if closest == dns.name.root:  # A nonexistent TLD: the root is never a customer's zone.
                    raise ProbeError("dns_zone_unknown")
                zone = closest.to_text(omit_final_dot=True)
                self._zones[name] = zone
                return zone
            current = _parent(current)
        raise ProbeError("dns_zone_unknown")

    def _servers(self, zone: str) -> tuple[str, ...]:
        if zone not in self._authorities:
            response = self._recursive(zone, "NS")
            servers = {
                record.target.to_text(omit_final_dot=True)
                for rrset in response.answer
                if rrset.name == dns.name.from_text(zone) and rrset.rdtype == dns.rdatatype.NS
                for record in rrset
            }
            if not servers or len(servers) > MAX_NAMESERVERS:
                raise ProbeError("dns_authorities_unproven")
            self._authorities[zone] = tuple(sorted(servers))
        return self._authorities[zone]

    def _address(self, server: str) -> str:
        if server not in self._addresses:
            response = self._recursive(server, "A")
            addresses = [
                record.to_text()
                for rrset in response.answer
                if rrset.name == dns.name.from_text(server) and rrset.rdtype == dns.rdatatype.A
                for record in rrset
            ]
            if not addresses:
                response = self._recursive(server, "AAAA")
                addresses = [
                    record.to_text()
                    for rrset in response.answer
                    if rrset.name == dns.name.from_text(server) and rrset.rdtype == dns.rdatatype.AAAA
                    for record in rrset
                ]
            try:
                self._addresses[server] = next(public_address(address) for address in addresses)
            except (StopIteration, ValueError) as error:
                raise ProbeError("dns_authority_address_unsafe") from error
        return self._addresses[server]

    def query(self, name: str, kind: str, *, parent: bool = False) -> Records:
        self.budget.check()
        name = _name(name)
        key = (name, kind, parent)
        if key in self._cache:
            return self._cache[key]
        zone = self.zone(_parent(name) if parent else name)
        answers = [
            self._parse(self._ask(name, kind, self._address(server), recursive=False, zone=zone), name, kind, zone)
            for server in self._servers(zone)
        ]
        canonical = {
            (tuple(sorted(value.to_digestable() for value in answer.values)), answer.alias, answer.negative)
            for answer in answers
        }
        if len(canonical) != 1:
            raise ProbeError(
                "dns_authorities_disagree", evidence={"answers": [answer.evidence() for answer in answers]}
            )
        first = answers[0]
        result = Records(
            name, kind, zone, first.values, first.alias, first.negative, max(answer.ttl or 0 for answer in answers)
        )
        self._cache[key] = result
        return result

    @staticmethod
    def _parse(response: dns.message.Message, name: str, kind: str, zone: str) -> Records:
        owner = dns.name.from_text(name)
        owned = [rrset for rrset in response.answer if rrset.name == owner]
        if any(rrset.rdtype == dns.rdatatype.DNAME for rrset in response.answer):
            raise ProbeError("dns_dname_unsupported")
        aliases = [rrset for rrset in owned if rrset.rdtype == dns.rdatatype.CNAME]
        if aliases:
            if (
                len(aliases) != 1
                or len(aliases[0]) != 1
                or any(rrset.rdtype not in (dns.rdatatype.CNAME, dns.rdatatype.RRSIG) for rrset in owned)
            ):
                raise ProbeError("dns_cname_ambiguous")
            return Records(name, kind, zone, alias=_name(next(iter(aliases[0])).target.to_text()), ttl=aliases[0].ttl)
        positive = [rrset for rrset in owned if rrset.rdtype == dns.rdatatype.from_text(kind)]
        if positive and response.rcode() == dns.rcode.NOERROR:
            return Records(
                name,
                kind,
                zone,
                tuple(record for rrset in positive for record in rrset),
                ttl=max(rrset.ttl for rrset in positive),
            )
        negative = [
            rrset
            for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == dns.name.from_text(zone)
        ]
        if not negative or response.answer:
            raise ProbeError("dns_negative_unproven")
        return Records(
            name,
            kind,
            zone,
            negative="nxdomain" if response.rcode() == dns.rcode.NXDOMAIN else "nodata",
            ttl=max(rrset.ttl for rrset in negative),
        )


def _component(  # noqa: PLR0913  # Stable identity, outcome and private typed observation fields.
    state: ProbeState,
    code: str,
    name: str,
    kind: str,
    *,
    ttl: int | None = None,
    evidence: dict[str, Any] | None = None,
) -> ComponentObservation:
    private = evidence or {}
    if len(json.dumps(private)) > MAX_COMPONENT_EVIDENCE:
        private = {
            "truncated": True,
            "fields": sorted(private)[:MAX_EVIDENCE_RECORDS],
            "validation": private.get("validation"),
            "scope": private.get("scope"),
        }
    return {
        "state": state,
        "code": code,
        "name": name,
        "record_type": kind,
        "checked_at": datetime.now(UTC).isoformat(),
        "ttl": ttl,
        "evidence": private,
    }


def _follow(transport: DnsProbeTransport, name: str, kind: str) -> tuple[Records, list[str]]:
    visited: list[str] = []
    current = name
    for _hop in range(MAX_CNAME_HOPS + 1):
        if current in visited:
            raise ProbeError("cname_cycle", state="broken")
        visited.append(current)
        answer = transport.query(current, kind)
        if not answer.alias:
            return answer, visited
        current = answer.alias
    raise ProbeError("cname_hop_limit")


def _routing(transport: DnsProbeTransport, name: str, target: ProbeTarget) -> ComponentObservation:
    ipv4, aliases = _follow(transport, name, "A")
    ipv6, aliases6 = _follow(transport, name, "AAAA")
    if aliases != aliases6:
        raise ProbeError("dns_alias_families_disagree")
    evidence = {
        "a": ipv4.evidence(),
        "aaaa": ipv6.evidence(),
        "aliases": aliases,
        "expected_ipv4": target.ipv4,
        "expected_ipv6": target.ipv6,
    }
    ttl = max(ipv4.ttl or 0, ipv6.ttl or 0)
    addresses = {str(ipaddress.ip_address(record.to_text())) for record in ipv4.values}
    if not addresses:
        return _component("broken", "routing_missing", name, "A/AAAA", ttl=ttl, evidence=evidence)
    if addresses != {target.ipv4}:
        if target.ipv4 in addresses or target.account_hostname in aliases:
            return _component("broken", "routing_mixed_addresses", name, "A/AAAA", ttl=ttl, evidence=evidence)
        return _component("unknown", "external_origin_unverified", name, "A/AAAA", ttl=ttl, evidence=evidence)
    addresses6 = {str(ipaddress.ip_address(record.to_text())) for record in ipv6.values}
    if addresses6 and addresses6 != ({target.ipv6} if target.ipv6 else set()):
        return _component("broken", "stray_aaaa", name, "A/AAAA", ttl=ttl, evidence=evidence)
    return _component("healthy", "routing_reaches_account", name, "A/AAAA", ttl=ttl, evidence=evidence)


def _caa_records(transport: DnsProbeTransport, name: str) -> Records | None:
    # RFC 8659: chase aliases for CAA(X), then climb Parent(X), not Parent(alias).
    current = name
    while current:
        answer, _aliases = _follow(transport, current, "CAA")
        if answer.values:
            return answer
        current = _parent(current)
    return None


def _caa_policy(answer: Records | None, name: str) -> ComponentObservation:
    if answer is None:
        return _component("healthy", "caa_unrestricted", name, "CAA")
    evidence = answer.evidence()
    issues = []
    for raw_record in answer.values:
        record = cast(CAA, raw_record)
        tag = record.tag.decode("ascii").lower()
        if record.flags & 128 and tag not in {"issue", "issuewild", "iodef"}:
            return _component("broken", "caa_unknown_critical", name, "CAA", ttl=answer.ttl, evidence=evidence)
        if tag == "issue":
            issues.append(record.value)
    if not issues:
        return _component("healthy", "caa_unrestricted", name, "CAA", ttl=answer.ttl, evidence=evidence)
    uncertain = False
    for value in issues:
        parsed = parse_caa_issue(value)
        if parsed is not None and parsed[0] == "letsencrypt.org":
            if not parsed[1]:
                return _component("healthy", "caa_allows_letsencrypt", name, "CAA", ttl=answer.ttl, evidence=evidence)
            uncertain = True
    return _component(
        "unknown" if uncertain else "broken",
        "caa_parameters_unverified" if uncertain else "caa_excludes_letsencrypt",
        name,
        "CAA",
        ttl=answer.ttl,
        evidence=evidence,
    )


def _caa_for_name(transport: DnsProbeTransport, name: str) -> ComponentObservation:
    return _caa_policy(_caa_records(transport, name), name)


def _caa(transport: DnsProbeTransport, target: ProbeTarget) -> ComponentObservation:
    outcomes = [
        _safe_component(partial(_caa_for_name, transport, name), name)
        for name in (target.domain, f"www.{target.domain}")
    ]
    rank = {"broken": 3, "unknown": 2, "healthy": 1, "not_applicable": 0}
    result = max(outcomes, key=lambda outcome: rank[outcome["state"]])
    return _component(
        result["state"], result["code"], target.domain, "CAA", ttl=result["ttl"], evidence={"names": outcomes}
    )


def _mail(transport: DnsProbeTransport, target: ProbeTarget) -> ComponentObservation:
    answer, _aliases = _follow(transport, target.domain, "MX")
    records = [cast(MX, record) for record in answer.values]
    exchanges = {record.exchange.canonicalize().to_text(omit_final_dot=True) for record in records}
    null = [record for record in records if record.exchange == dns.name.root]
    evidence = answer.evidence()
    if null and (len(answer.values) != 1 or null[0].preference != 0):
        return _component("broken", "mixed_null_mx", target.domain, "MX", ttl=answer.ttl, evidence=evidence)
    if not target.hosted_mail:
        code = "null_mx" if null else "external_mail" if exchanges else "implicit_external_mail"
        return _component("not_applicable", code, target.domain, "MX", ttl=answer.ttl, evidence=evidence)
    if exchanges != {target.account_hostname}:
        return _component("broken", "hosted_mx_mismatch", target.domain, "MX", ttl=answer.ttl, evidence=evidence)
    address = transport.query(target.account_hostname, "A")
    address6 = transport.query(target.account_hostname, "AAAA")
    if address.alias or address6.alias:
        return _component("broken", "mx_target_is_alias", target.domain, "MX", evidence=evidence)
    addresses4 = {record.to_text() for record in address.values}
    addresses6 = {str(ipaddress.ip_address(record.to_text())) for record in address6.values}
    if addresses4 != {target.ipv4} or (addresses6 and addresses6 != ({target.ipv6} if target.ipv6 else set())):
        return _component("broken", "hosted_mx_address_mismatch", target.domain, "MX", evidence=evidence)
    return _component("healthy", "hosted_mx_reaches_account", target.domain, "MX", ttl=answer.ttl, evidence=evidence)


def _check_delegation(delegation: Records, evidence: dict[str, Any]) -> None:
    if delegation.alias:
        raise ProbeError("dnssec_delegation_alias")
    if delegation.negative == "nxdomain":
        raise ProbeError("dnssec_delegation_unproven", evidence=evidence)


def _dnssec(transport: DnsProbeTransport, target: ProbeTarget) -> ComponentObservation:
    zone = transport.zone(target.domain)
    delegation = transport.query(zone, "DS", parent=True)
    evidence = {
        "validation": "not_performed",
        "scope": "parent_ds_child_dnskey_consistency",
        "ds": delegation.evidence(),
    }
    _check_delegation(delegation, evidence)
    if not delegation.values:
        return _component("not_applicable", "dnssec_unsigned", zone, "DS/DNSKEY", ttl=delegation.ttl, evidence=evidence)
    keys = transport.query(zone, "DNSKEY")
    evidence["dnskey"] = keys.evidence()
    if keys.alias:
        raise ProbeError("dnssec_dnskey_alias")
    supported = False
    unknown = False
    for raw_ds in delegation.values:
        ds = cast(DS, raw_ds)
        if ds.digest_type not in (1, 2, 4):
            unknown = True
            continue
        for raw_key in keys.values:
            key = cast(DNSKEY, raw_key)
            if key.protocol != DNSSEC_PROTOCOL or not key.flags & DNSSEC_ZONE_FLAG or key.flags & DNSSEC_REVOKED_FLAG:
                continue
            if not dns.dnssec.default_policy.ok_to_validate(key):
                unknown = True
                continue
            try:
                get_algorithm_cls_from_dnskey(key)
                calculated = dns.dnssec.make_ds(f"{zone}.", key, ds.digest_type, validating=True)
            except (dns.exception.UnsupportedAlgorithm, dns.exception.DeniedByPolicy):
                unknown = True
                continue
            supported = True
            if calculated == ds:
                return _component(
                    "healthy", "dnssec_ds_key_consistent", zone, "DS/DNSKEY", ttl=delegation.ttl, evidence=evidence
                )
    if unknown or (keys.values and not supported):
        return _component("unknown", "dnssec_algorithm_unsupported", zone, "DS/DNSKEY", evidence=evidence)
    return _component("broken", "dnssec_ds_key_mismatch", zone, "DS/DNSKEY", ttl=delegation.ttl, evidence=evidence)


def _safe_component(probe: Callable[[], ComponentObservation], name: str) -> ComponentObservation:
    try:
        return probe()
    except ProbeError as error:
        return _component(error.state, error.code, name, "", evidence=error.evidence)
    except (dns.exception.DNSException, ValueError, UnicodeError, OSError):
        return _component("unknown", "dns_response_invalid", name, "")


def probe_hosted_domain_dns(
    target: ProbeTarget,
    *,
    transport: DnsProbeTransport | None = None,
    budget: ProbeBudget | None = None,
) -> ProbeReport:
    """Return private versioned JSON observations. Expected DNS failures become unknown, not exceptions."""
    names = {
        "apex": target.domain,
        "www": f"www.{target.domain}",
        "caa": target.domain,
        "dnssec": target.domain,
        "mx": target.domain,
    }
    try:
        target = ProbeTarget(
            _name(target.domain),
            _name(target.account_hostname),
            public_address(target.ipv4, 4),
            public_address(target.ipv6, 6) if target.ipv6 else None,
            target.hosted_mail,
        )
    except (ValueError, dns.exception.DNSException, ProbeError):
        return {
            "version": 1,
            "dns_path": "unknown",
            "components": {key: _component("unknown", "invalid_probe_target", name, "") for key, name in names.items()},
        }
    try:
        channel = transport or DnsProbeTransport(budget=budget)
    except (dns.exception.DNSException, ValueError, OSError):
        return {
            "version": 1,
            "dns_path": "unknown",
            "components": {
                key: _component("unknown", "dns_configuration_unavailable", name, "") for key, name in names.items()
            },
        }
    probes: dict[str, Callable[[], ComponentObservation]] = {
        "apex": lambda: _routing(channel, target.domain, target),
        "www": lambda: _routing(channel, f"www.{target.domain}", target),
        "caa": lambda: _caa(channel, target),
        "dnssec": lambda: _dnssec(channel, target),
        "mx": lambda: _mail(channel, target),
    }
    outcomes: dict[str, ComponentObservation] = {}
    for key, probe in probes.items():
        outcomes[key] = _safe_component(probe, names[key])
    www = outcomes["www"]
    aliases = www["evidence"].get("aliases", [])
    path = (
        "cname"
        if www["state"] == "healthy" and target.account_hostname in aliases
        else "direct"
        if outcomes["apex"]["state"] == "healthy"
        else "unknown"
    )
    return {"version": 1, "dns_path": path, "components": outcomes}
