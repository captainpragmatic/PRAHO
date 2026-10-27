"""Conservative SPF lookup-budget analysis, never sender authorization or deliverability.

RFC7208 sections3.3,4.6.4,5,6: https://www.rfc-editor.org/rfc/rfc7208
All potentially reached mechanisms are summed, even if mutually exclusive for a
particular sender. A/AAAA void counts remain separate. DNS questions, aliases,
depth, bytes and elapsed time have independent hard caps. PTR and macros require
review; explanations/ignored modifiers are not validated as delivery policy.
Only the supplied top-level proposal is analysed; every external dependency is
observed in its CURRENT graph. No top-level discovery, writes or post-publication
readiness is established. A future publisher must compare all observed(name,type)
dependencies with ALL proposed/provider-managed DNS changes and refuse/re-analyse
any intersection before using this receipt. Unpublished answers are never invented.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT

from apps.common.types import Err, Ok, Result

MAX_TERMS = 10
MAX_VOID = 2
MAX_MX = 10
MAX_QUERIES = 64
MAX_SECONDS = 30.0
MAX_DEPTH = 10
MAX_ALIASES = 8
MAX_RECORDS = 128
MAX_RECORD_BYTES = 4096
MAX_ANSWER_BYTES = 65536
MAX_POLICY_BYTES = 4096
MAX_HOSTNAME_BYTES = 253
MAX_TTL = 2**31 - 1
MAX_IPV4_PREFIX = 32
MAX_IPV6_PREFIX = 128
MIN_PRINTABLE_ASCII = 32
MAX_PRINTABLE_ASCII = 127
MAX_RECEIPT_AGE = timedelta(minutes=5)
QUERY_TIMEOUT = 3.0
_DIGEST = re.compile(r"[a-f0-9]{64}")
_CIDR = re.compile(r"(?::(?P<domain>[^/]+))?(?:/(?P<v4>[0-9]{1,3}))?(?://(?P<v6>[0-9]{1,3}))?")
type RecordType = Literal["TXT", "A", "AAAA", "MX"]


class _SpfRefusalError(ValueError):
    """Only fixed codes cross the analysis boundary."""


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class SpfQuery:
    name: str
    record_type: RecordType
    timeout: float


@dataclass(frozen=True)
class SpfDnsRecord:
    name: str
    record_type: str
    ttl: int
    rdata: str


@dataclass(frozen=True)
class SpfDnsAnswer:
    name: str
    record_type: RecordType
    rcode: str
    records: tuple[SpfDnsRecord, ...]
    negative_ttl: int | None = None
    complete: bool = True


class SpfResolver(Protocol):
    """A server-owned transport must honor each question's remaining timeout."""

    def __call__(self, question: SpfQuery) -> SpfDnsAnswer: ...


@dataclass
class SpfBudget:
    seconds: float = MAX_SECONDS
    max_queries: int = MAX_QUERIES
    max_depth: int = MAX_DEPTH
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = _now
    queries: int = field(default=0, init=False)
    deadline: float = field(init=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.seconds, bool)
            or not math.isfinite(self.seconds)
            or self.seconds < 0
            or type(self.max_queries) is not int
            or self.max_queries < 0
            or type(self.max_depth) is not int
            or self.max_depth < 0
        ):
            raise ValueError("invalid SPF budget")
        self.max_queries = min(self.max_queries, MAX_QUERIES)
        self.max_depth = min(self.max_depth, MAX_DEPTH)
        self.deadline = self.clock() + min(self.seconds, MAX_SECONDS)

    def check(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise _SpfRefusalError("mail_spf_budget_exhausted")
        return min(remaining, QUERY_TIMEOUT)

    def dispatch(self) -> float:
        timeout = self.check()
        if self.queries >= self.max_queries:
            raise _SpfRefusalError("mail_spf_budget_exhausted")
        self.queries += 1
        return timeout


def _name(value: str) -> str:
    name = dns.name.from_text(value).canonicalize().to_text(omit_final_dot=True)
    if (
        len(name) > MAX_HOSTNAME_BYTES
        or "." not in name
        or any(not re.fullmatch(r"[a-z0-9_-]{1,63}", label) for label in name.split("."))
    ):
        raise _SpfRefusalError("mail_spf_policy_invalid")
    return name


@dataclass(frozen=True)
class TcpSpfResolver:
    """One recursive TCP question to an explicitly configured public IP; no retries/fallback.

    The wire ledger counts this application's questions, not a recursive server's
    internal traffic. SPF-derived names never become network destinations.
    """

    nameserver: str

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.nameserver)
        if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
            raise ValueError("SPF resolver must be a public IP")

    def __call__(self, question: SpfQuery) -> SpfDnsAnswer:
        if not math.isfinite(question.timeout) or not 0 < question.timeout <= QUERY_TIMEOUT:
            raise ValueError("invalid SPF question timeout")
        request = dns.message.make_query(question.name, question.record_type)
        response = dns.query.tcp(request, self.nameserver, timeout=question.timeout)
        records = tuple(
            SpfDnsRecord(
                rrset.name.to_text(omit_final_dot=True), dns.rdatatype.to_text(rrset.rdtype), rrset.ttl, row.to_text()
            )
            for rrset in response.answer
            for row in rrset
        )
        negative = [
            min(rrset.ttl, cast(SOA, row).minimum)
            for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.SOA and dns.name.from_text(question.name).is_subdomain(rrset.name)
            for row in rrset
        ]
        return SpfDnsAnswer(
            question.name,
            question.record_type,
            dns.rcode.to_text(response.rcode()),
            records,
            min(negative) if negative else None,
            complete=not bool(response.flags & dns.flags.TC),
        )


@dataclass(frozen=True)
class SpfDnsObservation:
    name: str
    record_type: RecordType
    digest: str
    positive_ttl: int | None
    negative_ttl: int | None


@dataclass(frozen=True)
class SpfSource:
    revision: int
    digest: str


@dataclass(frozen=True)
class SpfSafetyReceipt:
    domain: str
    proposal_sha256: str
    snapshot_revision: int
    snapshot_digest: str
    lookup_terms: int
    query_count: int
    void_ipv4: int
    void_ipv6: int
    checked_at: datetime
    valid_until: datetime
    observations: tuple[SpfDnsObservation, ...]
    dependencies: tuple[tuple[str, str], ...]
    scope: Literal["lookup_budget_upper_bound"] = "lookup_budget_upper_bound"


@dataclass(frozen=True)
class _Mechanism:
    kind: str
    target: str = ""


def _mechanism(term: str, domain: str) -> _Mechanism:
    body = term[1:] if term[:1] in {"+", "-", "~", "?"} else term
    match = re.fullmatch(r"([a-zA-Z0-9]+)(.*)", body)
    if match is None:
        raise _SpfRefusalError("mail_spf_policy_invalid")
    kind, suffix = match[1].lower(), match[2]
    if kind == "all" and not suffix:
        return _Mechanism(kind)
    if kind in {"ip4", "ip6"}:
        try:
            network = ipaddress.ip_network(suffix[1:], strict=False) if suffix.startswith(":") else None
        except ValueError as error:
            raise _SpfRefusalError("mail_spf_policy_invalid") from error
        if network is None or network.version != (4 if kind == "ip4" else 6):
            raise _SpfRefusalError("mail_spf_policy_invalid")
        return _Mechanism(kind)
    if kind in {"a", "mx"}:
        parsed = _CIDR.fullmatch(suffix)
        if (
            parsed is None
            or (parsed["v4"] and int(parsed["v4"]) > MAX_IPV4_PREFIX)
            or (parsed["v6"] and int(parsed["v6"]) > MAX_IPV6_PREFIX)
        ):
            raise _SpfRefusalError("mail_spf_policy_invalid")
        return _Mechanism(kind, _name(parsed["domain"]) if parsed["domain"] else domain)
    if kind in {"include", "exists"} and suffix.startswith(":"):
        return _Mechanism(kind, _name(suffix[1:]))
    raise _SpfRefusalError("mail_spf_policy_unsupported")


def _policy(value: str, domain: str) -> tuple[tuple[_Mechanism, ...], str]:
    if not isinstance(value, str) or len(value) > MAX_POLICY_BYTES or re.match(r"^v=spf1(?: |$)", value, re.I) is None:
        raise _SpfRefusalError("mail_spf_policy_invalid")
    if "%" in value:
        raise _SpfRefusalError("mail_spf_policy_unsupported")
    if any(not MIN_PRINTABLE_ASCII <= ord(char) < MAX_PRINTABLE_ASCII for char in value):
        raise _SpfRefusalError("mail_spf_policy_invalid")
    mechanisms, modifiers = [], {}
    terminal = False
    for term in filter(None, value.split(" ")[1:]):
        if "=" in term:
            key, _, target = term.partition("=")
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]*", key) is None:
                raise _SpfRefusalError("mail_spf_policy_invalid")
            if key.lower() in {"redirect", "exp"}:
                if key.lower() in modifiers:
                    raise _SpfRefusalError("mail_spf_policy_invalid")
                modifiers[key.lower()] = _name(target)
        else:
            mechanism = _mechanism(term, domain)
            if not terminal:
                mechanisms.append(mechanism)
            terminal = terminal or mechanism.kind == "all"
    return tuple(mechanisms), "" if terminal else modifiers.get("redirect", "")


@dataclass
class _Analysis:
    resolver: SpfResolver
    budget: SpfBudget
    terms: int = 0
    voids: list[int] = field(default_factory=lambda: [0, 0])
    cache: dict[tuple[str, RecordType], tuple[dns.rdata.Rdata, ...]] = field(default_factory=dict)
    observations: list[SpfDnsObservation] = field(default_factory=list)
    dependencies: set[tuple[str, str]] = field(default_factory=set)
    valid_until: datetime = field(init=False)

    def __post_init__(self) -> None:
        self.valid_until = self.budget.now() + MAX_RECEIPT_AGE

    def check(self) -> None:
        self.budget.check()
        if self.budget.now() >= self.valid_until:
            raise _SpfRefusalError("mail_spf_dns_lifetime_unknown")

    def lifetime(self, ttl: int | None) -> int:
        if type(ttl) is not int or not 0 < ttl <= MAX_TTL:
            raise _SpfRefusalError("mail_spf_dns_lifetime_unknown")
        self.valid_until = min(self.valid_until, self.budget.now() + timedelta(seconds=ttl))
        return ttl

    def ask(self, name: str, kind: RecordType) -> tuple[SpfDnsAnswer, tuple[tuple[str, dns.rdata.Rdata], ...]]:
        self.check()
        question = SpfQuery(name, kind, self.budget.dispatch())
        answer = self.resolver(question)
        self.check()
        rows = self.parse_answer(question, answer)
        self.dependencies.add((name, kind))
        for owner, row in rows:
            self.dependencies.add((owner, dns.rdatatype.to_text(row.rdtype)))
            if row.rdtype == dns.rdatatype.CNAME:
                self.dependencies.add((_name(cast(CNAME, row).target.to_text()), kind))
        positive_ttl = min(row.ttl for row in answer.records) if answer.records else None
        self.lifetime(positive_ttl if positive_ttl is not None else answer.negative_ttl)
        payload = [(row.name, row.record_type, row.ttl, row.rdata) for row in answer.records]
        digest = hashlib.sha256(json.dumps([answer.rcode, payload, answer.negative_ttl]).encode()).hexdigest()
        self.observations.append(SpfDnsObservation(name, kind, digest, positive_ttl, answer.negative_ttl))
        return answer, rows

    @staticmethod
    def parse_answer(question: SpfQuery, answer: SpfDnsAnswer) -> tuple[tuple[str, dns.rdata.Rdata], ...]:
        if (
            not isinstance(answer, SpfDnsAnswer)
            or (answer.name, answer.record_type) != (question.name, question.record_type)
            or answer.complete is not True
            or answer.rcode not in {"NOERROR", "NXDOMAIN"}
            or not isinstance(answer.records, tuple)
            or len(answer.records) > MAX_RECORDS
            or (
                answer.negative_ttl is not None
                and (type(answer.negative_ttl) is not int or not 0 <= answer.negative_ttl <= MAX_TTL)
            )
        ):
            raise _SpfRefusalError("mail_spf_dns_unknown")
        rows, size = [], 0
        for row in answer.records:
            if (
                not isinstance(row, SpfDnsRecord)
                or not isinstance(row.name, str)
                or row.record_type not in {question.record_type, "CNAME"}
                or type(row.ttl) is not int
                or not 0 <= row.ttl <= MAX_TTL
                or not isinstance(row.rdata, str)
                or len(row.rdata.encode()) > MAX_RECORD_BYTES
            ):
                raise _SpfRefusalError("mail_spf_dns_unknown")
            size += len(row.rdata.encode())
            rows.append((_name(row.name), dns.rdata.from_text(dns.rdataclass.IN, row.record_type, row.rdata)))
        if size > MAX_ANSWER_BYTES:
            raise _SpfRefusalError("mail_spf_dns_unknown")
        return tuple(rows)

    def resolve(self, name: str, kind: RecordType) -> tuple[dns.rdata.Rdata, ...]:
        self.check()
        if (name, kind) in self.cache:
            return self.cache[name, kind]
        current = name
        seen: set[str] = set()
        answer, rows = self.ask(current, kind)
        while True:
            if current in seen or len(seen) > MAX_ALIASES:
                raise _SpfRefusalError("mail_spf_alias_limit")
            seen.add(current)
            data = tuple(row for owner, row in rows if owner == current and row.rdtype == dns.rdatatype.from_text(kind))
            aliases = tuple(
                cast(CNAME, row) for owner, row in rows if owner == current and row.rdtype == dns.rdatatype.CNAME
            )
            if len(aliases) > 1 or (aliases and data) or (answer.rcode == "NXDOMAIN" and data):
                raise _SpfRefusalError("mail_spf_dns_unknown")
            if data:
                if any(owner not in seen for owner, _row in rows):
                    raise _SpfRefusalError("mail_spf_dns_unknown")
                self.cache[name, kind] = data
                return data
            if not aliases or answer.rcode == "NXDOMAIN":
                if any(owner not in seen for owner, _row in rows):
                    raise _SpfRefusalError("mail_spf_dns_unknown")
                self.lifetime(answer.negative_ttl)
                self.cache[name, kind] = ()
                return ()
            current = _name(aliases[0].target.to_text())
            if current in seen or len(seen) > MAX_ALIASES:
                raise _SpfRefusalError("mail_spf_alias_limit")
            if not any(owner == current for owner, _row in rows):
                answer, rows = self.ask(current, kind)

    def void(self, family: int | None = None) -> None:
        for index in range(2) if family is None else (family,):
            self.voids[index] += 1
            if self.voids[index] > MAX_VOID:
                raise _SpfRefusalError("mail_spf_void_limit")

    def addresses(self, name: str, *, mx: bool = False) -> None:
        kinds: tuple[RecordType, ...] = ("A", "AAAA")
        for family, kind in enumerate(kinds):
            records = self.resolve(name, kind)
            if mx and len(records) > MAX_MX:
                raise _SpfRefusalError("mail_spf_mx_limit")
            if not records:
                self.void(family)

    def mx(self, name: str) -> None:
        records = self.resolve(name, "MX")
        if len(records) > MAX_MX:
            raise _SpfRefusalError("mail_spf_mx_limit")
        if not records:
            self.void()
        for record in records:
            self.addresses(_name(cast(MX, record).exchange.to_text()), mx=True)

    def recurse(self, target: str, stack: tuple[str, ...]) -> None:
        if target in stack:
            raise _SpfRefusalError("mail_spf_cycle")
        if len(stack) > self.budget.max_depth:
            raise _SpfRefusalError("mail_spf_depth_limit")
        records = [b"".join(cast(TXT, row).strings) for row in self.resolve(target, "TXT")]
        selected = [row for row in records if re.match(rb"^v=spf1(?: |$)", row, re.I)]
        if not selected:
            raise _SpfRefusalError("mail_spf_record_missing")
        if len(selected) != 1:
            raise _SpfRefusalError("mail_spf_multiple_records")
        self.walk(target, selected[0].decode("ascii"), (*stack, target))

    def lookup(self) -> None:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise _SpfRefusalError("mail_spf_lookup_limit")

    def walk(self, domain: str, policy: str, stack: tuple[str, ...]) -> None:
        self.check()
        mechanisms, redirect = _policy(policy, domain)
        for mechanism in mechanisms:
            if mechanism.kind in {"all", "ip4", "ip6"}:
                continue
            self.lookup()
            if mechanism.kind == "include":
                self.recurse(mechanism.target, stack)
            elif mechanism.kind == "a":
                self.addresses(mechanism.target)
            elif mechanism.kind == "mx":
                self.mx(mechanism.target)
            elif not self.resolve(mechanism.target, "A"):
                self.void()  # literal exists always queries A, for both sender families.
        if redirect:
            self.lookup()
            self.recurse(redirect, stack)


def _binding(domain: str, proposed_txt: str, revision: int, digest: str) -> tuple[str, str]:
    domain = _name(domain)
    if type(revision) is not int or revision < 1 or not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise _SpfRefusalError("mail_spf_binding_stale")
    _policy(proposed_txt, domain)
    return domain, hashlib.sha256(proposed_txt.encode("ascii")).hexdigest()


def analyse_spf_proposal(
    domain: str,
    proposed_txt: str,
    *,
    source: SpfSource,
    resolver: SpfResolver,
    budget: SpfBudget | None = None,
) -> Result[SpfSafetyReceipt, str]:
    """Observe a conservative lookup upper bound, retaining exact source/proposal binding.

    No-DNS policies need no DNS lifetime; their deterministic local analysis still
    has a five-minute maximum receipt age. Any DNS dependency must prove a positive
    TTL or an actual negative SOA lifetime. This is not a complete SPF evaluator.
    """
    try:
        domain, proposal_digest = _binding(domain, proposed_txt, source.revision, source.digest)
        analysis = _Analysis(resolver, budget or SpfBudget())
        analysis.walk(domain, proposed_txt, (domain,))
        analysis.check()
        return Ok(
            SpfSafetyReceipt(
                domain,
                proposal_digest,
                source.revision,
                source.digest,
                analysis.terms,
                analysis.budget.queries,
                analysis.voids[0],
                analysis.voids[1],
                analysis.budget.now(),
                analysis.valid_until,
                tuple(analysis.observations),
                tuple(sorted(analysis.dependencies)),
            )
        )
    except _SpfRefusalError as error:
        return Err(str(error))
    except (dns.exception.DNSException, OSError, ValueError, TypeError, UnicodeError):
        return Err("mail_spf_dns_unknown")


def check_spf_receipt(
    receipt: SpfSafetyReceipt,
    *,
    domain: str,
    proposed_txt: str,
    source: SpfSource,
    now: datetime | None = None,
) -> Result[None, str]:
    """Check exact binding/age; this does not approve the graph after DNS changes.

    Before a first write, the future publisher must also refuse/re-analyse any
    intersection of receipt.dependencies with ALL proposed or
    provider-managed changes. Only trusted server-built receipts are accepted.
    """
    try:
        binding = _binding(domain, proposed_txt, source.revision, source.digest)
        current = now or _now()
        if (
            binding != (receipt.domain, receipt.proposal_sha256)
            or (source.revision, source.digest) != (receipt.snapshot_revision, receipt.snapshot_digest)
            or receipt.scope != "lookup_budget_upper_bound"
            or current.tzinfo is None
            or not receipt.checked_at <= current < receipt.valid_until
        ):
            return Err("mail_spf_binding_stale")
        return Ok(None)
    except (ValueError, TypeError, dns.exception.DNSException):
        return Err("mail_spf_binding_stale")
