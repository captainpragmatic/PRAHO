"""Whether every authoritative server answers a name with exactly the expected addresses (ADR-0061 P2.10).

The cutover moves an account name to a new node only once DNS says so everywhere: each authoritative
server must answer A, and AAAA when the node has one, with exactly the node's addresses. A failed
query is never agreement. It is retried a bounded number of times, and an answer still missing or
different after the last attempt is a disagreement the caller reports.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from apps.infrastructure.panel_cert_probes import AuthoritativeAnswer, authoritative_addresses, public_address

AGREEMENT_ATTEMPTS = 3
AGREEMENT_PAUSE_SECONDS = 5.0
ROUTING_MAX_CNAME_HOPS = 8
ROUTING_MAX_NAMESERVERS = 8
ROUTING_TIMEOUT_SECONDS = 60.0
ROUTING_QUERY_TIMEOUT = 3.0
_ROUTING_MIN_LABELS = 3  # Host, public suffix, and the root label.


@dataclass(frozen=True)
class Agreement:
    """The outcome of the probe: `ttl` is the highest TTL any server answered, for the caller's wait."""

    agreed: bool
    ttl: int | None = None
    detail: str = ""
    answers: tuple[AuthoritativeAnswer, ...] = field(default=())


@dataclass(frozen=True)
class RoutingAnswer(AuthoritativeAnswer):
    """One customer-name A/AAAA question, with its authoritative CNAME when aliased."""

    cname: str = ""
    queried_name: str = ""


def _routing_name(value: str) -> str:
    parsed = dns.name.from_text(value).canonicalize()
    if len(parsed.labels) < _ROUTING_MIN_LABELS or any(label == b"*" for label in parsed.labels):
        raise ValueError("A concrete public routing name is required")
    return parsed.to_text(omit_final_dot=True)


def _routing_remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("Customer routing probe deadline exceeded")
    return min(ROUTING_QUERY_TIMEOUT, remaining)


def _routing_query(  # noqa: PLR0911  # Every unproven DNS response has an explicit refusal
    fqdn: str, nameserver: str, address: str, record_type: str, deadline: float
) -> RoutingAnswer:
    """Read one authority, preserving aliases instead of changing the panel's direct-address policy."""
    answer = RoutingAnswer(nameserver, record_type, server_address=address, queried_name=fqdn)
    query = dns.message.make_query(fqdn, record_type)
    query.flags &= ~dns.flags.RD
    try:
        response = dns.query.tcp(query, address, timeout=_routing_remaining(deadline))
    except (dns.exception.DNSException, OSError, ValueError) as error:
        return replace(answer, error=f"DNS query failed: {error}")
    if not response.flags & dns.flags.AA or response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return replace(answer, error="Missing successful authoritative answer")
    negative = [
        rrset
        for rrset in response.authority
        if rrset.rdtype == dns.rdatatype.SOA and query.question[0].name.is_subdomain(rrset.name)
    ]
    if response.rcode() == dns.rcode.NXDOMAIN:
        if response.answer or not negative:
            return replace(answer, error="Unproven authoritative absence")
        return replace(answer, ttl=max(rrset.ttl for rrset in negative))
    if any(rrset.rdtype == dns.rdatatype.DNAME for rrset in response.answer):
        return replace(answer, error="DNAME routing cannot be proven")
    owned = [rrset for rrset in response.answer if rrset.name == query.question[0].name]
    aliases = [rrset for rrset in owned if rrset.rdtype == dns.rdatatype.CNAME]
    if aliases:
        if (
            len(aliases) != 1
            or len(aliases[0]) != 1
            or any(rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) for rrset in owned)
        ):
            return replace(answer, error="Mixed or ambiguous CNAME routing")
        try:
            target = _routing_name(next(iter(aliases[0])).target.to_text())
        except (ValueError, dns.exception.DNSException):
            return replace(answer, error="Invalid CNAME target")
        return replace(answer, cname=target, ttl=aliases[0].ttl)
    records = [rrset for rrset in owned if rrset.rdtype == dns.rdatatype.from_text(record_type)]
    addresses = tuple(sorted({record.to_text() for rrset in records for record in rrset}))
    if not addresses and not negative:
        return replace(answer, error="Missing authoritative negative evidence")
    return replace(answer, addresses=addresses, ttl=max((rrset.ttl for rrset in records or negative), default=None))


def _routing_addresses(fqdn: str, deadline: float) -> list[RoutingAnswer]:
    """Discover the closest zone for this hop and ask every bounded authority both families."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = _routing_remaining(deadline)
        resolver.retry_servfail = False
        name = dns.name.from_text(fqdn)
        zone = dns.resolver.zone_for_name(name, resolver=resolver, lifetime=_routing_remaining(deadline))
        if zone == dns.name.root or not name.is_subdomain(zone):
            raise ValueError("No containing authoritative zone")
        servers = sorted(
            {
                record.to_text()
                for record in resolver.resolve(zone, "NS", lifetime=_routing_remaining(deadline), search=False)
            }
        )
        if not servers or len(servers) > ROUTING_MAX_NAMESERVERS:
            raise ValueError("Authoritative nameserver count exceeds the routing probe limit")
    except (dns.exception.DNSException, OSError, ValueError) as error:
        return [RoutingAnswer("discovery", "NS", error=str(error), queried_name=fqdn)]
    answers: list[RoutingAnswer] = []
    for server in servers:
        try:
            address = ""
            for family in ("A", "AAAA"):
                try:
                    resolved = resolver.resolve(server, family, lifetime=_routing_remaining(deadline), search=False)
                except dns.resolver.NoAnswer:
                    continue
                for record in resolved:
                    try:
                        address = public_address(record.to_text())
                        break
                    except ValueError:
                        continue
                if address:
                    break
            if not address:
                raise ValueError("The authoritative nameserver has no public address")
        except (dns.exception.DNSException, OSError, ValueError) as error:
            answers.append(RoutingAnswer(server, "NS", error=str(error), queried_name=fqdn))
            continue
        answers.extend(_routing_query(fqdn, server, address, family, deadline) for family in ("A", "AAAA"))
    return answers


def _routing_hop(
    answers: list[RoutingAnswer], ipv4: str, ipv6: str | None, *, allow_absent: bool
) -> tuple[str, list[str]]:
    servers = {answer.nameserver for answer in answers}
    problems = (
        [f"{answer.nameserver} {answer.record_type}: {answer.error}" for answer in answers if answer.error]
        if answers
        else ["No authoritative routing answers"]
    )
    for server in servers:
        questions = [answer.record_type for answer in answers if answer.nameserver == server]
        if sorted(questions) != ["A", "AAAA"]:
            problems.append(f"{server}: missing or duplicate A/AAAA evidence")
    if problems:
        return "", problems
    aliased = [answer for answer in answers if answer.cname]
    if aliased:
        if len(aliased) != len(answers) or any(answer.addresses for answer in aliased):
            return "", ["Authoritative servers disagree on direct versus CNAME routing"]
        targets = {_routing_name(answer.cname) for answer in aliased}
        if len(targets) != 1:
            return "", ["Authoritative servers disagree on the CNAME target"]
        return targets.pop(), []
    # A customer may publish IPv4 only, even on a dual-stack target. A published AAAA must
    # agree everywhere and reach this target; its proven absence is also a valid routing path.
    ipv6_answers = {_normalised(answer.addresses) for answer in answers if answer.record_type == "AAAA"}
    if len(ipv6_answers) != 1:
        return "", ["Authoritative servers disagree on AAAA routing"]
    expected = {
        "A": frozenset() if allow_absent and not any(answer.addresses for answer in answers) else _normalised((ipv4,)),
        "AAAA": _normalised((ipv6,)) if ipv6 and next(iter(ipv6_answers)) else frozenset(),
    }
    return "", _disagreements(list(answers), expected)


def routing_agreement(  # noqa: PLR0913  # Target, absence policy, and deterministic external-probe injection
    fqdn: str,
    ipv4: str,
    ipv6: str | None,
    *,
    query: Callable[[str], list[RoutingAnswer]] | None = None,
    pause: float = AGREEMENT_PAUSE_SECONDS,
    allow_absent: bool = False,
) -> Agreement:
    """Prove customer routing through consistent authoritative CNAME hops or direct target addresses.

    Each hop discovers its own zone; recursive cached answers never stand in for authoritative
    proof. Opaque proxy addresses, missing families, mixed aliases and cycles keep the bridge up.
    Optional unused frontends may allow proven A and AAAA absence on every authority.
    """
    deadline = time.monotonic() + ROUTING_TIMEOUT_SECONDS
    try:
        name = _routing_name(fqdn)
        ipv4 = public_address(ipv4, 4)
        ipv6 = public_address(ipv6, 6) if ipv6 else None
    except (ValueError, dns.exception.DNSException) as error:
        return Agreement(False, detail=str(error))
    lookup = query if query is not None else lambda candidate: _routing_addresses(candidate, deadline)
    detail = ""
    observed_ttl: int | None = None
    observations: list[AuthoritativeAnswer] = []
    for attempt in range(AGREEMENT_ATTEMPTS):
        observations = []
        try:
            if attempt and pause:
                time.sleep(min(pause, max(0.0, deadline - time.monotonic())))
            current = name
            visited: set[str] = set()
            for _hop in range(ROUTING_MAX_CNAME_HOPS + 1):
                _routing_remaining(deadline)
                if current in visited:
                    raise ValueError("CNAME routing cycle detected")
                visited.add(current)
                answers = lookup(current)
                observations.extend(answers)
                ttls = [answer.ttl for answer in answers if answer.ttl is not None]
                if ttls:
                    observed_ttl = max([observed_ttl, *ttls] if observed_ttl is not None else ttls)
                _routing_remaining(deadline)
                target, problems = _routing_hop(answers, ipv4, ipv6, allow_absent=allow_absent)
                if problems:
                    raise ValueError("; ".join(problems))
                if not target:
                    detail = "Authoritatively absent" if not any(answer.addresses for answer in answers) else ""
                    return Agreement(True, observed_ttl, detail, tuple(observations))
                current = target
            raise ValueError("CNAME routing hop limit exceeded")
        except (ValueError, dns.exception.DNSException, OSError) as error:
            detail = str(error)
            if time.monotonic() >= deadline:
                break
    return Agreement(False, observed_ttl, detail, tuple(observations))


def _normalised(addresses: tuple[str, ...]) -> frozenset[str]:
    try:
        return frozenset(str(ipaddress.ip_address(address)) for address in addresses)
    except ValueError:
        return frozenset({"<unparseable>"})


def _disagreements(answers: list[AuthoritativeAnswer], expected: dict[str, frozenset[str]]) -> list[str]:
    if not answers:
        return ["no authoritative answers"]
    problems = [f"{answer.nameserver} {answer.record_type}: {answer.error}" for answer in answers if answer.error]
    seen: dict[str, set[str]] = {}
    for answer in answers:
        if answer.error:
            continue
        seen.setdefault(answer.record_type, set()).add(answer.nameserver)
        want = expected.get(answer.record_type, frozenset())
        got = _normalised(answer.addresses)
        if got != want:
            problems.append(
                f"{answer.nameserver} {answer.record_type}: answered {sorted(got)}, expected {sorted(want)}"
            )
    servers = {answer.nameserver for answer in answers if not answer.error}
    problems.extend(
        f"{record_type}: not every server answered"
        for record_type in expected
        if seen.get(record_type, set()) != servers
    )
    return problems


def authoritative_agreement(
    fqdn: str,
    ipv4: str,
    ipv6: str | None,
    *,
    pause: float = AGREEMENT_PAUSE_SECONDS,
    query: Callable[[str], list[AuthoritativeAnswer]] = authoritative_addresses,
) -> Agreement:
    """Ask every authoritative server; agree only if all of them answer exactly `ipv4` and `ipv6`."""
    expected = {
        "A": _normalised((ipv4,)),
        "AAAA": _normalised((ipv6,)) if ipv6 else frozenset(),
    }
    detail = ""
    answers: list[AuthoritativeAnswer] = []
    for attempt in range(AGREEMENT_ATTEMPTS):
        if attempt and pause:
            time.sleep(pause)
        answers = query(fqdn)
        problems = _disagreements(answers, expected)
        if not problems:
            ttl = max((answer.ttl for answer in answers if answer.ttl is not None), default=None)
            return Agreement(True, ttl, "", tuple(answers))
        detail = "; ".join(problems)
    return Agreement(False, None, detail, tuple(answers))


def record_progress(agreement: Agreement, ipv4: str, ipv6: str | None) -> dict[str, dict[str, object]]:
    """Persist independent A/AAAA observations, including authoritative negative AAAA evidence."""
    expected = {"A": _normalised((ipv4,)), "AAAA": _normalised((ipv6,)) if ipv6 else frozenset()}
    servers = {answer.nameserver for answer in agreement.answers}
    result: dict[str, dict[str, object]] = {}
    for family, addresses in expected.items():
        answers = [answer for answer in agreement.answers if answer.record_type == family]
        agreed = (
            bool(servers)
            and {answer.nameserver for answer in answers} == servers
            and all(not answer.error and _normalised(answer.addresses) == addresses for answer in answers)
        )
        result[family] = {"agreed": agreed, "answers": [asdict(answer) for answer in answers]}
    return result
