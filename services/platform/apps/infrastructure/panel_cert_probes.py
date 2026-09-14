"""Read-only public DNS and HTTP observations for the panel-certificate drill."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import requests

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request

PROBE_TIMEOUT = 10
HTTP_PROBE_PATH = "/.well-known/acme-challenge/praho-preflight"


@dataclass(frozen=True)
class AuthoritativeAnswer:
    """One nameserver's answer; an error must never be interpreted as NODATA."""

    nameserver: str
    record_type: str
    addresses: tuple[str, ...] = ()
    server_address: str = ""
    error: str = ""


def public_address(value: str, version: int | None = None) -> str:
    """Normalize an Internet address and refuse private or special destinations."""
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or (version is not None and address.version != version):
        raise ValueError("A public address of the expected family is required")
    return str(address)


def _nameserver_address(resolver: dns.resolver.Resolver, nameserver: str) -> str:
    # One reachable transport per authoritative server is sufficient to ask BOTH
    # A and AAAA questions. A controller without IPv6 can still inspect AAAA data.
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(nameserver, record_type, lifetime=PROBE_TIMEOUT, search=False)
        except dns.resolver.NoAnswer:
            continue
        for record in answer:
            try:
                return public_address(record.to_text())
            except ValueError:
                continue
    raise ValueError("No public nameserver address")


def _query_authority(fqdn: str, nameserver: str, address: str, record_type: str) -> AuthoritativeAnswer:
    query = dns.message.make_query(fqdn, record_type)
    query.flags &= ~dns.flags.RD
    try:
        # TCP avoids retrying a truncated UDP answer. No application retry loop.
        response = dns.query.tcp(query, address, timeout=PROBE_TIMEOUT)
    except (dns.exception.DNSException, OSError):
        return AuthoritativeAnswer(
            nameserver, record_type, server_address=address, error="DNS query failed or timed out"
        )
    if not response.flags & dns.flags.AA:
        return AuthoritativeAnswer(
            nameserver, record_type, server_address=address, error="No authoritative answer; check delegation"
        )
    if response.rcode() != dns.rcode.NOERROR:
        return AuthoritativeAnswer(
            nameserver,
            record_type,
            server_address=address,
            error=f"Authority returned {dns.rcode.to_text(response.rcode())}; check node records and delegation",
        )
    if any(rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME) for rrset in response.answer):
        return AuthoritativeAnswer(
            nameserver,
            record_type,
            server_address=address,
            error="Alias found; the node requires direct A/AAAA records",
        )
    addresses = tuple(
        sorted(
            {
                record.to_text()
                for rrset in response.answer
                if rrset.name == query.question[0].name and rrset.rdtype == dns.rdatatype.from_text(record_type)
                for record in rrset
            }
        )
    )
    if not addresses and not any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority):
        return AuthoritativeAnswer(
            nameserver, record_type, server_address=address, error="Empty answer lacks authoritative negative evidence"
        )
    return AuthoritativeAnswer(nameserver, record_type, addresses, address)


def authoritative_addresses(fqdn: str) -> list[AuthoritativeAnswer]:
    """Discover the closest zone, then query each NS directly, bypassing cached A/AAAA."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = PROBE_TIMEOUT
        resolver.lifetime = PROBE_TIMEOUT
        resolver.retry_servfail = False
        zone = dns.resolver.zone_for_name(dns.name.from_text(fqdn), resolver=resolver, lifetime=PROBE_TIMEOUT)
        if not dns.name.from_text(fqdn).is_subdomain(zone) or zone == dns.name.root:
            raise ValueError("No containing zone")
        nameservers = sorted(
            record.to_text() for record in resolver.resolve(zone, "NS", lifetime=PROBE_TIMEOUT, search=False)
        )
        if not nameservers:
            raise ValueError("No authoritative nameservers")
    except (dns.exception.DNSException, OSError, ValueError):
        return [
            AuthoritativeAnswer("discovery", "NS", error="Cannot discover authoritative nameservers; check DNS access")
        ]

    answers: list[AuthoritativeAnswer] = []
    for nameserver in nameservers:
        try:
            address = _nameserver_address(resolver, nameserver)
        except (dns.exception.DNSException, OSError, ValueError):
            answers.append(AuthoritativeAnswer(nameserver, "NS", error="Cannot resolve a public nameserver address"))
            continue
        answers.extend(_query_authority(fqdn, nameserver, address, record_type) for record_type in ("A", "AAAA"))
    return answers


def observe_http(fqdn: str, address: str) -> int | None:
    """Observe the first HTTP response, without following redirects or reading bodies.

    This path contains no real ACME nonce. Even 200 cannot prove HTTP-01 readiness.
    The explicit Host header exercises hostname routing at each published address.
    """
    address = public_address(address)
    host = f"[{address}]" if ":" in address else address
    policy = OutboundPolicy(
        name="panel_cert_preflight_http",
        require_https=False,
        allowed_schemes=frozenset({"http"}),
        allowed_ports=frozenset({80}),
        allowed_domains=frozenset({address}),
        timeout_seconds=PROBE_TIMEOUT,
        connect_timeout_seconds=PROBE_TIMEOUT,
        max_retries=0,
        retry_connection_errors=False,
    )
    try:
        with safe_request(
            "GET", f"http://{host}{HTTP_PROBE_PATH}", policy=policy, headers={"Host": fqdn}, stream=True
        ) as response:
            return response.status_code
    except (requests.RequestException, OutboundSecurityError):
        return None
