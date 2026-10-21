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
from dataclasses import dataclass, field

from apps.infrastructure.panel_cert_probes import AuthoritativeAnswer, authoritative_addresses

AGREEMENT_ATTEMPTS = 3
AGREEMENT_PAUSE_SECONDS = 5.0


@dataclass(frozen=True)
class Agreement:
    """The outcome of the probe: `ttl` is the highest TTL any server answered, for the caller's wait."""

    agreed: bool
    ttl: int | None = None
    detail: str = ""
    answers: tuple[AuthoritativeAnswer, ...] = field(default=())


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
    for record_type, want in expected.items():
        if want and seen.get(record_type, set()) != servers:
            problems.append(f"{record_type}: not every server answered")
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
