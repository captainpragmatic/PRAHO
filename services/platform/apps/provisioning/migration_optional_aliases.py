"""Explicit staff declarations for independent Virtualmin webmail/admin aliases."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_agreement import ROUTING_MAX_CNAME_HOPS, ROUTING_MAX_NAMESERVERS

from .migration_routing import _date, _inventory, _ipv4, _known_source_addresses, _ttl

if TYPE_CHECKING:
    from .virtualmin_migration_models import MigrationBridge

CACHED_ROUTE_MAX_AGE = timedelta(minutes=15)
OPTIONAL_ALIAS_PREFIXES = ("webmail", "admin")


def optional_alias_names(bridge: MigrationBridge, names: list[str]) -> list[str]:
    """Only the two native optional customer aliases can have independent service semantics."""
    allowed = {f"{prefix}.{bridge.domain.lower().rstrip('.')}" for prefix in OPTIONAL_ALIAS_PREFIXES}
    return sorted(set(names) & allowed)


def _name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Missing authoritative routing name")
    return _inventory([value])[0]


def _hop(answers: list[Mapping[str, Any]], forbidden: set[str]) -> tuple[str, dict[str, list[str]]]:
    servers: dict[str, dict[str, tuple[str, tuple[str, ...]]]] = {}
    for answer in answers:
        if answer.get("error"):
            raise ValueError("Incomplete authoritative routing evidence")
        _ttl(answer.get("ttl"))
        server = _name(answer.get("nameserver"))
        family = answer.get("record_type")
        if family not in {"A", "AAAA"} or family in servers.setdefault(server, {}):
            raise ValueError("Missing or duplicate routing family")
        cname = _name(answer["cname"]) if answer.get("cname") else ""
        raw = answer.get("addresses")
        if not isinstance(raw, list | tuple):
            raise ValueError("Missing authoritative address evidence")
        parsed = [ipaddress.ip_address(address) for address in raw]
        if any(not address.is_global or address.version != (4 if family == "A" else 6) for address in parsed):
            raise ValueError("Independent services require public addresses of the correct family")
        addresses = tuple(sorted({str(address) for address in parsed}))
        if set(addresses) & forbidden or (cname and addresses):
            raise ValueError("Source or ambiguous routing cannot be declared independent")
        servers[server][family] = (cname, addresses)
    if (
        not servers
        or len(servers) > ROUTING_MAX_NAMESERVERS
        or any(set(values) != {"A", "AAAA"} for values in servers.values())
    ):
        raise ValueError("Every authority must answer both routing families")
    families: dict[str, tuple[str, tuple[str, ...]]] = {}
    for family in ("A", "AAAA"):
        values = {server[family] for server in servers.values()}
        if len(values) != 1:
            raise ValueError("Authoritative servers disagree on routing")
        families[family] = values.pop()
    if families["A"][0] != families["AAAA"][0]:
        raise ValueError("Mixed authoritative alias evidence")
    cname = families["A"][0]
    addresses_by_family = {family: list(values[1]) for family, values in families.items()}
    if not cname and not any(addresses_by_family.values()):
        raise ValueError("An independent service must have a complete destination")
    return cname, addresses_by_family


def _route(observation: Any, name: str, forbidden: set[str]) -> dict[str, Any]:
    """Canonical chain and terminal addresses; TTLs and nameserver addresses are cache metadata."""
    if not isinstance(observation, Mapping):
        raise ValueError("Authoritative routing evidence is missing")
    if not observation.get("agreed"):
        detail = observation.get("detail")
        if (
            not isinstance(detail, str)
            or not detail
            or not all(": answered " in part and ", expected " in part for part in detail.split("; "))
        ):
            raise ValueError("Only a completed authoritative address result can be declared independent")
    answers = observation.get("answers")
    if (
        not isinstance(answers, list | tuple)
        or not answers
        or len(answers) > 2 * ROUTING_MAX_NAMESERVERS * (ROUTING_MAX_CNAME_HOPS + 1)
    ):
        raise ValueError("Authoritative routing evidence is missing or exceeds the probe limit")
    hops: dict[str, list[Mapping[str, Any]]] = {}
    for answer in answers:
        if not isinstance(answer, Mapping):
            raise ValueError("Invalid authoritative routing evidence")
        hops.setdefault(_name(answer.get("queried_name")), []).append(answer)
    current = name
    chain: list[list[str]] = []
    visited: set[str] = set()
    for _index in range(ROUTING_MAX_CNAME_HOPS + 1):
        if current in visited or current not in hops:
            raise ValueError("Unfinished or cyclic independent-service routing")
        visited.add(current)
        cname, addresses = _hop(hops[current], forbidden)
        if not cname:
            if set(hops) != visited:
                raise ValueError("Unrelated or unfinished routing evidence")
            return {"chain": chain, "addresses": addresses}
        chain.append([current, cname])
        current = cname
    raise ValueError("Independent service routing exceeds the CNAME hop limit")


def _before(bridge: MigrationBridge, name: str) -> tuple[dict[str, Any], set[str]]:
    before = bridge.evidence.get("frontend_dns_before", {}).get(name, {})
    original_sources = before.get("source_addresses")
    observed_at = _date(before.get("checked_at"))
    committed = bridge.migration.cutover_committed_at
    if (
        not isinstance(original_sources, list)
        or not original_sources
        or observed_at is None
        or committed is None
        or observed_at > committed
    ):
        raise ValueError("Complete precommit independent-service evidence is required")
    forbidden = _known_source_addresses(bridge)
    return _route(before.get("observation"), name, forbidden), forbidden


def _same_service(before: dict[str, Any], current: dict[str, Any]) -> bool:
    # An external provider may rotate its terminal public pool while the explicit CNAME
    # delegation is unchanged. Direct address declarations have no such stable identity.
    return before["chain"] == current["chain"] if before["chain"] else before == current


def _bound(bridge: MigrationBridge, names: list[str], statement: Any, now: datetime) -> bool:
    if not isinstance(statement, dict):
        return False
    expires = _date(statement.get("expires_at"))
    return bool(
        expires is not None
        and expires > now
        and statement.get("kind") == "independent_service"
        and statement.get("actor")
        and statement.get("note")
        and statement.get("target_id") == str(bridge.target_server_id)
        and statement.get("ipv4") == _ipv4(bridge.target_server)
        and statement.get("ipv6") == (bridge.target_server.ipv6_address or "")
        and statement.get("names") == sorted(names)
    )


def declared_independent_names(bridge: MigrationBridge, names: list[str], now: datetime) -> list[str]:
    declarations = bridge.evidence.get("independent_services", {})
    if not isinstance(declarations, dict):
        return []
    return [name for name in optional_alias_names(bridge, names) if _bound(bridge, names, declarations.get(name), now)]


def independent_service_matches(
    bridge: MigrationBridge, names: list[str], name: str, observation: Any, now: datetime
) -> bool:
    """Every cleanup still requires this exact declared external route, with no source/error bypass."""
    if name not in declared_independent_names(bridge, names, now):
        return False
    statement = bridge.evidence["independent_services"][name]
    try:
        before, forbidden = _before(bridge, name)
        current = _route(observation, name, forbidden)
        return _same_service(before, current) and statement.get("routes", {}).get(name) == current
    except (KeyError, TypeError, ValueError):
        return False


def prepare_independent_statement(
    bridge: MigrationBridge, names: list[str], fields: Mapping[str, str], statement: dict[str, Any], now: datetime
) -> Result[dict[str, Any], str]:
    """Use worker-cached evidence only; no DNS or other remote work occurs on the staff request."""
    try:
        selected = _inventory(re.split(r"[,\s]+", fields.get("names", "").strip()))
        if not set(selected) <= set(optional_alias_names(bridge, names)):
            raise ValueError("Only inventoried webmail and admin aliases may be declared independent")
        routes = {}
        for name in selected:
            before, forbidden = _before(bridge, name)
            cached = bridge.evidence.get("routing", {}).get(name, {})
            checked = _date(cached.get("checked_at"))
            committed = bridge.migration.cutover_committed_at
            if (
                checked is None
                or committed is None
                or checked > now
                or now - checked > CACHED_ROUTE_MAX_AGE
                or checked < committed
            ):
                raise ValueError("A complete independent-service DNS observation from the last 15 minutes is required")
            current = _route(cached.get("observation"), name, forbidden)
            if not _same_service(before, current):
                raise ValueError("Independent-service routing no longer matches its precommit identity")
            routes[name] = current
    except (KeyError, TypeError, ValueError) as error:
        return Err(str(error))
    return Ok({**statement, "kind": "independent_service", "service_names": selected, "routes": routes})


def independent_statement_evidence(bridge: MigrationBridge, statement: dict[str, Any]) -> dict[str, Any]:
    """Narrow any prior origin claim and restart the cache clock for the newly verified route."""
    selected = statement["service_names"]
    declarations = dict(bridge.evidence.get("independent_services", {}))
    declarations.update(dict.fromkeys(selected, statement))
    routing = dict(bridge.evidence.get("routing", {}))
    for name in selected:
        routing[name] = {
            **routing[name],
            "agreed": False,
            "confirmed_at": None,
            "cache_until": None,
            "attested": False,
            "independent_service": False,
        }
    evidence = {**bridge.evidence, "independent_services": declarations, "routing": routing}
    origin = evidence.get("routing_attestation")
    if isinstance(origin, dict):
        covered = origin.get("covered_names", origin.get("names", []))
        if not isinstance(covered, list):
            covered = []
        evidence["routing_attestation"] = {
            **origin,
            "covered_names": [name for name in covered if name not in selected],
        }
    return evidence
