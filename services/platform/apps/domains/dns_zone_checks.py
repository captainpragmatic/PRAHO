"""Checkpointed old-zone, assigned-authority and parent-delegation observations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from typing import Any

import dns.exception
import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype

from apps.infrastructure.dns_probes import probeable

from .dns_zone_import import make_record_data

MAX_BATCH_QUERIES = 4
MAX_NAMESERVERS = 8


class ZoneCheckError(ValueError):
    pass


class _Channel:
    """Phase3's single-budget transport also supports explicit assigned/parent NS checks."""

    def __init__(self) -> None:
        from apps.infrastructure.dns_probes import DnsProbeTransport, ProbeError  # noqa: PLC0415

        self.transport = DnsProbeTransport()
        self.error_type = ProbeError
        self.parent_ttl = 0

    def _call(self, callback: Callable[[], Any]) -> Any:
        try:
            return callback()
        except self.error_type as error:
            raise ZoneCheckError("dns_observation_unknown") from error

    def query(self, name: str, kind: str, *, parent: bool = False, wildcard_owner: bool = False) -> Any:
        return self._call(lambda: self.transport.query(name, kind, parent=parent, wildcard_owner=wildcard_owner))

    def assigned(self, name: str, kind: str, nameservers: tuple[str, ...], zone: str) -> Any:
        if not nameservers or len(nameservers) > MAX_NAMESERVERS:
            raise ZoneCheckError("dns_observation_unknown")
        answers = []
        for server in nameservers:
            address = self._call(partial(self.transport._address, server))
            response = self._call(partial(self.transport._ask, name, kind, address, recursive=False, zone=zone))
            answers.append(self._call(partial(self.transport._parse, response, name, kind, zone)))
        if len({(_entries(answer), answer.ttl) for answer in answers}) != 1:
            raise ZoneCheckError("assigned_authorities_disagree")
        return answers[0]

    def parent_nameservers(self, name: str) -> tuple[str, ...]:
        parent = dns.name.from_text(name).parent().to_text(omit_final_dot=True)
        zone = self._call(lambda: self.transport.zone(parent))
        servers = self._call(lambda: self.transport._servers(zone))
        answers = []
        for server in servers:
            # Delegation referrals legitimately lack AA. The destinations are the
            # discovered parent authorities, and every packet uses the shared budget.
            address = self._call(partial(self.transport._address, server))
            response = self._call(partial(self.transport._ask, name, "NS", address, recursive=True, zone=zone))
            owner = dns.name.from_text(name)
            values = {
                record.target.canonicalize().to_text(omit_final_dot=True)
                for rrset in [*response.answer, *response.authority]
                if rrset.rdtype == dns.rdatatype.NS and rrset.name == owner
                for record in rrset
            }
            self.parent_ttl = max(
                self.parent_ttl,
                max(
                    (
                        rrset.ttl
                        for rrset in [*response.answer, *response.authority]
                        if rrset.rdtype == dns.rdatatype.NS and rrset.name == owner
                    ),
                    default=0,
                ),
            )
            if response.rcode() != dns.rcode.NOERROR or not values:
                raise ZoneCheckError("parent_delegation_unproven")
            answers.append(tuple(sorted(values)))
        if not answers or len(set(answers)) != 1:
            raise ZoneCheckError("parent_delegation_unproven")
        return answers[0]


def _entries(answer: Any) -> tuple[str, tuple[str, ...]]:
    if answer.alias:
        data = make_record_data("CNAME", answer.alias + ".")
        return "CNAME", (hashlib.sha256(bytes.fromhex(data["wire"])).hexdigest(),)
    if not answer.values and answer.negative not in {"nodata", "nxdomain"}:
        raise ZoneCheckError("dns_negative_unproven")
    return str(answer.record_type), tuple(
        sorted(hashlib.sha256(record.to_digestable()).hexdigest() for record in answer.values)
    )


def handover_snapshot(name: str, *, channel: Any = None) -> dict[str, Any]:
    selected = channel or _Channel()
    try:
        nameservers = selected.parent_nameservers(name)
        ds = selected.query(name, "DS", parent=True)
        _entries(ds)  # A missing DS is safe only with a proven authoritative negative.
        if ds.alias or ds.negative == "nxdomain":
            raise ZoneCheckError("parent_ds_unproven")
        return {
            "state": "verified",
            "nameservers": list(nameservers),
            "ds": [record.to_text() for record in ds.values],
            "ds_ttl": int(ds.ttl or 0) if ds.values else 0,
            "ns_ttl": int(getattr(selected, "parent_ttl", 0)),
            "checked_at": datetime.now(UTC).isoformat(),
        }
    except (ZoneCheckError, dns.exception.DNSException, ValueError, OSError):
        return {"state": "unknown", "error": "dns_observation_unknown", "checked_at": datetime.now(UTC).isoformat()}


def _index(inventory: list[dict[str, Any]]) -> tuple[dict[tuple[str, str], set[str]], set[str]]:
    expected: dict[tuple[str, str], set[str]] = {}
    nodes: set[str] = set()
    for row in inventory:
        expected.setdefault((row["name"], row["record_type"]), set()).add(row["rdata_digest"])
        current = dns.name.from_text(row["name"])
        while current != dns.name.root:
            nodes.add(current.to_text(omit_final_dot=True))
            current = current.parent()
    return expected, nodes


def _expected(expected: dict[tuple[str, str], set[str]], nodes: set[str], name: str, kind: str) -> set[str]:
    if name in nodes:
        return expected.get((name, kind), set())
    current = dns.name.from_text(name).parent()
    while current != dns.name.root:
        parent = current.to_text(omit_final_dot=True)
        if parent in nodes:
            return expected.get((f"*.{parent}", kind), set())
        current = current.parent()
    return set()


def import_questions(name: str, inventory: list[dict[str, Any]]) -> list[tuple[str, str]]:
    queries = {(row["name"], row["record_type"]) for row in inventory if not row.get("infrastructure")}
    common = {
        "": ("A", "AAAA", "MX", "TXT", "CAA"),
        "www": ("A", "AAAA", "CNAME"),
        "mail": ("A", "AAAA", "CNAME"),
        "autodiscover": ("A", "AAAA", "CNAME"),
        "_dmarc": ("TXT",),
        "default._domainkey": ("TXT",),
        "mail._domainkey": ("TXT",),
        "selector1._domainkey": ("TXT",),
        "selector2._domainkey": ("TXT",),
        "_sip._tcp": ("SRV",),
    }
    queries.update((f"{prefix}.{name}" if prefix else name, kind) for prefix, kinds in common.items() for kind in kinds)
    return sorted(queries)


def probe_import_batch(
    name: str, inventory: list[dict[str, Any]], cursor: int, *, channel: Any = None, batch_size: int = MAX_BATCH_QUERIES
) -> dict[str, Any]:
    selected = channel or _Channel()
    queries = import_questions(name, inventory)
    expected, nodes = _index(inventory)
    result: dict[str, Any] = {
        "cursor": cursor,
        "total": len(queries),
        "complete": False,
        "ok": True,
        "observations": {},
        "checked_at": datetime.now(UTC).isoformat(),
    }
    # A name the probe refuses is refused whatever the network does: report it before any packet.
    if not all(probeable(owner, wildcard_owner=True) for owner, _kind in queries):
        return {**result, "ok": False, "error": "source_owner_uncheckable"}
    if cursor == 0:
        handover = handover_snapshot(name, channel=selected)
        if handover["state"] != "verified":
            return {**result, "ok": False, "error": "dns_observation_unknown"}
        result["handover"] = handover
        result["ds_ttl"] = handover["ds_ttl"]
    for index in range(cursor, min(len(queries), cursor + min(MAX_BATCH_QUERIES, max(1, batch_size)))):
        owner, kind = queries[index]
        try:
            answer = selected.query(owner, kind, wildcard_owner=True)
            actual_kind, values = _entries(answer)
        except (ZoneCheckError, dns.exception.DNSException, ValueError, OSError):
            return {**result, "ok": False, "error": "dns_observation_unknown"}
        if not set(values).issubset(_expected(expected, nodes, owner, actual_kind)):
            return {**result, "ok": False, "error": "source_record_missing_from_inventory"}
        result["observations"][f"{owner}|{kind}"] = {"kind": actual_kind, "digests": list(values), "ttl": answer.ttl}
        result["cursor"] = index + 1
    result["complete"] = result["cursor"] == len(queries)
    return result


def probe_provider_batch(
    name: str, manifest: list[dict[str, Any]], nameservers: tuple[str, ...], cursor: int, *, channel: Any = None
) -> dict[str, Any]:
    selected = channel or _Channel()
    groups: dict[tuple[str, str], tuple[set[str], int]] = {}
    for row in manifest:
        data = make_record_data(row["record_type"], row["rdata"]["text"], origin=name)
        expected_values, _ttl = groups.setdefault((row["name"], row["record_type"]), (set(), int(row["ttl"])))
        expected_values.add(hashlib.sha256(bytes.fromhex(data["wire"])).hexdigest())
    queries = sorted(groups)
    result: dict[str, Any] = {
        "cursor": cursor,
        "total": len(queries),
        "complete": False,
        "ok": True,
        "checked_at": datetime.now(UTC).isoformat(),
    }
    for index in range(cursor, min(len(queries), cursor + MAX_BATCH_QUERIES)):
        owner, kind = queries[index]
        try:
            observed = selected.assigned(owner, kind, nameservers, name)
            actual_kind, values = _entries(observed)
        except (ZoneCheckError, dns.exception.DNSException, ValueError, OSError):
            return {**result, "ok": False, "error": "assigned_dns_unproven"}
        expected, ttl = groups[(owner, kind)]
        if actual_kind != kind or set(values) != expected or observed.ttl != ttl:
            return {**result, "ok": False, "error": "assigned_dns_mismatch"}
        result["cursor"] = index + 1
    result["complete"] = result["cursor"] == len(queries)
    return result
