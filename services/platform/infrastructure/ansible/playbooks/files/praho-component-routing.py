#!/usr/bin/env python3
"""Plan exact website address changes; native DNS locks retain mail and other records."""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 10000
SOA_FIELDS = 7


def retained_digest(domain: str, records: list[dict[str, Any]]) -> str:
    rows = []
    names = {domain + ".", "www." + domain + "."}
    for record in records:
        kind = str(record.get("type", "")).upper()
        if kind in {"RRSIG", "NSEC", "NSEC3"} or (record.get("name", "").lower() in names and kind in {"A", "AAAA"}):
            continue
        row = {
            key: record[key] for key in ("name", "type", "ttl", "values", "defttl", "origin", "class") if key in record
        }
        if kind == "SOA":
            values = list(row["values"])
            if len(values) != SOA_FIELDS:
                raise ValueError("The native SOA record is unqualified")
            values[2] = "<native serial>"
            row["values"] = values
        rows.append(json.dumps(row, sort_keys=True, separators=(",", ":")))
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()


def _network(network: dict[str, str]) -> None:
    for key, value in network.items():
        if key not in {"source_ipv4", "source_ipv6", "target_ipv4", "target_ipv6"}:
            raise ValueError("The frozen routing network is unqualified")
        if value:
            parsed = ipaddress.ip_address(value)
            if parsed.version != (4 if key.endswith("ipv4") else 6):
                raise ValueError("The frozen routing address family changed")
    if set(network) != {"source_ipv4", "source_ipv6", "target_ipv4", "target_ipv6"} or not all(
        network[key] for key in ("source_ipv4", "target_ipv4")
    ):
        raise ValueError("Exact source and target routing dispositions are required")


def _addresses(addresses: list[tuple[int, dict[str, Any]]], network: dict[str, str]) -> list[dict[str, Any]] | None:
    operations = []
    for index, row in addresses:
        family = "ipv4" if row["type"].upper() == "A" else "ipv6"
        values = row.get("values")
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError("The native website address record is unqualified")
        address = str(ipaddress.ip_address(values[0]))
        old, new = network["source_" + family], network["target_" + family]
        if address not in {old, new}:
            return None
        if address != new:
            operations.append({"index": index, "value": new})
    return operations


def plan_records(domain: str, records: list[dict[str, Any]], network: dict[str, str]) -> dict[str, Any]:
    if not isinstance(records, list) or len(records) > MAX_RECORDS or any(not isinstance(row, dict) for row in records):
        raise ValueError("The native DNS record inventory exceeds its exact bound")
    _network(network)
    protected = retained_digest(domain, records)
    operations = []
    for name in (domain + ".", "www." + domain + "."):
        selected = [(index, row) for index, row in enumerate(records) if row.get("name", "").lower() == name]
        aliases = [row for _index, row in selected if str(row.get("type", "")).upper() == "CNAME"]
        addresses = [(index, row) for index, row in selected if str(row.get("type", "")).upper() in {"A", "AAAA"}]
        if aliases:
            if name == domain + "." or len(aliases) != 1 or aliases[0].get("values") != [domain + "."] or addresses:
                return {"mode": "operator_dns_required", "operations": [], "retained_digest": protected}
            continue
        if not addresses:
            if name == domain + ".":
                return {"mode": "operator_dns_required", "operations": [], "retained_digest": protected}
            continue
        changes = _addresses(addresses, network)
        if changes is None:
            return {"mode": "operator_dns_required", "operations": [], "retained_digest": protected}
        operations.extend(changes)
        if network["target_ipv6"] and not any(row["type"].upper() == "AAAA" for _index, row in addresses):
            template = next((row for _index, row in addresses if row["type"].upper() == "A"), None)
            if template is not None:
                operations.append(
                    {
                        "create": {
                            "name": name,
                            "type": "AAAA",
                            "ttl": template.get("ttl"),
                            "values": [network["target_ipv6"]],
                        }
                    }
                )
    return {"mode": "source_dns_updated", "operations": operations, "retained_digest": protected}


def verify_bridged_source(source: Any, state: dict[str, Any], network: dict[str, str]) -> str:
    # Retained mail credentials may rotate independently after the source seal.
    # Compare CURRENT retained state across this operation; the selected writer,
    # inode, SQL and original-vhost authority remains unchanged and fully checked.
    context = state["context"]
    retained = source.retained(context)
    steps = source.build(context)
    ingress = steps["web"]
    with ingress.journal.locked():
        held = ingress._state()
        if held["phase"] != "held":
            raise ValueError("The committed source lost its independently owned ingress hold")
        ingress._original()
        ingress._owned(held)
        ingress._owned_certificates(held)
    spec = importlib.util.spec_from_file_location(
        "component_committed_bridge", Path(__file__).with_name("praho-bridge.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("Committed bridge verification is unavailable")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    node = bridge.NodeBridge()
    manifest = node.bound_manifest(
        json.loads((node.directory(source.operation) / "source.json").read_text()), source.operation
    )
    if any(
        manifest[key] != value
        for key, value in {
            "domain": source.request["domain"],
            "source": network["source_ipv4"],
            "target": network["target_ipv4"],
        }.items()
    ):
        raise ValueError("The committed source bridge differs from its frozen component network")
    node.verify(source.operation)
    for name in ("cron", "database", "paths"):
        steps[name].verify()
    if source.retained(context) != retained:
        raise ValueError("Retained source services changed during committed bridge verification")
    return retained


def route_source(source: Any, network: dict[str, str]) -> dict[str, str]:
    with source.coordinator.journal.locked():
        state = source.coordinator._state()
        if state["phase"] != "committed":
            raise ValueError("Only the sealed source may publish component routing")
        retained = verify_bridged_source(source, state, network)
        result = subprocess.run(  # noqa: S603 -- protected sibling, fixed native API and bounded private stdin
            ["/usr/bin/perl", str(Path(__file__).with_suffix(".pl"))],
            input=json.dumps({"request": source.request, "network": network}),
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if result.returncode or len(result.stdout.encode()) > MAX_BYTES:
            raise ValueError("Native component routing is uncertain; preserve its source bridge")
        receipt = json.loads(result.stdout)
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"mode"}
            or receipt["mode"] not in {"source_dns_updated", "operator_dns_required"}
        ):
            raise ValueError("The native routing receipt is unrecognized")
        if verify_bridged_source(source, state, network) != retained:
            raise ValueError("Retained source services changed during website DNS publication")
        return receipt


if __name__ == "__main__":
    encoded = sys.stdin.read(MAX_BYTES + 1)
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("Native routing input exceeds its bound")
    payload = json.loads(encoded)
    if sys.argv[1:] == ["--retained"]:
        print(retained_digest(payload["domain"], payload["records"]))
    elif sys.argv[1:] == ["--plan"]:
        print(json.dumps(plan_records(payload["domain"], payload["records"], payload["network"])))
    else:
        raise ValueError("An exact native routing planner action is required")
