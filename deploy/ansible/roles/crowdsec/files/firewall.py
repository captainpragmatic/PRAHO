#!/usr/bin/python3 -I
"""Converge only the two exact PRAHO INPUT tables; preserve every other owner."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

TABLES = {"ip": "praho_crowdsec4", "ip6": "praho_crowdsec6"}
CONFIG = Path("/etc/praho-crowdsec/config.json")
NFT = "/usr/sbin/nft"
MAX_PROTECTED_NETWORKS = 256
OWNED_SET_COUNT = 2
OWNED_RULE_COUNT = 2
IPV6_VERSION = 6


def protected_networks(config: dict[str, object]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    values = config.get("protected_cidrs")
    if (
        type(config.get("simulation")) is not bool
        or not isinstance(values, list)
        or not 1 <= len(values) <= MAX_PROTECTED_NETWORKS
    ):
        raise ValueError("Explicit simulation and bounded protected inventory are required")
    if any(not isinstance(value, str) for value in values):
        raise ValueError("Protected inventory must contain canonical CIDRs")
    networks = [ipaddress.ip_network(value, strict=True) for value in values]
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError("Inventory cannot protect the whole Internet")
    return networks


def _members(values: list[object]) -> set[str]:
    result = set()
    for value in values:
        if isinstance(value, str):
            result.add(str(ipaddress.ip_network(value, strict=True)))
        elif isinstance(value, dict) and set(value) == {"prefix"}:
            prefix = value["prefix"]
            result.add(str(ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=True)))
        else:
            raise ValueError("Unrecognized owned firewall protected member")
    return result


def _objects(observed: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    entries = observed.get("nftables")
    if not isinstance(entries, list):
        raise ValueError("Incomplete owned firewall evidence")
    tables, sets, chains, rules = [], [], [], []
    kinds = {"table": tables, "set": sets, "chain": chains, "rule": rules}
    for entry in entries:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError("Malformed owned firewall object")
        kind, value = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if kind not in kinds or not isinstance(value, dict):
            raise ValueError("Unclassified owned firewall facility")
        kinds[kind].append({key: item for key, item in value.items() if key != "handle"})
    return kinds


def _validate(family: str, observed: dict[str, object]) -> dict[str, dict[str, object]]:
    table = TABLES[family]
    objects = _objects(observed)
    tables, sets, chains, rules = (objects[name] for name in ("table", "set", "chain", "rule"))
    if (
        tables != [{"family": family, "name": table}]
        or len(sets) != OWNED_SET_COUNT
        or len(chains) != 1
        or len(rules) != OWNED_RULE_COUNT
    ):
        raise ValueError("Unexpected owned firewall schema")
    expected_chain = {
        "family": family,
        "table": table,
        "name": "input",
        "type": "filter",
        "hook": "input",
        "prio": -10,
        "policy": "accept",
    }
    if chains != [expected_chain]:
        raise ValueError("Unexpected owned firewall hook")
    by_name = {item.get("name"): item for item in sets}
    if set(by_name) != {"protected", "bans"}:
        raise ValueError("Unexpected owned firewall sets")
    address_type = "ipv4_addr" if family == "ip" else "ipv6_addr"
    for name, flags in (("protected", {"interval"}), ("bans", {"interval", "timeout"})):
        actual = by_name[name]
        if (
            set(actual) - {"family", "table", "name", "type", "flags", "elem"}
            or {key: actual.get(key) for key in ("family", "table", "name", "type")}
            != {"family": family, "table": table, "name": name, "type": address_type}
            or set(actual.get("flags", [])) != flags
        ):
            raise ValueError("Unexpected owned firewall set properties")
    for rule, name, verdict in zip(rules, ("protected", "bans"), ("return", "drop"), strict=True):
        expected = {
            "family": family,
            "table": table,
            "chain": "input",
            "expr": [
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": family, "field": "saddr"}},
                        "right": "@" + name,
                    }
                },
                {verdict: None},
            ],
        }
        if rule != expected:
            raise ValueError("Unexpected owned firewall rule")
    return by_name


def compile_update(config: dict[str, object], observed: dict[str, dict[str, object] | None]) -> str:
    networks = protected_networks(config)
    # Validate every existing family before generating any mutation.
    validated = {
        family: _validate(family, observed[family]) if observed[family] is not None else None for family in TABLES
    }
    commands = []
    for family, table in TABLES.items():
        wanted = sorted(
            str(value)
            for value in ipaddress.collapse_addresses(
                [network for network in networks if (network.version == IPV6_VERSION) == (family == "ip6")]
            )
        )
        existing = validated[family]
        if existing is None:
            address_type = "ipv4_addr" if family == "ip" else "ipv6_addr"
            elements = " elements = { " + ", ".join(wanted) + " };" if wanted else ""
            commands.append(
                f"table {family} {table} {{\nset protected {{ type {address_type}; flags interval;{elements} }}\nset bans {{ type {address_type}; flags interval,timeout; }}\nchain input {{ type filter hook input priority -10; policy accept;\n{family} saddr @protected return\n{family} saddr @bans drop\n}}\n}}"
            )
        else:
            if _members(existing["protected"].get("elem", [])) != set(wanted):
                commands.append(f"flush set {family} {table} protected")
                if wanted:
                    commands.append(f"add element {family} {table} protected {{ " + ", ".join(wanted) + " }")
            if config["simulation"] and existing["bans"].get("elem"):
                commands.append(f"flush set {family} {table} bans")
    return "\n".join(commands) + ("\n" if commands else "")


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError("The fixed firewall helper requires root and no arguments")
    config = json.loads(CONFIG.read_text())
    observed = {}
    for family, table in TABLES.items():
        result = subprocess.run(  # noqa: S603 -- fixed executable and owned table identifiers
            [NFT, "-j", "list", "table", family, table], capture_output=True, text=True, check=False, timeout=10
        )
        if result.returncode == 0:
            observed[family] = json.loads(result.stdout)
        elif "No such file or directory" in result.stderr:
            observed[family] = None
        else:
            raise ValueError("Cannot inspect existing firewall ownership")
    update = compile_update(config, observed)
    if update:
        subprocess.run([NFT, "-f", "-"], input=update, text=True, capture_output=True, check=True, timeout=10)  # noqa: S603 -- validated, fixed-schema nft transaction
    print(json.dumps({"changed": bool(update)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
