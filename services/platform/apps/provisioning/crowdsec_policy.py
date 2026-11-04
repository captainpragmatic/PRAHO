"""Exact, opt-in CrowdSec host schema; no network I/O or firewall mutations."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import NoReturn
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

BASE_PROFILE = "virtualmin-web-only-v2"
CROWDSEC_PROFILE = "virtualmin-web-only-v2+crowdsec-v1"
PROFILES = frozenset({BASE_PROFILE, CROWDSEC_PROFILE})
MAX_PUBLIC_KEY_BYTES = 16384
PUBLIC_KEY_FIELDS = 2
IPV6_VERSION = 6
OWNED_SET_COUNT = 2
TABLES = {"ip": "praho_crowdsec4", "ip6": "praho_crowdsec6"}
# Shipped independently from the host facts; test_crowdsec_artifacts checks these bindings.
EXPECTED_HELPER_SHA256 = "a3e2e0ee01e29294ac52b04ad2ddd33134a9fdfaf6e0ebec31b20bb21d554704"
EXPECTED_ARTIFACT_LOCK_SHA256 = "ebc0065bddd5271a402ce22ef6f73c1f5f715834055cc4569fd40b65c8b01aad"
EXPECTED_BOUNCER_SHA256 = {
    "amd64": "894c139f9477a0b614689011d4cf9b9da0be9f9a3e14a9cda4e92ac105a2caff",
    "arm64": "bd8f8466ba611ada38ace34bfcb46b4fe00a3f1666b5c7272ff9d0e7e3a62dc1",
}
CROWDSEC_SSH_CONFIG_DIGESTS = {
    ".ssh/authorized_keys": "aa1ff90d0c027583bcef714ae028d932af6ed7660f628882a17e3bcff46705f2",
    ".ssh/authorized_keys .ssh/authorized_keys2": "8934a82a7069c2baa713053024ccbd1f32615c1b72cd404c80f66d9ee3831a91",
}
MANAGED_FILES = frozenset(
    {
        "/etc/crowdsec/config.yaml",
        "/etc/crowdsec/acquis.yaml",
        "/etc/crowdsec/profiles.yaml",
        "/etc/crowdsec/simulation.yaml",
        "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
        "/usr/bin/cscli",
        "/etc/systemd/system/crowdsec.service.d/praho.conf",
        "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/praho.conf",
        "/etc/systemd/system/crowdsec-hubupdate.service.d/praho.conf",
        "/etc/systemd/system/crowdsec-hubupdate.timer.d/praho.conf",
        "/etc/systemd/system/praho-crowdsec-firewall.service",
        "/usr/local/libexec/praho-crowdsec-firewall",
        "/usr/local/libexec/praho-crowdsec-gateway",
        "/home/praho-crowdsec/.ssh/authorized_keys",
        "/etc/sudoers.d/praho-crowdsec",
        "/etc/praho-crowdsec/artifacts.lock.json",
        "/etc/crowdsec/parsers/s00-raw/syslog-logs.yaml",
        "/etc/crowdsec/parsers/s01-parse/sshd-logs.yaml",
        "/etc/crowdsec/parsers/s01-parse/apache2-logs.yaml",
        "/etc/crowdsec/parsers/s01-parse/webmin-logs.yaml",
        "/etc/crowdsec/parsers/s02-enrich/dateparse-enrich.yaml",
        "/etc/crowdsec/parsers/s02-enrich/http-logs.yaml",
        "/etc/crowdsec/scenarios/ssh-bf.yaml",
        "/etc/crowdsec/scenarios/ssh-slow-bf.yaml",
        "/etc/crowdsec/scenarios/ssh-cve-2024-6387.yaml",
        "/etc/crowdsec/scenarios/http-cve-2021-41773.yaml",
        "/etc/crowdsec/scenarios/http-cve-2021-42013.yaml",
        "/etc/crowdsec/scenarios/http-probing.yaml",
        "/etc/crowdsec/scenarios/webmin-bf.yaml",
    }
)
GATEWAY_COMMAND = "sudo -n /usr/local/libexec/praho-crowdsec-gateway"
GATEWAY_SUDO = (
    "Defaults:praho-crowdsec env_reset\n"
    'Defaults:praho-crowdsec secure_path="/usr/sbin:/usr/bin:/sbin:/bin"\n'
    'Defaults:praho-crowdsec env_keep += "SSH_ORIGINAL_COMMAND"\n'
    'praho-crowdsec ALL=(root) NOPASSWD: /usr/local/libexec/praho-crowdsec-gateway ""\n'
)


def _fail() -> NoReturn:
    raise ValidationError(_("The selected CrowdSec host policy is incomplete or differs from the reviewed schema."))


def gateway_public_key() -> str:
    """Read one separately enrolled public identity; never accept authorized_keys options."""
    from apps.common.ssh import parse_ssh_host_keys  # noqa: PLC0415 -- transport boundary

    try:
        path = str(getattr(settings, "PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH", "") or "")
        if not path:
            _fail()
        with Path(path).open("rb") as source:
            content = source.read(MAX_PUBLIC_KEY_BYTES + 1)
        if len(content) > MAX_PUBLIC_KEY_BYTES:
            _fail()
        lines = [line for line in content.decode().splitlines() if line.strip()]
        if len(lines) != 1 or len(lines[0].split()) < PUBLIC_KEY_FIELDS:
            _fail()
        public = " ".join(lines[0].split()[:PUBLIC_KEY_FIELDS])
        parse_ssh_host_keys(public)
        return public
    except (OSError, UnicodeError, ValueError) as error:
        raise ValidationError(_("The dedicated CrowdSec SSH public identity is unavailable or invalid.")) from error


def gateway_key_fingerprint() -> str:
    encoded = gateway_public_key().split()[1]
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(encoded, validate=True)).digest()
    ).decode().rstrip("=")


def _hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _configuration_rows(services: list[str]) -> dict[str, list[dict[str, object]]]:
    rows: dict[str, list[dict[str, object]]] = {name: [] for name in ("CONFIG", "POLICY", "RUNTIME", "FILE")}
    for line in services:
        if not line.startswith("PRAHO_CROWDSEC_"):
            continue
        tag, separator, raw = line.removeprefix("PRAHO_CROWDSEC_").partition(" ")
        if not separator or tag not in rows:
            _fail()
        value = json.loads(raw)
        if not isinstance(value, dict):
            _fail()
        rows[tag].append(value)
    return rows


def _single(rows: dict[str, list[dict[str, object]]], name: str) -> dict[str, object]:
    if len(rows[name]) != 1:
        _fail()
    return rows[name][0]


def _actual_managed_files(rows: list[dict[str, object]]) -> dict[str, str]:
    files: dict[str, str] = {}
    for row in rows:
        path = row.get("path")
        digest = row.get("sha256")
        if (
            set(row) != {"path", "sha256", "root_owned"}
            or not isinstance(path, str)
            or path not in MANAGED_FILES
            or path in files
            or not isinstance(digest, str)
            or not _hex(digest)
            or row["root_owned"] is not True
        ):
            _fail()
        files[path] = digest
    if set(files) != MANAGED_FILES or EXPECTED_HELPER_SHA256 == "0" * 64:
        _fail()
    if files["/usr/local/libexec/praho-crowdsec-gateway"] != EXPECTED_HELPER_SHA256:
        _fail()
    if files["/etc/sudoers.d/praho-crowdsec"] != hashlib.sha256(GATEWAY_SUDO.encode()).hexdigest():
        _fail()
    if files["/etc/praho-crowdsec/artifacts.lock.json"] != EXPECTED_ARTIFACT_LOCK_SHA256:
        _fail()
    return files


def _protected_inventory(value: object, required_cidrs: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail()
    networks = [ipaddress.ip_network(item, strict=True) for item in value]
    if value != sorted({str(network) for network in networks}) or any(network.prefixlen == 0 for network in networks):
        _fail()
    for cidr in required_cidrs:
        required = ipaddress.ip_network(cidr, strict=True)
        if not any(_contains_network(network, required) for network in networks):
            _fail()
    return list(value)


def _contains_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    required: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if isinstance(network, ipaddress.IPv4Network) and isinstance(required, ipaddress.IPv4Network):
        return required.subnet_of(network)
    if isinstance(network, ipaddress.IPv6Network) and isinstance(required, ipaddress.IPv6Network):
        return required.subnet_of(network)
    return False


def verify_configuration(services: list[str], expected_digest: str, required_cidrs: list[str]) -> list[str]:
    """Reconstruct the approved policy from observed fixed files, not a trusted installed flag."""
    try:
        rows = _configuration_rows(services)
        config, policy, runtime = (_single(rows, name) for name in ("CONFIG", "POLICY", "RUNTIME"))
        if (
            set(config) != {"configuration_digest", "configuration_sha256", "installation_id", "root_owned"}
            or config["root_owned"] is not True
            or not _hex(config["configuration_sha256"])
            or not isinstance(config["installation_id"], str)
            or str(UUID(config["installation_id"])) != config["installation_id"]
        ):
            _fail()
        if (
            set(policy)
            != {"schema", "host_kind", "simulation", "protected_cidrs", "artifact_lock_sha256", "bouncer_binary_sha256"}
            or type(policy["schema"]) is not int
            or policy["schema"] != 1
            or policy["host_kind"] != "node"
            or type(policy["simulation"]) is not bool
            or policy["artifact_lock_sha256"] != EXPECTED_ARTIFACT_LOCK_SHA256
            or not _hex(policy["bouncer_binary_sha256"])
        ):
            _fail()
        protected = _protected_inventory(policy["protected_cidrs"], required_cidrs)
        if (
            set(runtime)
            != {
                "architecture",
                "engine_version",
                "engine_active",
                "bouncer_active",
                "bouncer_binary_sha256",
                "database_matches",
                "simulation_bans_empty",
                "configuration_canonical",
                "services_canonical",
            }
            or runtime["engine_version"] != "1.8.2"
            or runtime["engine_active"] is not True
            or runtime["database_matches"] is not True
            or type(runtime["architecture"]) is not str
            or runtime["architecture"] not in EXPECTED_BOUNCER_SHA256
            or runtime["configuration_canonical"] is not True
            or runtime["services_canonical"] is not True
            or runtime["bouncer_binary_sha256"] != EXPECTED_BOUNCER_SHA256.get(str(runtime["architecture"]))
            or runtime["bouncer_binary_sha256"] != policy["bouncer_binary_sha256"]
            or runtime["bouncer_active"] is not (not policy["simulation"])
            or runtime["simulation_bans_empty"] is not (True if policy["simulation"] else None)
        ):
            _fail()
        actual = {**policy, "managed_files": _actual_managed_files(rows["FILE"])}
        digest = hashlib.sha256(
            json.dumps(actual, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if not _hex(expected_digest) or expected_digest != digest or config["configuration_digest"] != digest:
            _fail()
        return protected
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValidationError(_("CrowdSec configuration evidence is malformed.")) from error


def _members(values: object, ipv6: bool) -> set[str]:
    if not isinstance(values, list):
        _fail()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        if isinstance(value, str):
            network = ipaddress.ip_network(value, strict=True)
        elif isinstance(value, dict) and set(value) == {"prefix"}:
            prefix = value["prefix"]
            if (
                not isinstance(prefix, dict)
                or set(prefix) != {"addr", "len"}
                or not isinstance(prefix["addr"], str)
                or type(prefix["len"]) is not int
            ):
                _fail()
            network = ipaddress.ip_network(prefix["addr"] + "/" + str(prefix["len"]), strict=True)
        else:
            _fail()
        if (network.version == IPV6_VERSION) != ipv6 or network.prefixlen == 0:
            _fail()
        networks.append(network)
    ipv4 = [network for network in networks if isinstance(network, ipaddress.IPv4Network)]
    ipv6_networks = [network for network in networks if isinstance(network, ipaddress.IPv6Network)]
    return {
        *(str(network) for network in ipaddress.collapse_addresses(ipv4)),
        *(str(network) for network in ipaddress.collapse_addresses(ipv6_networks)),
    }


def _family_objects(entries: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    objects: dict[str, list[dict[str, object]]] = {kind: [] for kind in ("table", "chain", "set", "rule")}
    for entry in entries:
        if len(entry) != 1:
            _fail()
        kind, value = next(iter(entry.items()))
        if kind not in objects or not isinstance(value, dict):
            _fail()
        objects[kind].append(value)
    return objects


def _verify_family(entries: list[dict[str, object]], family: str, protected_cidrs: list[str]) -> None:
    table = TABLES[family]
    identity = {"family": family, "table": table}
    objects = _family_objects(entries)
    if objects["table"] != [{"family": family, "name": table}]:
        _fail()
    if objects["chain"] != [
        {**identity, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}
    ]:
        _fail()
    if len(objects["set"]) != OWNED_SET_COUNT:
        _fail()
    sets = {item.get("name"): item for item in objects["set"]}
    if set(sets) != {"protected", "bans"}:
        _fail()
    address_type = "ipv6_addr" if family == "ip6" else "ipv4_addr"
    if sets["bans"] != {**identity, "name": "bans", "type": address_type, "flags": ["interval", "timeout"]}:
        _fail()
    protected = sets["protected"]
    if {key: value for key, value in protected.items() if key != "elem"} != {
        **identity,
        "name": "protected",
        "type": address_type,
        "flags": ["interval"],
    }:
        _fail()
    expected = [value for value in protected_cidrs if (":" in value) == (family == "ip6")]
    if _members(protected.get("elem", []), family == "ip6") != _members(expected, family == "ip6"):
        _fail()
    rules = []
    for name, verdict in (("protected", "return"), ("bans", "drop")):
        rules.append(
            {
                **identity,
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
        )
    if objects["rule"] != rules:
        _fail()


def verify_owned_firewall(entries: list[dict[str, object]], protected_cidrs: list[str]) -> None:
    """Require both exact owned tables; volatile ban members must not enter review evidence."""
    try:
        grouped: dict[str, list[dict[str, object]]] = {"ip": [], "ip6": []}
        for entry in entries:
            if not isinstance(entry, dict) or len(entry) != 1:
                _fail()
            value = next(iter(entry.values()))
            if not isinstance(value, dict) or value.get("family") not in grouped:
                _fail()
            grouped[str(value["family"])].append(entry)
        for family, values in grouped.items():
            _verify_family(values, family, protected_cidrs)
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValidationError(_("CrowdSec firewall evidence is malformed.")) from error
