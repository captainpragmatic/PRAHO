"""Verify live INPUT reachability rather than trusting a configuration marker."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections import defaultdict
from typing import Any, NoReturn, cast

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .virtualmin_security import _evidence_digest
from .virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES

MIN_SOCKET_FIELDS = 6
LOOPBACK_TCP_PORTS = frozenset({"25", "3306", "53", "11000"})
SSH_BASELINE = {
    "port": ["9876"],
    "permitrootlogin": ["without-password"],
    "pubkeyauthentication": ["yes"],
    "authenticationmethods": ["publickey"],
    "passwordauthentication": ["no"],
    "kbdinteractiveauthentication": ["no"],
    "permitemptypasswords": ["no"],
    "hostbasedauthentication": ["no"],
    "strictmodes": ["yes"],
    "usedns": ["no"],
    "allowtcpforwarding": ["no"],
    "allowstreamlocalforwarding": ["no"],
    "allowagentforwarding": ["no"],
    "x11forwarding": ["no"],
    "permittunnel": ["no"],
    "gatewayports": ["no"],
    "permituserenvironment": ["no"],
    "authorizedkeyscommand": ["none"],
    "authorizedprincipalscommand": ["none"],
    "authorizedprincipalsfile": ["none"],
    "trustedusercakeys": ["none"],
    "forcecommand": ["none"],
    "permittty": ["yes"],
    "permitopen": ["any"],
}
TUNNEL_KEY_OPTIONS = ["permitopen=127.0.0.1:10000", "port-forwarding", "restrict"]
MAX_OPERATOR_KEYS = 128
# Public SHA-256 fingerprints of the two reviewed canonical SSH configurations.
SSH_CONFIG_PRIMARY_SHA256 = "c669752c5b7bfb7598e54762b055b17ec4f1c816f049e17022dfca8f16d07ecf"
SSH_CONFIG_DUAL_KEYS_SHA256 = "07febb4eb6e488686aec753740b361d418469b382ccd2bbcab22cd7ee6e493a1"
SSH_CONFIG_DIGESTS = {
    ".ssh/authorized_keys": SSH_CONFIG_PRIMARY_SHA256,
    ".ssh/authorized_keys .ssh/authorized_keys2": SSH_CONFIG_DUAL_KEYS_SHA256,
}


def _fail() -> NoReturn:
    raise ValidationError(_("Effective inbound firewall policy is incomplete or admits unreviewed traffic."))


def _options(rule: list[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    modules = []
    allowed = {
        "-s",
        "-d",
        "-i",
        "-p",
        "--sport",
        "--dport",
        "--ctstate",
        "--state",
        "--icmp-type",
        "--icmpv6-type",
        "--hl-eq",
    }
    index = 0
    while index < len(rule):
        key = rule[index]
        if index + 1 >= len(rule):
            _fail()
        value = rule[index + 1]
        if key == "-m":
            modules.append(value)
        elif key not in allowed or key in options:
            _fail()
        else:
            options[key] = value
        index += 2
    if set(modules) - {"tcp", "udp", "conntrack", "state", "icmp", "icmp6", "hl"}:
        _fail()
    return options


def _accept(rule: list[str], networks: set[str], ipv6: bool) -> tuple[str, str] | None:
    options = _options(rule)
    if options == {"-i": "lo"}:
        return None
    if options in (
        {"--ctstate": "RELATED,ESTABLISHED"},
        {"--ctstate": "ESTABLISHED,RELATED"},
        {"--state": "RELATED,ESTABLISHED"},
        {"--state": "ESTABLISHED,RELATED"},
    ):
        return None
    if options.get("-p") == "tcp" and set(options) <= {"-p", "--dport", "-s"}:
        port = options.get("--dport", "")
        source = str(ipaddress.ip_network(options["-s"], strict=False)) if "-s" in options else "any"
        if (port in {"80", "443"} and source == "any") or (port in {"9876", "10000"} and source in networks):
            return port, source
    if options == {"-p": "udp", "--sport": "547" if ipv6 else "67", "--dport": "546" if ipv6 else "68"}:
        return None
    if ipv6 and options == {"-p": "udp", "-s": "fe80::/10", "--sport": "547", "-d": "fe80::/10", "--dport": "546"}:
        return None
    kind = "--icmpv6-type" if ipv6 else "--icmp-type"
    types = (
        {
            "1",
            "2",
            "3",
            "4",
            "128",
            "129",
            "130",
            "131",
            "132",
            "133",
            "134",
            "135",
            "136",
            "141",
            "142",
            "143",
            "144",
            "145",
            "146",
            "147",
            "148",
            "149",
            "151",
            "152",
            "153",
        }
        if ipv6
        else {"3", "8", "11", "12"}
    )
    if (
        options.get("-p") == ("ipv6-icmp" if ipv6 else "icmp")
        and options.get(kind) in types
        and set(options) <= {"-p", kind, "--hl-eq", "-s"}
        and options.get("-s", "fe80::/10") == "fe80::/10"
        and options.get("--hl-eq", "255") in {"255", "1"}
    ):
        return None
    _fail()


def _chains(saved: str) -> dict[str, list[list[str]]]:
    chains: dict[str, list[list[str]]] = defaultdict(list)
    for line in saved.splitlines():
        if line.startswith(":"):
            chains[line.split()[0][1:]]
        if line.startswith("-A "):
            words = shlex.split(line)
            chains[words[1]].append(words[2:])
    return chains


def _jump(rule: list[str]) -> tuple[str, list[str]]:
    if "-g" in rule or "-j" not in rule or rule.count("-j") != 1:
        _fail()
    jump = rule.index("-j")
    if jump + 1 >= len(rule):
        _fail()
    return rule[jump + 1], rule[:jump] + rule[jump + 2 :]


def verify_filter(saved: str, cidrs: list[str], *, ipv6: bool) -> None:
    """Follow every INPUT jump. Require exact web/admin grants in both address families."""
    networks = {str(ipaddress.ip_network(value, strict=True)) for value in cidrs if (":" in value) == ipv6}
    if any(ipaddress.ip_network(value).prefixlen == 0 for value in networks):
        _fail()
    if not any(line.startswith(":INPUT DROP ") for line in saved.splitlines()):
        _fail()
    chains = _chains(saved)
    required = {("80", "any"), ("443", "any")} | {(port, source) for port in ("9876", "10000") for source in networks}
    grants = set()
    visited = set()
    pending = ["INPUT"]
    while pending:
        chain = pending.pop()
        if chain in visited:
            continue
        visited.add(chain)
        for rule in chains[chain]:
            target, conditions = _jump(rule)
            if target == "ACCEPT":
                grant = _accept(conditions, networks, ipv6)
                # Grants in a conditional subchain don't prove public/admin reachability.
                if grant and chain == ("ufw6-user-input" if ipv6 else "ufw-user-input"):
                    grants.add(grant)
            elif target in {"DROP", "REJECT", "RETURN", "LOG", "NFLOG"}:
                continue
            elif target in chains:
                pending.append(target)
            else:
                _fail()
    if required != grants:
        _fail()


def _network_fail(detail: str) -> NoReturn:
    raise ValidationError(
        _(
            "Network preparation required: %(detail)s. Remove or restrict this public publication/direct route, "
            "or prepare an independently verified ingress policy; preserve unrelated outbound/private routing. "
            "Inspect again before hardening. Import and migration-source acknowledgment remain available."
        )
        % {"detail": detail[:650]}
    )


def _network_section(rows: list[str], family: str, table: str) -> str:
    start, end = f"PRAHO_{family}_{table}_BEGIN", f"PRAHO_{family}_{table}_END"
    if rows.count(start) != 1 or rows.count(end) != 1 or rows.index(start) >= rows.index(end):
        _network_fail(f"Complete {family} {table} evidence is missing")
    saved = "\n".join(rows[rows.index(start) + 1 : rows.index(end)])
    if not saved.startswith("*" + table.lower() + "\n") or not saved.endswith("COMMIT"):
        _network_fail(f"The {family} {table} evidence is malformed")
    return saved


def _network_json(rows: list[str], tag: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line in rows:
        if line.startswith(tag + " "):
            value = json.loads(line[len(tag) + 1 :])
            if not isinstance(value, dict):
                _network_fail(f"Malformed {tag} fact")
            result.append(value)
    return result


def _network_interfaces(rows: list[str]) -> tuple[set[str], dict[str, object]]:
    links = _network_json(rows, "PRAHO_NETWORK_LINK")
    flags = _network_json(rows, "PRAHO_FORWARDING")
    if not links or len(flags) != 1 or set(flags[0]) != {"ipv4", "ipv6"}:
        _network_fail("Complete interface/address and forwarding facts are missing")
    forwarding = flags[0]
    v6 = forwarding["ipv6"]
    if (
        type(forwarding["ipv4"]) is not int
        or forwarding["ipv4"] not in {0, 1}
        or not isinstance(v6, dict)
        or not {"all", "default"} <= set(v6)
        or any(type(value) is not int or value not in {0, 1} for value in v6.values())
    ):
        _network_fail("IPv4/IPv6 forwarding settings are incomplete")
    routes = _network_json(rows, "PRAHO_NETWORK_ROUTE4") + _network_json(rows, "PRAHO_NETWORK_ROUTE6")
    if any("nexthops" in route for route in routes):
        _network_fail("Multipath routing requires reviewed ingress-interface preparation")
    wan = {route["dev"] for route in routes if route.get("dst") in {"default", "0.0.0.0/0", "::/0"} and "dev" in route}
    public = _public_interfaces(links, wan)
    if not public and (forwarding["ipv4"] or any(v6.values())):
        _network_fail("Forwarding is enabled but external ingress interfaces cannot be established")
    return public, forwarding


def _public_interfaces(links: list[dict[str, Any]], wan: set[str]) -> set[str]:
    names, private, masters = set(), set(), {}
    for link in links:
        if set(link) != {"name", "kind", "master", "up", "addresses"} or not isinstance(link["name"], str):
            _network_fail("Malformed interface scope")
        name = link["name"]
        if name in names or type(link["up"]) is not bool or not isinstance(link["addresses"], list):
            _network_fail("Repeated or malformed interface scope")
        names.add(name)
        addresses = [ipaddress.ip_interface(value).ip for value in link["addresses"]]
        if link["kind"] not in {"veth", "bridge", "loopback", "ether", "vlan", "bond"} and link["up"]:
            _network_fail(f"Interface {name} ({link['kind']}) has unclassified direct/overlay ingress")
        if (
            not link["up"]
            or link["kind"] == "loopback"
            or (
                name not in wan
                and link["kind"] == "bridge"
                and addresses
                and all(address.is_private or address.is_link_local for address in addresses)
            )
        ):
            private.add(name)
        masters[name] = link["master"]
    # Only local virtual members of a classified private bridge inherit its scope.
    # A standalone RFC1918 veth can be another externally routed cloud interface.
    private.update(link["name"] for link in links if link["kind"] == "veth" and link["master"] in private)
    if wan - names:
        _network_fail("A routed ingress interface is missing from the address inventory")
    public = names - private
    public.update(wan)
    for name, master in masters.items():
        if master is not None and (not isinstance(master, str) or master not in names):
            _network_fail(f"Interface {name} has an unknown bridge master")
    return _public_master_scope(public, masters, links)


def _public_master_scope(public: set[str], masters: dict[str, Any], links: list[dict[str, Any]]) -> set[str]:
    # Propagate through stacked masters independently of interface enumeration order.
    for _iteration in links:
        previous = set(public)
        for name, master in masters.items():
            if master in public or (name in public and master):
                public.update({name, master})
        if public == previous:
            break
    for link in links:
        if link["up"] and link["kind"] == "bridge" and link["name"] in public:
            _network_fail(
                f"Public bridge {link['name']} can expose backend Ethernet traffic independently of IP forwarding"
            )
    return public


def _network_options(words: list[str]) -> dict[str, str]:
    result = {}
    index = 0
    while index < len(words):
        negate = words[index] == "!"
        index += int(negate)
        if index + 1 >= len(words):
            _network_fail("A packet rule has an incomplete condition")
        key, value = words[index : index + 2]
        index += 2
        if key == "-m":
            if value not in {
                "tcp",
                "udp",
                "conntrack",
                "state",
                "icmp",
                "icmp6",
                "hl",
                "comment",
                "addrtype",
                "limit",
                "multiport",
            }:
                _network_fail("A packet rule uses an unclassified matching module: " + value)
            continue
        if key == "--comment":
            continue
        if negate and key not in {"-i", "-o"}:
            _network_fail("A packet rule uses unclassified negation")
        if key in result:
            _network_fail("A packet rule repeats a condition")
        result[key] = ("!" if negate else "") + value
    return result


def _interface_matches(options: dict[str, str], interface: str) -> bool:
    wanted = options.get("-i")
    if wanted is None:
        return True
    negate = wanted.startswith("!")
    wanted = wanted.lstrip("!")
    matches = interface.startswith(wanted[:-1]) if wanted.endswith("+") else interface == wanted
    return not matches if negate else matches


def _web_constraint(conditions: list[dict[str, str]]) -> bool:
    if not any(item.get("-p") in {"tcp", "6"} for item in conditions):
        return False
    return any(
        key in item and bool(set(item[key].split(","))) and set(item[key].split(",")) <= {"80", "443"}
        for item in conditions
        for key in ("--dport", "--dports")
    )


def _qualify_packet_graph(saved: str, public: set[str], *, nat: bool, ipv6: bool) -> None:
    chains = _chains(saved)
    root = "PREROUTING" if nat else "FORWARD"
    if nat and not chains:
        return  # Successful native save reported no NAT table/rules.
    if root not in chains:
        _network_fail("Missing " + root + " packet policy")
    if not nat and not any(line.startswith(":FORWARD DROP ") for line in saved.splitlines()):
        _network_fail("FORWARD has no independently proven deny baseline")
    for interface in public:
        pending: list[tuple[str, list[dict[str, str]], frozenset[str]]] = [(root, [], frozenset())]
        while pending:
            chain, inherited, visited = pending.pop()
            if chain in visited:
                _network_fail("A public packet policy contains a jump cycle")
            for rule in chains[chain]:
                try:
                    target, words = _jump(rule)
                except ValidationError:
                    _network_fail("Unclassified jump: -A " + chain + " " + " ".join(rule))
                if target in {"DROP", "REJECT", "RETURN", "LOG", "NFLOG"}:
                    continue
                options = _network_options(words)
                if not _interface_matches(options, interface):
                    continue
                conditions = [*inherited, options]
                if target in chains:
                    pending.append((target, conditions, visited | {chain}))
                    continue
                text = f"{interface}: -A {chain} " + " ".join(rule)
                _qualify_public_grant(target, conditions, text, nat=nat, ipv6=ipv6)


def _qualify_public_grant(target: str, conditions: list[dict[str, str]], text: str, *, nat: bool, ipv6: bool) -> None:
    if nat:
        if target not in {"DNAT", "REDIRECT", "ACCEPT"} or not _web_constraint(conditions):
            _network_fail(text)
        return
    if target != "ACCEPT":
        _network_fail(text)
    states = [item.get("--ctstate", item.get("--state", "")) for item in conditions]
    if any(value and set(value.split(",")) <= {"RELATED", "ESTABLISHED"} for value in states):
        return
    if _web_constraint(conditions) or any(
        item.get("--ctstate") == "DNAT" or item.get("--ctstatus") == "DNAT" for item in conditions
    ):
        return  # Every public DNAT origin was separately restricted to web ports.
    try:
        merged = {key: value for item in conditions for key, value in item.items()}
        _accept([word for pair in merged.items() for word in pair], set(), ipv6)
    except ValidationError:
        _network_fail(text)


def _native_hook(chain: dict[str, Any]) -> tuple[tuple[str, ...], str | None]:
    if any(not isinstance(chain.get(field), str) for field in ("family", "table", "name")):
        _network_fail("Malformed native chain identity")
    key = tuple(str(chain[field]) for field in ("family", "table", "name"))
    if "hook" not in chain:
        return key, None
    if chain.get("family") not in {"ip", "ip6", "inet"} or chain["hook"] not in {
        "input",
        "forward",
        "prerouting",
        "output",
        "postrouting",
    }:
        _network_fail("Unclassified bridge/early ingress hook: " + str(key))
    if chain.get("table") in {"filter", "nat"} and chain.get("family") in {"ip", "ip6"}:
        expected = (
            {"INPUT": "input", "FORWARD": "forward", "OUTPUT": "output"}
            if chain["table"] == "filter"
            else {"PREROUTING": "prerouting", "INPUT": "input", "OUTPUT": "output", "POSTROUTING": "postrouting"}
        )
        if expected.get(str(chain["name"])) != chain["hook"]:
            _network_fail("Unclassified compatibility-table hook: " + str(key))
    if chain["hook"] == "input" and key not in {("ip", "filter", "INPUT"), ("ip6", "filter", "INPUT")}:
        _network_fail("Unclassified native INPUT hook: " + str(key))
    return key, str(chain["hook"])


def _qualify_native_network(rows: list[str]) -> None:
    entries = _network_json(rows, "PRAHO_NETWORK_NATIVE")
    hooks = {}
    for entry in entries:
        if "chain" in entry:
            chain = entry["chain"]
            if not isinstance(chain, dict):
                _network_fail("Malformed native hook")
            key, hook = _native_hook(chain)
            hooks[key] = hook
        elif "rule" not in entry:
            _network_fail("Unclassified native flowtable or packet facility")
    for entry in entries:
        if "rule" not in entry:
            continue
        rule = entry["rule"]
        key = tuple(rule.get(field) for field in ("family", "table", "chain"))
        hook = hooks.get(key)
        allowed = {"match", "counter", "accept", "drop", "reject", "return", "log"}
        if hook in {"postrouting", "output"}:
            allowed |= {"snat", "masquerade"}
        if (
            hook is None
            or not isinstance(rule.get("expr"), list)
            or any(not isinstance(item, dict) or set(item) - allowed for item in rule["expr"])
        ):
            _network_fail("Unclassified native packet rule: " + json.dumps(rule, sort_keys=True)[:450])


def verify_network_ingress(firewall: list[str]) -> None:
    """Qualify ingress without changing or blanket-rejecting unrelated NAT/routing policy."""
    try:
        if firewall.count("PRAHO_NETWORK_V2") != 1 or firewall.count("PRAHO_NETWORK_COMPLETE") != 1:
            observed = [
                row.removeprefix("Network preparation required: ")
                for row in firewall
                if row.startswith("Network preparation required: ")
            ]
            _network_fail(
                "; ".join(observed[:3])
                or "Current complete NAT/FORWARD/native-hook/address/route inspection is required"
            )
        backends = _network_json(firewall, "PRAHO_XTABLES_BACKEND")
        if (
            len(backends) != 1
            or set(backends[0]) != {"ip", "ip6"}
            or any(value not in {"nf_tables", "legacy"} for value in backends[0].values())
        ):
            _network_fail("The IPv4/IPv6 native backend and coexisting nftables rules require inspection")
        public, forwarding = _network_interfaces(firewall)
        _qualify_native_network(firewall)
        for family, ipv6 in (("IPV4", False), ("IPV6", True)):
            _qualify_packet_graph(_network_section(firewall, family, "NAT"), public, nat=True, ipv6=ipv6)
            saved = _network_section(firewall, family, "FILTER")
            enabled = any(cast("dict[str, int]", forwarding["ipv6"]).values()) if ipv6 else forwarding["ipv4"]
            if enabled:
                _qualify_packet_graph(saved, public, nat=False, ipv6=ipv6)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
        _network_fail("Malformed network topology evidence: " + str(error)[:120])


def network_preparation(firewall: list[str]) -> list[str]:
    try:
        verify_network_ingress(firewall)
    except ValidationError as error:
        return error.messages
    return []


def _verify_principals(principals: list[dict[str, str]], username: str, cidrs: list[str]) -> None:
    found = set()
    for principal in principals:
        if principal["name"].startswith("group:"):
            continue
        found.add(principal["name"])
        attributes = dict(part.split("=", 1) for part in principal["access"].split(";"))
        actual = set(attributes.get("allow", "").split())
        wanted = set(cidrs) if principal["name"] == username else {"127.0.0.1/32"}
        if actual != wanted or attributes.get("deny") != "":
            _fail()
    if not {username, "root"} <= found:
        _fail()


def _verify_services(services: list[str]) -> None:
    required = {"Native feature webmin: No", "Native default webmin: No", "Customer Webmin domains: 0"}
    required.update("Native feature " + feature + ": Yes" for feature in WEB_ONLY_VIRTUALMIN_FEATURES)
    if not required <= set(services):
        _fail()
    allowed_defaults = {"Native default " + feature + ": Yes" for feature in WEB_ONLY_VIRTUALMIN_FEATURES}
    if any(
        line.startswith("Native default ") and line.endswith(": Yes") and line not in allowed_defaults
        for line in services
    ):
        _fail()
    if any(
        " install ok installed " in line and line.split()[0].startswith(("fail2ban", "usermin", "proftpd"))
        for line in services
    ):
        _fail()


def _verify_listeners(listeners: list[str]) -> None:
    for line in listeners:
        fields = line.split()
        if len(fields) < MIN_SOCKET_FIELDS or fields[0] not in {"tcp", "udp"}:
            _fail()
        address, port = fields[4].rsplit(":", 1)
        address = address.strip("[]").split("%", 1)[0]
        # This compares listener evidence; it does not open or bind a socket.
        loopback = address not in {"*", "0.0.0.0", "::"} and ipaddress.ip_address(address).is_loopback  # nosec B104 - reject wildcard evidence before checking loopback.
        if fields[0] == "tcp" and (port in {"80", "443", "9876", "10000"} or (loopback and port in LOOPBACK_TCP_PORTS)):
            continue
        if fields[0] == "udp" and ((loopback and port == "53") or port in {"68", "546"}):
            continue
        _fail()
    listening_ports = {line.split()[4].rsplit(":", 1)[1] for line in listeners if line.startswith("tcp ")}
    if not {"80", "9876", "10000"} <= listening_ports:
        _fail()


def _verify_firewall(firewall: list[str], cidrs: list[str]) -> None:
    if not {"Status: active", "PRAHO_NFT_INPUT_INSPECTED"} <= set(firewall):
        _fail()
    if any(
        line.startswith("NFT input chain: ")
        and line not in {"NFT input chain: ip:filter:INPUT", "NFT input chain: ip6:filter:INPUT"}
        for line in firewall
    ):
        _fail()
    for family, ipv6 in (("IPV4", False), ("IPV6", True)):
        start, end = f"PRAHO_{family}_FILTER_BEGIN", f"PRAHO_{family}_FILTER_END"
        if firewall.count(start) != 1 or firewall.count(end) != 1 or firewall.index(start) >= firewall.index(end):
            _fail()
        verify_filter("\n".join(firewall[firewall.index(start) + 1 : firewall.index(end)]), cidrs, ipv6=ipv6)


def _ssh_fail() -> NoReturn:
    raise ValidationError(
        _("Effective SSH authentication or restricted operator tunnel policy is incomplete or unreviewed.")
    )


def _ssh_rows(services: list[str]) -> dict[str, list[object]]:
    rows: dict[str, list[object]] = defaultdict(list)
    for line in services:
        if not line.startswith("PRAHO_SSH_"):
            continue
        tag, separator, payload = line.partition(" ")
        if not separator or tag not in {
            "PRAHO_SSH_" + name for name in ("GLOBAL", "ROOT", "TUNNEL", "ACCOUNT", "KEYS", "KEY", "CONFIG", "STARTUP")
        }:
            _ssh_fail()
        try:
            rows[tag.removeprefix("PRAHO_SSH_")].append(json.loads(payload))
        except (ValueError, TypeError) as error:
            raise ValidationError(_("SSH policy evidence is malformed.")) from error
    return rows


def _ssh_single(rows: dict[str, list[object]], name: str) -> dict[str, object]:
    values = rows.get(name, [])
    if len(values) != 1 or not isinstance(values[0], dict):
        _ssh_fail()
    return cast("dict[str, object]", values[0])


def _verify_ssh_context(rows: dict[str, list[object]], name: str) -> list[str]:
    projection = _ssh_single(rows, name)
    # OpenSSH 10 uses the modern spelling; earlier supported releases print its alias.
    if projection.get("permitrootlogin") == ["prohibit-password"]:
        projection = {**projection, "permitrootlogin": ["without-password"]}
    expected = dict(SSH_BASELINE)
    if name == "TUNNEL":
        expected.update(
            allowtcpforwarding=["local"], forcecommand=["/bin/false"], permittty=["no"], permitopen=["127.0.0.1:10000"]
        )
    files = projection.get("authorizedkeysfile")
    if files not in ([".ssh/authorized_keys"], [".ssh/authorized_keys .ssh/authorized_keys2"]):
        _ssh_fail()
    if {key: value for key, value in projection.items() if key != "authorizedkeysfile"} != expected:
        _ssh_fail()
    return cast("list[str]", files)[0].split()


def verify_ssh_policy(services: list[str], expected_operator_fingerprints: list[str] | None) -> None:
    """Require effective auth/forwarding policy and the exact separately reviewed tunnel key set."""
    if (
        not isinstance(expected_operator_fingerprints, list)
        or not 1 <= len(expected_operator_fingerprints) <= MAX_OPERATOR_KEYS
        or any(
            not isinstance(value, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value)
            for value in expected_operator_fingerprints
        )
        or len(set(expected_operator_fingerprints)) != len(expected_operator_fingerprints)
    ):
        _ssh_fail()
    rows = _ssh_rows(services)
    global_files = _verify_ssh_context(rows, "GLOBAL")
    if _verify_ssh_context(rows, "ROOT") != global_files:
        _ssh_fail()
    key_files = _verify_ssh_context(rows, "TUNNEL")
    startup = _ssh_single(rows, "STARTUP")
    if (
        key_files != global_files
        or _ssh_single(rows, "CONFIG") != {"sha256": SSH_CONFIG_DIGESTS[" ".join(key_files)]}
        or set(startup) != {"canonical"}
        or startup["canonical"] is not True
    ):
        _ssh_fail()
    account = _ssh_single(rows, "ACCOUNT")
    if (
        set(account) != {"present", "name", "uid", "gid", "home", "shell"}
        or account.get("present") is not True
        or account.get("name") != "praho-webmin-tunnel"
        or any(type(account.get(key)) is not int or not 0 < cast("int", account[key]) < 2**32 for key in ("uid", "gid"))
        or account.get("home") != "/home/praho-webmin-tunnel"
        or not isinstance(account.get("shell"), str)
        or account.get("shell") not in {"/usr/sbin/nologin", "/sbin/nologin"}
    ):
        _ssh_fail()
    if _ssh_single(rows, "KEYS") != {"status": "complete", "files": key_files}:
        _ssh_fail()
    actual = []
    for key in rows.get("KEY", []):
        if (
            not isinstance(key, dict)
            or set(key) != {"fingerprint", "options"}
            or not isinstance(key["fingerprint"], str)
            or not isinstance(key["options"], list)
            or any(not isinstance(option, str) for option in key["options"])
            or sorted(key["options"]) != TUNNEL_KEY_OPTIONS
        ):
            _ssh_fail()
        actual.append(key["fingerprint"])
    if sorted(actual) != sorted(expected_operator_fingerprints):
        _ssh_fail()


def verify_evidence(
    evidence: dict[str, object],
    username: str,
    cidrs: list[str],
    *,
    expected_operator_fingerprints: list[str] | None = None,
) -> None:
    """Require native principal, service, listener and effective dual-stack firewall proof."""
    _evidence_digest(evidence)
    verify_network_ingress(cast("list[str]", evidence["firewall"]))
    if username == "root" or evidence["versions"] != {"webmin": "2.670", "virtualmin": "8.3.0"}:
        _fail()
    _verify_principals(cast("list[dict[str, str]]", evidence["principals"]), username, cidrs)
    _verify_services(cast("list[str]", evidence["services"]))
    _verify_listeners(cast("list[str]", evidence["listeners"]))
    _verify_firewall(cast("list[str]", evidence["firewall"]), cidrs)
    verify_ssh_policy(cast("list[str]", evidence["services"]), expected_operator_fingerprints)
