"""Read-only, bounded inspection. No passwords or arbitrary native response hashes leave the node."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

LIMIT = 131072
TUNNEL_HOME = Path("/home/praho-webmin-tunnel")
MAX_SSH_KEYS = 128
MAX_SSH_PORT = 65535
MAX_DESCRIPTION_LENGTH = 2048
MAX_NETWORK_ROWS = 256
MAX_NETWORK_BYTES = 32768
SSH_CONNECTION_FIELDS = 4
SSH_WIRE_LENGTH_BYTES = 4
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_DEFAULTS = Path("/etc/default/ssh")
SSH_OPTION_VALUES = {
    "port": set(),
    "permitrootlogin": {"yes", "no", "without-password", "prohibit-password", "forced-commands-only"},
    **{
        name: {"yes", "no"}
        for name in (
            "pubkeyauthentication",
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "permitemptypasswords",
            "hostbasedauthentication",
            "strictmodes",
            "usedns",
            "allowagentforwarding",
            "x11forwarding",
            "gatewayports",
            "permituserenvironment",
            "permittty",
        )
    },
    "authenticationmethods": {"publickey", "any"},
    "allowtcpforwarding": {"yes", "no", "local", "remote"},
    "allowstreamlocalforwarding": {"yes", "no", "local", "remote"},
    "permittunnel": {"no", "yes", "point-to-point", "ethernet"},
    "authorizedkeysfile": {".ssh/authorized_keys", ".ssh/authorized_keys .ssh/authorized_keys2"},
    **{
        name: {"none"}
        for name in (
            "authorizedkeyscommand",
            "authorizedprincipalscommand",
            "authorizedprincipalsfile",
            "trustedusercakeys",
        )
    },
    "forcecommand": {"none", "/bin/false"},
    "permitopen": {"any", "none", "127.0.0.1:10000"},
}
PRINCIPALS = r"""
use strict; use warnings; use JSON::PP;
our ($no_acl_check, %gconfig); $no_acl_check = 1;
$ENV{'WEBMIN_CONFIG'} = '/etc/webmin'; $ENV{'WEBMIN_VAR'} = '/var/webmin';
chdir('/usr/share/webmin') or die "Webmin missing";
$0 = '/usr/share/webmin/praho-security-inspect';
require './web-lib.pl'; &init_config(); &foreign_require('acl', 'acl-lib.pl');
my @result;
foreach my $u (&acl::list_users()) {
    push @result, { name => $u->{'name'}, access =>
        'allow='.($u->{'allow'} // '').';deny='.($u->{'deny'} // '').
        ';modules='.join(' ', @{$u->{'modules'} || []}) };
}
foreach my $g (&acl::list_groups()) {
    push @result, { name => 'group:'.$g->{'name'}, access =>
        'members='.join(' ', @{$g->{'members'} || []}).
        ';modules='.join(' ', @{$g->{'modules'} || []}) };
}
print encode_json([sort { $a->{'name'} cmp $b->{'name'} } @result]);
"""


def command(argv: list[str]) -> str:
    """Fixed read-only commands only. Missing tooling is an incomplete inspection."""
    if not argv or argv[0] not in {
        "perl",
        "ss",
        "ufw",
        "systemctl",
        "dpkg-query",
        "iptables-save",
        "ip6tables-save",
        "virtualmin",
        "nft",
        "ip",
        "/usr/sbin/sshd",
    }:
        raise ValueError("Unknown inspection command")
    result = subprocess.run(  # noqa: S603 -- Fixed read-only allowlist and argv at call sites.
        argv, capture_output=True, text=True, timeout=20, check=False, env={**os.environ, "LC_ALL": "C"}
    )
    if result.returncode and not (argv[0] == "dpkg-query" and result.returncode == 1):
        raise ValueError(f"Inspection command failed: {argv[0]}")
    if len(result.stdout.encode()) > LIMIT:
        raise ValueError("Inspection command exceeded its output limit")
    return result.stdout


def versions() -> dict[str, str]:
    webmin = Path("/usr/share/webmin/version").read_text().strip()
    module = Path("/usr/share/webmin/virtual-server/module.info").read_text()
    match = re.search(r"(?m)^version=(\S+)$", module)
    if not match:
        raise ValueError("Cannot identify installed Virtualmin version")
    return {"webmin": webmin, "virtualmin": match.group(1)}


def inspect(identity: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("Invalid connection identity")
    principals = json.loads(command(["perl", "-e", PRINCIPALS]))
    services = command(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]).splitlines()
    packages = command(
        ["dpkg-query", "-W", "-f=${Package} ${Status} ${Version}\\n", "fail2ban", "proftpd*", "usermin"]
    ).splitlines()
    features = json.loads(command(["virtualmin", "list-features", "--json"]))
    for feature in features["data"]:
        services.append("Native feature " + feature["name"] + ": " + str(feature["values"]["enabled"][0]))
        services.append("Native default " + feature["name"] + ": " + str(feature["values"]["default"][0]))
    customer_logins = command(["virtualmin", "list-domains", "--with-feature", "webmin", "--name-only"]).splitlines()
    services.append("Customer Webmin domains: " + str(len(customer_logins)))
    proposed = [
        "Expose TCP 80/443 publicly; restrict SSH and Webmin to the reviewed administrative networks.",
        "Remove legacy public firewall rules, including removed administrative networks, for IPv4 and IPv6.",
        "Foreign INPUT policies and native nftables input hooks require reviewed manual preparation before conversion.",
        "Qualify every interface and secondary address, public NAT publication and directly routed IPv6 service before conversion; preserve unrelated private and outbound routing.",
        "Preserve loopback, DHCP and required ICMP/IPv6 control traffic; deny other inbound traffic.",
        "Stop public mail, DNS and FTP services after their dependencies have been evacuated.",
        "Remove fail2ban, ProFTPd and Usermin; disable Webmin UDP discovery.",
        "Disable Webmin access for all domain owners and remove it from defaults and templates.",
        "Remove ancillary features from new-domain defaults without deleting existing mail or DNS data.",
        "Persist and verify the dedicated API identity before restricting interactive administrators.",
        "Restrict interactive administrators to loopback; operators use the restricted SSH tunnel.",
        "Webmin and service reloads may interrupt connections. Access recovery restores firewall/SSH configuration; it does not recover removed services or data.",
    ]
    for hook in (Path("/etc/ufw/before.init"), Path("/etc/ufw/after.init")):
        if hook.exists():
            with hook.open("rb") as source:
                contents = source.read(LIMIT + 1)
            if len(contents) > LIMIT:
                raise ValueError("Firewall hook exceeds inspection limit")
            description = f"Firewall reload hook {hook}: sha256={hashlib.sha256(contents).hexdigest()}, executable={os.access(hook, os.X_OK)}"
            proposed.append(description)
            if os.access(hook, os.X_OK):
                proposed.append(
                    f"Disable execution of the reviewed firewall reload hook {hook} before applying policy."
                )
    return {
        "schema": 1,
        "identity": identity,
        "versions": versions(),
        "listeners": sorted(command(["ss", "-H", "-tuln"]).splitlines()),
        "principals": principals,
        "services": sorted(services + packages + inspect_ssh()),
        "firewall": inspect_firewall(),
        "proposed_changes": proposed,
    }


def _ssh_projection(output: str) -> dict[str, list[str]]:
    """Never publish arbitrary command arguments, file paths or other sshd values."""
    result: dict[str, list[str]] = {}
    for line in output.splitlines():
        name, separator, value = line.partition(" ")
        if name not in SSH_OPTION_VALUES or not separator:
            continue
        allowed = value in SSH_OPTION_VALUES[name] or (
            name == "port" and value.isdigit() and 0 < int(value) <= MAX_SSH_PORT
        )
        result.setdefault(name, []).append(value if allowed else "unreviewed")
    return result


def _ssh_row(tag: str, value: object) -> str:
    row = "PRAHO_SSH_" + tag + " " + json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(row) > MAX_DESCRIPTION_LENGTH:
        raise ValueError("SSH projection exceeds the technical description limit")
    return row


def canonical_ssh_digest(source: str) -> str:
    """Retain every effective directive and its order, while dropping presentation only."""
    lines = []
    for line in source.splitlines():
        words = shlex.split(line, comments=True)
        if words:
            lines.append(" ".join([words[0].lower(), *words[1:]]))
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def _bounded_ssh_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("SSH policy path is not a regular file")
        content = source.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise ValueError("SSH policy file exceeds the inspection limit")
    return content.decode()


def canonical_ssh_startup(properties: dict[str, str], options: str) -> bool:
    """Project the same vendor-service/empty-SSHD_OPTS adoption contract without raw environment values."""
    expected = {
        "FragmentPath": {"/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service"},
        "KillMode": {"process"},
        "DropInPaths": {""},
        "Environment": {""},
        "EnvironmentFiles": {"/etc/default/ssh (ignore_errors=yes)"},
        "ActiveState": {"active"},
    }
    if any(properties.get(key) not in values for key, values in expected.items()):
        return False
    if not re.match(
        r"^\{ path=/usr/sbin/sshd ; argv\[\]=/usr/sbin/sshd -D \$SSHD_OPTS ; ignore_errors=no ;",
        properties.get("ExecStart", ""),
    ):
        return False
    assignments = [
        line.strip() for line in options.splitlines() if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]
    return bool(assignments) and all(re.fullmatch(r"""SSHD_OPTS\s*=\s*(?:""|'')?\s*""", line) for line in assignments)


def inspect_ssh_files() -> list[str]:
    try:
        config = {"sha256": canonical_ssh_digest(_bounded_ssh_file(SSHD_CONFIG))}
    except (OSError, ValueError, UnicodeError):
        config = {"status": "unreviewed"}
    try:
        shown = command(
            [
                "systemctl",
                "show",
                "--property=FragmentPath,KillMode,DropInPaths,Environment,EnvironmentFiles,ExecStart,ActiveState",
                "ssh.service",
            ]
        )
        properties = dict(line.split("=", 1) for line in shown.splitlines())
        startup = canonical_ssh_startup(properties, _bounded_ssh_file(SSHD_DEFAULTS))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        startup = False
    return [_ssh_row("CONFIG", config), _ssh_row("STARTUP", {"canonical": startup})]


def _authorized_key(line: str) -> dict[str, object]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split, lexer.commenters = True, ""
    algorithms = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
    first = next(lexer)
    options = [] if first in algorithms else first.split(",")
    algorithm = first if first in algorithms else next(lexer)
    encoded = next(lexer)
    if algorithm not in algorithms:
        raise ValueError("Unrecognized tunnel key")
    public = base64.b64decode(encoded, validate=True)
    kind_length = int.from_bytes(public[:SSH_WIRE_LENGTH_BYTES], "big")
    kind_end = SSH_WIRE_LENGTH_BYTES + kind_length
    if public[SSH_WIRE_LENGTH_BYTES:kind_end] != algorithm.encode() or len(public) <= kind_end:
        raise ValueError("Tunnel key type differs from its wire encoding")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("=")
    allowed_options = {"restrict", "port-forwarding", "permitopen=127.0.0.1:10000"}
    return {
        "fingerprint": fingerprint,
        "options": sorted(options) if set(options) <= allowed_options else ["unreviewed"],
    }


def _check_key_paths(account: pwd.struct_passwd, files: list[str]) -> None:
    for path in [TUNNEL_HOME, TUNNEL_HOME / ".ssh", *(TUNNEL_HOME / name for name in files)]:
        if path.is_symlink():
            raise ValueError("Symlink in tunnel key path")
        if not path.exists():
            continue
        status = path.stat()
        expected_kind = stat.S_ISDIR if path in {TUNNEL_HOME, TUNNEL_HOME / ".ssh"} else stat.S_ISREG
        if not expected_kind(status.st_mode):
            raise ValueError("Unexpected tunnel key path type")
        if status.st_uid not in {0, account.pw_uid} or status.st_mode & 0o022:
            raise ValueError("Unsafe tunnel key ownership or permissions")


def _tunnel_keys(account: pwd.struct_passwd, files: list[str]) -> list[str]:
    metadata = {"status": "complete", "files": files}
    rows = []
    if Path(account.pw_dir) != TUNNEL_HOME or files not in (
        [".ssh/authorized_keys"],
        [".ssh/authorized_keys", ".ssh/authorized_keys2"],
    ):
        return [_ssh_row("KEYS", {"status": "unreviewed", "files": []})]
    try:
        _check_key_paths(account, files)
        for name in files:
            path = TUNNEL_HOME / name
            if not path.exists():
                continue
            with path.open("rb") as source:
                content = source.read(LIMIT + 1)
            if len(content) > LIMIT:
                raise ValueError("Tunnel key file exceeds inspection limit")
            for line in content.decode().splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    rows.append(_ssh_row("KEY", _authorized_key(line)))
                if len(rows) > MAX_SSH_KEYS:
                    raise ValueError("Too many tunnel keys")
    except (OSError, ValueError, StopIteration, UnicodeError):
        metadata["status"] = "unreviewed"
        rows = []
    return [_ssh_row("KEYS", metadata), *rows]


def inspect_ssh() -> list[str]:
    """Read effective policy for the current pinned connection and both named principals."""
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) != SSH_CONNECTION_FIELDS:
        return [_ssh_row("KEYS", {"status": "unavailable", "files": []})]
    peer, local = str(ipaddress.ip_address(connection[0])), str(ipaddress.ip_address(connection[2]))
    port = int(connection[3])
    if not 0 < port <= MAX_SSH_PORT:
        raise ValueError("Invalid inspection SSH connection")
    rows = [_ssh_row("GLOBAL", _ssh_projection(command(["/usr/sbin/sshd", "-T"])))]
    tunnel: dict[str, list[str]] = {}
    for tag, user in (("ROOT", "root"), ("TUNNEL", "praho-webmin-tunnel")):
        context = f"user={user},host={peer},addr={peer},laddr={local},lport={port}"
        projected = _ssh_projection(command(["/usr/sbin/sshd", "-T", "-C", context]))
        rows.append(_ssh_row(tag, projected))
        if tag == "TUNNEL":
            tunnel = projected
    rows += inspect_ssh_files()
    try:
        account = pwd.getpwnam("praho-webmin-tunnel")
    except KeyError:
        return [
            *rows,
            _ssh_row("ACCOUNT", {"present": False}),
            _ssh_row("KEYS", {"status": "unavailable", "files": []}),
        ]
    rows.append(
        _ssh_row(
            "ACCOUNT",
            {
                "present": True,
                "name": account.pw_name,
                "uid": account.pw_uid,
                "gid": account.pw_gid,
                "home": str(TUNNEL_HOME) if account.pw_dir == str(TUNNEL_HOME) else "unreviewed",
                "shell": account.pw_shell
                if account.pw_shell in {"/usr/sbin/nologin", "/sbin/nologin"}
                else "unreviewed",
            },
        )
    )
    filenames = tunnel.get("authorizedkeysfile", [])
    rows += _tunnel_keys(account, filenames[0].split() if len(filenames) == 1 else [])
    return rows


def _network_row(tag: str, value: object) -> str:
    row = tag + " " + json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(row) > MAX_DESCRIPTION_LENGTH:
        raise ValueError("A network fact exceeds the inspection limit")
    return row


def _stable_native(value: object) -> object:
    if isinstance(value, list):
        return [_stable_native(item) for item in value]
    if isinstance(value, dict):
        return {
            key: None if key == "counter" else _stable_native(item) for key, item in value.items() if key != "handle"
        }
    return value


def forwarding_flags() -> dict[str, object]:
    return {
        "ipv4": int(Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()),
        "ipv6": {
            path.parent.name: int(path.read_text().strip())
            for path in sorted(Path("/proc/sys/net/ipv6/conf").glob("*/forwarding"))
        },
    }


def _represented_native_rule(rule: dict, backends: dict[str, str]) -> bool:
    if backends.get(rule.get("family")) != "nf_tables" or rule.get("table") not in {"filter", "nat"}:
        return False
    allowed = {"match", "counter", "jump", "goto", "accept", "drop", "reject", "return", "log", "limit", "xt"}
    if rule["table"] == "nat":
        allowed |= {"dnat", "snat", "redirect", "masquerade"}
    for expression in rule.get("expr", []):
        if not isinstance(expression, dict) or set(expression) - allowed:
            return False
        if isinstance(expression.get("xt"), dict) and expression["xt"].get("type") == "target":
            represented_targets = {"LOG", "NFLOG", "REJECT"}
            if rule["table"] == "nat":
                represented_targets |= {"SNAT", "MASQUERADE", "DNAT", "REDIRECT"}
            if expression["xt"].get("name") not in represented_targets:
                return False
    return True


def inspect_network(native: dict | None) -> list[str]:  # noqa: C901, PLR0912 -- fixed read-only collection with bounded incomplete-evidence fallback
    """Keep unsafe or incomplete topology inspectable; qualification happens before any conversion."""
    rows = ["PRAHO_NETWORK_V2"]
    try:
        if native is None or not shutil.which("ip"):
            raise ValueError("Prepare iproute2 and nftables read-only inspection tools")
        rows.append(_network_row("PRAHO_FORWARDING", forwarding_flags()))
        links = json.loads(command(["ip", "-j", "-d", "link", "show"]))
        addresses = json.loads(command(["ip", "-j", "address", "show"]))
        if not isinstance(links, list) or not isinstance(addresses, list) or len(links) > MAX_SSH_KEYS:
            raise ValueError("Network interfaces are incomplete or exceed the bounded topology limit")
        names = {link["ifindex"]: link["ifname"] for link in links}
        for link in sorted(links, key=lambda item: item["ifname"]):
            address = next((item for item in addresses if item["ifname"] == link["ifname"]), None)
            if address is None:
                raise ValueError("Network addresses are incomplete")
            master = link.get("master")
            if isinstance(master, int):
                master = names.get(master, "unclassified")
            rows.append(
                _network_row(
                    "PRAHO_NETWORK_LINK",
                    {
                        "name": link["ifname"],
                        "kind": link.get("linkinfo", {}).get("info_kind", link.get("link_type", "unknown")),
                        "master": master,
                        "up": "UP" in link.get("flags", []),
                        "addresses": sorted(
                            str(ipaddress.ip_interface(str(item["local"]) + "/" + str(item["prefixlen"])))
                            for item in address.get("addr_info", [])
                            if item.get("family") in {"inet", "inet6"}
                        ),
                    },
                )
            )
        for family in ("4", "6"):
            routes = json.loads(command(["ip", "-" + family, "-j", "route", "show", "table", "all"]))
            if not isinstance(routes, list):
                raise ValueError("Network routes are incomplete")
            projected = [
                {key: item[key] for key in ("dst", "dev", "gateway", "table", "type", "nexthops") if key in item}
                for item in routes
            ]
            rows.extend(
                _network_row("PRAHO_NETWORK_ROUTE" + family, item)
                for item in sorted(projected, key=lambda item: json.dumps(item, sort_keys=True))
            )
        backends = {}
        for tool, family in (("iptables-save", "IPV4"), ("ip6tables-save", "IPV6")):
            if not shutil.which(tool):
                raise ValueError("Prepare complete IPv4 and IPv6 NAT inspection tools")
            backend = re.search(r"\((nf_tables|legacy)\)", command([tool, "--version"]))
            if backend is None:
                raise ValueError("The native packet-filter backend is unclassified")
            backends["ip" if family == "IPV4" else "ip6"] = backend[1]
            saved = [
                re.sub(r"\[\d+:\d+\]", "[0:0]", line)
                for line in command([tool, "-t", "nat"]).splitlines()
                if not line.startswith("#")
            ]
            if not saved:
                saved = ["*nat", "COMMIT"]  # A successful save of an absent native table has no rules.
            if any(len(line) > MAX_DESCRIPTION_LENGTH for line in saved):
                raise ValueError("An unclassified NAT rule exceeds the inspection limit")
            rows += [f"PRAHO_{family}_NAT_BEGIN", *saved, f"PRAHO_{family}_NAT_END"]
        rows.append(_network_row("PRAHO_XTABLES_BACKEND", backends))
        for entry in native["nftables"]:
            if "metainfo" in entry or "table" in entry:
                continue
            rule = entry.get("rule")
            # The native compatibility tables are already captured by exact saved rules;
            # retain their chain hooks too, so a nonstandard hook cannot hide there.
            if rule and _represented_native_rule(rule, backends):
                continue
            rows.append(_network_row("PRAHO_NETWORK_NATIVE", _stable_native(entry)))
        if len(rows) > MAX_NETWORK_ROWS or sum(len(line.encode()) for line in rows) > MAX_NETWORK_BYTES:
            raise ValueError("Network facts exceed the bounded topology limit")
        rows.append("PRAHO_NETWORK_COMPLETE")
    except (OSError, ValueError, KeyError, TypeError) as error:
        rows.append("Network preparation required: " + str(error)[:500])
    if len(rows) > MAX_NETWORK_ROWS or sum(len(line.encode()) for line in rows) > MAX_NETWORK_BYTES:
        rows = [
            "PRAHO_NETWORK_V2",
            "Network preparation required: Native topology exceeds bounded inspection; reduce or separately prepare its unclassified rules before conversion.",
        ]
    return rows


def inspect_firewall() -> list[str]:
    firewall = []
    if shutil.which("ufw"):
        firewall += command(["ufw", "status", "numbered"]).splitlines()
    else:
        firewall.append("UFW is not installed; hardening will install it only after approval.")
    for tool, family in (("iptables-save", "IPV4"), ("ip6tables-save", "IPV6")):
        if shutil.which(tool):
            try:
                saved = [
                    re.sub(r"\[\d+:\d+\]", "[0:0]", line)
                    for line in command([tool, "-t", "filter"]).splitlines()
                    if not line.startswith("#")
                ] or ["*filter", "COMMIT"]
            except ValueError:
                firewall.append("Network preparation required: Could not read " + family + " filter policy")
                continue
            firewall += [f"PRAHO_{family}_FILTER_BEGIN", *saved, f"PRAHO_{family}_FILTER_END"]
    native = None
    if shutil.which("nft"):
        try:
            native = json.loads(command(["nft", "-j", "list", "ruleset"]))
            if not isinstance(native, dict) or not isinstance(native.get("nftables"), list):
                raise ValueError("Native ruleset is incomplete")
            firewall.append("PRAHO_NFT_INPUT_INSPECTED")
            for entry in native["nftables"]:
                chain = entry.get("chain", {})
                if chain.get("hook") == "input":
                    firewall.append(
                        "NFT input chain: " + ":".join(str(chain.get(key, "")) for key in ("family", "table", "name"))
                    )
        except (ValueError, KeyError, TypeError, AttributeError):
            native = None
            firewall.append("Network preparation required: Could not read complete native nftables policy")
    return firewall + inspect_network(native)


if __name__ == "__main__":
    payload = json.dumps(inspect(sys.argv[1]), sort_keys=True)
    if len(payload.encode()) > LIMIT:
        raise ValueError("Inspection exceeded the evidence limit")
    print(payload)
