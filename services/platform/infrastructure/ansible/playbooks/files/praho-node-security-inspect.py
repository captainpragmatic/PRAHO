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
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from uuid import UUID, uuid4

LIMIT = 131072
TUNNEL_HOME = Path("/home/praho-webmin-tunnel")
GATEWAY_HOME = Path("/home/praho-crowdsec")
BASE_PROFILE = "virtualmin-web-only-v2"
CROWDSEC_PROFILE = "virtualmin-web-only-v2+crowdsec-v1"
GATEWAY_COMMAND = "sudo -n /usr/local/libexec/praho-crowdsec-gateway"
CROWDSEC_TABLES = {"ip": "praho_crowdsec4", "ip6": "praho_crowdsec6"}
CROWDSEC_UNIT_SHA256 = {
    "crowdsec.service": "ec110a27de1ceaa991dd07bbe2cff69413b5c1f7bafd73870a98cb6a77e335ab",
    "crowdsec-firewall-bouncer.service": "1c459fdc032edf948d2e97eae4ca1160c093f234898c1fb14dcf641fe9fb26f5",
}
BASE_ARGUMENT_COUNT = 3
EXTENSION_ARGUMENT_COUNT = 5
CROWDSEC_FILES = (
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
)
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
        "dpkg",
        "iptables-save",
        "ip6tables-save",
        "virtualmin",
        "nft",
        "ip",
        "/usr/sbin/sshd",
        "/usr/bin/crowdsec",
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


def inspect(
    identity: str, profile: str = BASE_PROFILE, helper_sha256: str = "", lock_sha256: str = ""
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("Invalid connection identity")
    if profile not in {BASE_PROFILE, CROWDSEC_PROFILE}:
        raise ValueError("Unsupported selected security profile")
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
        "services": sorted(
            services
            + packages
            + inspect_ssh(profile)
            + (inspect_crowdsec(helper_sha256, lock_sha256) if profile == CROWDSEC_PROFILE else [])
        ),
        "firewall": inspect_firewall(profile),
        "proposed_changes": proposed,
    }


def _ssh_projection(output: str, *, profile: str = BASE_PROFILE) -> dict[str, list[str]]:
    """Never publish arbitrary command arguments, file paths or other sshd values."""
    result: dict[str, list[str]] = {}
    for line in output.splitlines():
        name, separator, value = line.partition(" ")
        if not separator:
            continue
        if name == "disableforwarding" and profile == CROWDSEC_PROFILE:
            result.setdefault(name, []).append(value if value in {"yes", "no"} else "unreviewed")
            continue
        if name not in SSH_OPTION_VALUES:
            continue
        allowed = (
            value in SSH_OPTION_VALUES[name]
            or (name == "port" and value.isdigit() and 0 < int(value) <= MAX_SSH_PORT)
            or (profile == CROWDSEC_PROFILE and name == "forcecommand" and value == GATEWAY_COMMAND)
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


def _check_key_paths(account: pwd.struct_passwd, files: list[str], *, gateway: bool = False) -> None:
    home = GATEWAY_HOME if gateway else TUNNEL_HOME
    for path in [home, home / ".ssh", *(home / name for name in files)]:
        if path.is_symlink():
            raise ValueError("Symlink in tunnel key path")
        if not path.exists():
            continue
        status = path.stat()
        expected_kind = stat.S_ISDIR if path in {home, home / ".ssh"} else stat.S_ISREG
        if not expected_kind(status.st_mode):
            raise ValueError("Unexpected tunnel key path type")
        if status.st_uid not in ({0} if gateway else {0, account.pw_uid}) or status.st_mode & 0o022:
            raise ValueError("Unsafe tunnel key ownership or permissions")


def _tunnel_keys(account: pwd.struct_passwd, files: list[str], *, gateway: bool = False) -> list[str]:
    home = GATEWAY_HOME if gateway else TUNNEL_HOME
    tag = "GATEWAY_" if gateway else ""
    metadata = {"status": "complete", "files": files}
    rows = []
    if Path(account.pw_dir) != home or files not in (
        [".ssh/authorized_keys"],
        [".ssh/authorized_keys", ".ssh/authorized_keys2"],
    ):
        return [_ssh_row(tag + "KEYS", {"status": "unreviewed", "files": []})]
    try:
        _check_key_paths(account, files, gateway=gateway)
        for name in files:
            path = home / name
            if not path.exists():
                continue
            with path.open("rb") as source:
                content = source.read(LIMIT + 1)
            if len(content) > LIMIT:
                raise ValueError("Tunnel key file exceeds inspection limit")
            for line in content.decode().splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    rows.append(_ssh_row(tag + "KEY", _authorized_key(line)))
                if len(rows) > MAX_SSH_KEYS:
                    raise ValueError("Too many tunnel keys")
    except (OSError, ValueError, StopIteration, UnicodeError):
        metadata["status"] = "unreviewed"
        rows = []
    return [_ssh_row(tag + "KEYS", metadata), *rows]


def inspect_ssh(profile: str = BASE_PROFILE) -> list[str]:
    """Read effective policy for the current pinned connection and both named principals."""
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) != SSH_CONNECTION_FIELDS:
        return [_ssh_row("KEYS", {"status": "unavailable", "files": []})]
    peer, local = str(ipaddress.ip_address(connection[0])), str(ipaddress.ip_address(connection[2]))
    port = int(connection[3])
    if not 0 < port <= MAX_SSH_PORT:
        raise ValueError("Invalid inspection SSH connection")
    rows = [_ssh_row("GLOBAL", _ssh_projection(command(["/usr/sbin/sshd", "-T"]), profile=profile))]
    tunnel: dict[str, list[str]] = {}
    for tag, user in (("ROOT", "root"), ("TUNNEL", "praho-webmin-tunnel")):
        context = f"user={user},host={peer},addr={peer},laddr={local},lport={port}"
        projected = _ssh_projection(command(["/usr/sbin/sshd", "-T", "-C", context]), profile=profile)
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
    if profile == CROWDSEC_PROFILE:
        context = f"user=praho-crowdsec,host={peer},addr={peer},laddr={local},lport={port}"
        projection = _ssh_projection(command(["/usr/sbin/sshd", "-T", "-C", context]), profile=profile)
        rows.append(_ssh_row("GATEWAY", projection))
        try:
            gateway = pwd.getpwnam("praho-crowdsec")
        except KeyError:
            return [*rows, _ssh_row("GATEWAY_ACCOUNT", {"present": False})]
        rows.append(
            _ssh_row(
                "GATEWAY_ACCOUNT",
                {
                    "present": True,
                    "name": gateway.pw_name,
                    "uid": gateway.pw_uid,
                    "gid": gateway.pw_gid,
                    "home": str(GATEWAY_HOME) if gateway.pw_dir == str(GATEWAY_HOME) else "unreviewed",
                    "shell": gateway.pw_shell if gateway.pw_shell == "/bin/sh" else "unreviewed",
                },
            )
        )
        files = projection.get("authorizedkeysfile", [])
        rows += _tunnel_keys(gateway, files[0].split() if len(files) == 1 else [], gateway=True)
    return rows


def _root_file(path: Path, limit: int = LIMIT) -> bytes:
    for parent in [*path.parents, path]:
        status = parent.lstat()
        if stat.S_ISLNK(status.st_mode) or status.st_uid != 0 or status.st_mode & 0o022:
            raise ValueError("Unreviewed CrowdSec file ownership")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Unsupported CrowdSec file type")
        content = source.read(limit + 1)
    if len(content) > limit:
        raise ValueError("CrowdSec file exceeds inspection limit")
    return content


def canonical_crowdsec_service(unit: str, properties: dict[str, str]) -> bool:
    executable = "/usr/bin/crowdsec" if unit == "crowdsec.service" else "/usr/local/libexec/praho-crowdsec-bouncer"
    configuration = (
        "/etc/crowdsec/config.yaml"
        if unit == "crowdsec.service"
        else "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    )
    if unit not in {"crowdsec.service", "crowdsec-firewall-bouncer.service"}:
        return False
    fragments = (
        {"/lib/systemd/system/" + unit, "/usr/lib/systemd/system/" + unit}
        if unit == "crowdsec.service"
        else {"/etc/systemd/system/" + unit}
    )
    if (
        properties.get("FragmentPath") not in fragments
        or properties.get("FragmentSha256") != CROWDSEC_UNIT_SHA256[unit]
        or properties.get("DropInPaths") != "/etc/systemd/system/" + unit + ".d/praho.conf"
        or properties.get("EnvironmentFiles") != ""
        or properties.get("Type") != "notify"
    ):
        return False
    environment = shlex.split(properties.get("Environment", ""))
    if sorted(environment) != ["LANG=C", "LC_ALL=C"] and not (unit != "crowdsec.service" and not environment):
        return False
    for field, suffix in (("ExecStart", ""), ("ExecStartPre", " -t -error" if unit == "crowdsec.service" else " -t")):
        argv = executable + " -c " + configuration + suffix
        expected = (
            r"\{ path=" + re.escape(executable) + r" ; argv\[\]=" + re.escape(argv) + r" ; ignore_errors=no ; [^{}]* \}"
        )
        if not re.fullmatch(expected, properties.get(field, "")):
            return False
    return True


def _crowdsec_services_canonical() -> bool:
    for unit in ("crowdsec.service", "crowdsec-firewall-bouncer.service"):
        output = command(
            [
                "systemctl",
                "show",
                "--property=FragmentPath,DropInPaths,Environment,EnvironmentFiles,ExecStart,ExecStartPre,Type",
                unit,
            ]
        )
        properties: dict[str, str] = {}
        for line in output.splitlines():
            name, value = line.split("=", 1)
            if name in properties:
                return False
            properties[name] = value
        # systemctl omits empty list-valued properties on the supported native
        # host; nonempty EnvironmentFiles is always emitted and remains refused.
        properties.setdefault("EnvironmentFiles", "")
        fragments = (
            {"/lib/systemd/system/" + unit, "/usr/lib/systemd/system/" + unit}
            if unit == "crowdsec.service"
            else {"/etc/systemd/system/" + unit}
        )
        if properties.get("FragmentPath") not in fragments:
            return False
        fragment = Path(properties["FragmentPath"])
        if unit == "crowdsec.service" and str(fragment).startswith("/lib/") and Path("/lib").is_symlink():
            if Path("/lib").resolve(strict=True) != Path("/usr/lib"):
                return False
            fragment = Path("/usr/lib/systemd/system/") / unit
        properties["FragmentSha256"] = hashlib.sha256(_root_file(fragment)).hexdigest()
        if not canonical_crowdsec_service(unit, properties):
            return False
    return True


def _crowdsec_manifest_files(policy: dict, lock_sha256: str) -> set[str]:
    content = _root_file(Path("/etc/praho-crowdsec/artifacts.lock.json"))
    if hashlib.sha256(content).hexdigest() != lock_sha256 or policy["artifact_lock_sha256"] != lock_sha256:
        raise ValueError("Unreviewed artifact manifest")
    manifest = json.loads(content)
    leaves = {item["installed_path"] for item in manifest["hub"]["files"] if policy["host_kind"] in item["host_kinds"]}
    if any(
        not re.fullmatch(r"/etc/crowdsec/(?:parsers/s0[012]-[a-z]+|scenarios)/[a-zA-Z0-9_-]+\.ya?ml", path)
        for path in leaves
    ):
        raise ValueError("Unreviewed Hub leaf path")
    return set(CROWDSEC_FILES) | leaves


def _crowdsec_policy_files(config: dict, helper_sha256: str, lock_sha256: str) -> tuple[dict[str, str], str]:
    policy = config["policy"]
    if set(policy) != {
        "schema",
        "host_kind",
        "simulation",
        "protected_cidrs",
        "artifact_lock_sha256",
        "bouncer_binary_sha256",
        "managed_files",
    }:
        raise ValueError("Unsupported CrowdSec policy")
    if str(UUID(config["installation_id"])) != config["installation_id"]:
        raise ValueError("Unreviewed CrowdSec installation")
    if config["simulation"] != policy["simulation"] or config["protected_cidrs"] != policy["protected_cidrs"]:
        raise ValueError("Inconsistent CrowdSec policy")
    if not re.fullmatch(r"[0-9a-f]{64}", helper_sha256) or not re.fullmatch(r"[0-9a-f]{64}", lock_sha256):
        raise ValueError("Missing controller artifact identity")
    if hashlib.sha256(_root_file(Path("/usr/local/libexec/praho-crowdsec-gateway"))).hexdigest() != helper_sha256:
        raise ValueError("Unreviewed gateway helper")
    owned_files = _crowdsec_manifest_files(policy, lock_sha256)
    if set(policy["managed_files"]) != owned_files:
        raise ValueError("Unreviewed CrowdSec file set")
    actual_files = {name: hashlib.sha256(_root_file(Path(name))).hexdigest() for name in sorted(owned_files)}
    digest = hashlib.sha256(
        json.dumps(
            {**policy, "managed_files": actual_files}, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()
    if digest != config["configuration_digest"]:
        raise ValueError("Changed CrowdSec files")
    return actual_files, digest


def _gateway_health(config: dict, digest: str) -> dict:
    request = {
        "protocol": 1,
        "request_id": str(uuid4()),
        "installation_id": config["installation_id"],
        "configuration_digest": digest,
        "operation": "health",
        "payload": {},
    }
    result = subprocess.run(
        ["/usr/local/libexec/praho-crowdsec-gateway"],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode or len(result.stdout.encode()) > LIMIT:
        raise ValueError("Unqualified CrowdSec helper")
    health = json.loads(result.stdout)
    if any(
        health.get(key) != request[key]
        for key in ("protocol", "request_id", "installation_id", "configuration_digest", "operation")
    ):
        raise ValueError("Mismatched CrowdSec helper identity")
    return health


def _crowdsec_database_matches(config: dict) -> bool:
    status = Path("/var/lib/crowdsec/data/crowdsec.db").lstat()
    if (
        not stat.S_ISREG(status.st_mode)
        or {"device": status.st_dev, "inode": status.st_ino} != config["database_witness"]
    ):
        return False
    marker = "praho-installation-" + config["installation_id"]
    with closing(sqlite3.connect("file:/var/lib/crowdsec/data/crowdsec.db?mode=ro", uri=True, timeout=1)) as connection:
        return connection.execute("SELECT machine_id FROM machines WHERE machine_id=?", (marker,)).fetchall() == [
            (marker,)
        ]


def _simulation_bans_empty(policy: dict) -> bool | None:
    if not policy["simulation"]:
        return None
    for family, table in CROWDSEC_TABLES.items():
        bans = json.loads(command(["nft", "-j", "list", "set", family, table, "bans"]))
        if any(entry.get("set", {}).get("elem") for entry in bans["nftables"]):
            return False
    return True


def _crowdsec_runtime(config: dict, health: dict) -> dict:
    engine = command(["/usr/bin/crowdsec", "-version"])
    bouncer = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "crowdsec-firewall-bouncer.service"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return {
        "architecture": command(["dpkg", "--print-architecture"]).strip(),
        "engine_version": "1.8.2" if re.search(r"\bv1\.8\.2\b", engine) else "unreviewed",
        "engine_active": command(["systemctl", "is-active", "crowdsec.service"]).strip() == "active",
        "bouncer_active": bouncer.stdout.strip() == "active",
        "bouncer_binary_sha256": hashlib.sha256(
            _root_file(Path("/usr/local/libexec/praho-crowdsec-bouncer"), 67108864)
        ).hexdigest(),
        "database_matches": _crowdsec_database_matches(config),
        "simulation_bans_empty": _simulation_bans_empty(config["policy"]),
        "configuration_canonical": health["result"]["configuration"]["qualified"] is True,
        "services_canonical": _crowdsec_services_canonical(),
    }


def inspect_crowdsec(helper_sha256: str, lock_sha256: str) -> list[str]:
    """Only fixed secret-free files and approved summary fields leave the host."""
    try:
        content = _root_file(Path("/etc/praho-crowdsec/config.json"))
        config = json.loads(content)
        actual_files, digest = _crowdsec_policy_files(config, helper_sha256, lock_sha256)
        health = _gateway_health(config, digest)
        return [
            _network_row(
                "PRAHO_CROWDSEC_CONFIG",
                {
                    "configuration_digest": digest,
                    "configuration_sha256": hashlib.sha256(content).hexdigest(),
                    "installation_id": config["installation_id"],
                    "root_owned": True,
                },
            ),
            _network_row(
                "PRAHO_CROWDSEC_POLICY",
                {key: value for key, value in config["policy"].items() if key != "managed_files"},
            ),
            _network_row("PRAHO_CROWDSEC_RUNTIME", _crowdsec_runtime(config, health)),
            *[
                _network_row("PRAHO_CROWDSEC_FILE", {"path": name, "sha256": value, "root_owned": True})
                for name, value in actual_files.items()
            ],
        ]
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError):
        return ['PRAHO_CROWDSEC_ERROR {"status":"unreviewed"}']


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


def inspect_network(native: dict | None, profile: str = BASE_PROFILE) -> list[str]:  # noqa: C901, PLR0912, PLR0915 -- fixed bounded technical collection; no mutation or arbitrary commands
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
            if profile == CROWDSEC_PROFILE and len(entry) == 1:
                kind, value = next(iter(entry.items()))
                if (
                    isinstance(value, dict)
                    and value.get("family") in CROWDSEC_TABLES
                    and CROWDSEC_TABLES[value["family"]] == value.get("name" if kind == "table" else "table")
                ):
                    stable = _stable_native(entry)
                    if kind == "set" and value.get("name") == "bans":
                        stable["set"].pop("elem", None)
                    rows.append(_network_row("PRAHO_CROWDSEC_NFT", stable))
                    continue
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


def inspect_firewall(profile: str = BASE_PROFILE) -> list[str]:  # noqa: C901, PLR0912 -- fixed native address families and bounded incomplete-evidence fallback
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
            native = json.loads(
                command(["nft", "-j", *(["-t"] if profile == CROWDSEC_PROFILE else []), "list", "ruleset"])
            )
            if not isinstance(native, dict) or not isinstance(native.get("nftables"), list):
                raise ValueError("Native ruleset is incomplete")
            if profile == CROWDSEC_PROFILE:
                for family, table in CROWDSEC_TABLES.items():
                    protected = json.loads(command(["nft", "-j", "list", "set", family, table, "protected"]))
                    matches = [entry["set"] for entry in protected["nftables"] if "set" in entry]
                    if len(matches) != 1 or matches[0].get("family") != family or matches[0].get("table") != table:
                        raise ValueError("Incomplete CrowdSec protected membership")
                    native["nftables"] = [
                        {"set": matches[0]}
                        if entry.get("set", {}).get("family") == family
                        and entry["set"].get("table") == table
                        and entry["set"].get("name") == "protected"
                        else entry
                        for entry in native["nftables"]
                    ]
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
    return firewall + inspect_network(native, profile)


if __name__ == "__main__":
    if len(sys.argv) not in {2, BASE_ARGUMENT_COUNT, EXTENSION_ARGUMENT_COUNT}:
        raise ValueError("Expected connection identity and optional selected profile")
    payload = json.dumps(
        inspect(
            sys.argv[1],
            sys.argv[2] if len(sys.argv) >= BASE_ARGUMENT_COUNT else BASE_PROFILE,
            sys.argv[3] if len(sys.argv) == EXTENSION_ARGUMENT_COUNT else "",
            sys.argv[4] if len(sys.argv) == EXTENSION_ARGUMENT_COUNT else "",
        ),
        sort_keys=True,
    )
    if len(payload.encode()) > LIMIT:
        raise ValueError("Inspection exceeded the evidence limit")
    print(payload)
