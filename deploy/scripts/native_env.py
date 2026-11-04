"""Decode native deployment configuration as data; never source it as shell code."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
CONNECTION_KEYS = (
    "PRAHO_SERVER_IP",
    "PRAHO_DEV_IP",
    "PRAHO_SSH_USER",
    "PRAHO_SSH_KEY",
    "PRAHO_SSH_PORT",
    "PRAHO_SSH_PUBLIC_KEYS_FILE",
    "PRAHO_DEPLOY_KNOWN_HOSTS_FILE",
    "PRAHO_SSH_ALLOWED_CIDRS",
)
ALLOWLIST_KEYS = (
    "PLATFORM_ALLOWED_CIDRS",
    "PRAHO_SSH_ALLOWED_CIDRS",
    "PRAHO_MONITORING_CIDRS",
    "PRAHO_PORTAL_API_SOURCE_CIDRS",
    "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS",
    "PRAHO_PLATFORM_SSH_ALLOWED_CIDRS",
    "PRAHO_PORTAL_SSH_ALLOWED_CIDRS",
)
LOOPBACK_CIDRS = ("127.0.0.1/32", "::1/128")
PORTAL_KEYS = frozenset(
    {
        "PORTAL_ID",
        "PORTAL_HMAC_SECRET",
        "PLATFORM_TO_PORTAL_WEBHOOK_SECRET",
        "CUSTOMER_VIEW_ENABLED",
        "PLATFORM_PUBLIC_ORIGIN",
        "PLATFORM_DOMAIN",
        "PORTAL_DOMAIN",
        "PLATFORM_API_TIMEOUT",
        "PLATFORM_API_TOTAL_BUDGET_SECONDS",
        "PLATFORM_API_AUTH_MIN_DURATION_SECONDS",
        "CSP_PROFILE",
        "CSP_REPORT_ONLY",
        "DJANGO_LOG_LEVEL",
        "TIME_ZONE",
        "BRAND_DIR",
        "PORTAL_GUNICORN_WORKER_CLASS",
        "PORTAL_GUNICORN_WORKERS",
        "PORTAL_GUNICORN_THREADS",
        "CROWDSEC_AUTH_EVENTS_ENABLED",
        "CROWDSEC_AUTH_PSEUDONYM_KEY",
        "CROWDSEC_AUTH_LOG_PATH",
        "SESSION_DB_PATH",
        "HSTS_POLICY",
        "ACME_EMAIL",
        "PLATFORM_ALLOWED_CIDRS",
        "PRAHO_MONITORING_CIDRS",
        "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS",
        "PRAHO_ADDRESS_IPV4_DOMAIN",
        "PRAHO_ADDRESS_IPV6_DOMAIN",
        "PRAHO_NATIVE_TOPOLOGY",
    }
)


def runtime_environments(values: dict[str, str], environment: str, mode: str) -> tuple[dict[str, str], dict[str, str]]:
    """Filter on the controller before a Portal host can see any configuration."""
    for name in ("STATIC_ROOT", "MEDIA_ROOT"):
        if path := values.get(name):
            if path == "/" or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path) or ".." in Path(path).parts:
                raise ValueError(f"{name} must be a safe absolute native filesystem path")
    key = values.get("PORTAL_DJANGO_SECRET_KEY", "")
    if not key or key == values.get("DJANGO_SECRET_KEY", ""):
        raise ValueError("Portal requires a distinct PORTAL_DJANGO_SECRET_KEY")
    auth_log_path = values.get("CROWDSEC_AUTH_LOG_PATH", "/var/log/praho/portal/portal-auth.jsonl")
    if values.get("CROWDSEC_AUTH_EVENTS_ENABLED", "false").lower() == "true" and (
        auth_log_path != "/var/log/praho/portal/portal-auth.jsonl"
    ):
        raise ValueError(
            "Enabled native detection requires the qualified Portal authentication log path "
            "/var/log/praho/portal/portal-auth.jsonl"
        )
    platform = dict(values)
    platform.update(
        {
            "DJANGO_SETTINGS_MODULE": f"config.settings.{environment}",
            "STATIC_ROOT": values.get("STATIC_ROOT") or "/opt/praho/static",
            "MEDIA_ROOT": values.get("MEDIA_ROOT") or "/opt/praho/media",
            "ALLOWED_HOSTS": values.get("ALLOWED_HOSTS")
            or f"{values['PLATFORM_DOMAIN']},{values['PORTAL_DOMAIN']},localhost,127.0.0.1",
            "PORTAL_PAYMENT_WEBHOOK_URL": f"https://{values['PORTAL_DOMAIN']}/order/payment/webhook/",
            "INTERNAL_SERVICE_ALLOWED_DOMAINS": values["PORTAL_DOMAIN"],
            "IPWARE_TRUSTED_PROXY_LIST": ",".join(LOOPBACK_CIDRS),
            "PLATFORM_TRUSTED_PROXY_CIDRS": ",".join(LOOPBACK_CIDRS),
            "PRAHO_NATIVE_TOPOLOGY": mode,
        }
    )
    portal = {key: value for key, value in values.items() if key in PORTAL_KEYS}
    portal.setdefault("CROWDSEC_AUTH_LOG_PATH", auth_log_path)
    portal.update(
        {
            "DJANGO_SECRET_KEY": key,
            "PORTAL_DJANGO_SECRET_KEY": key,
            "DJANGO_SETTINGS_MODULE": f"config.settings.{environment}",
            "ALLOWED_HOSTS": f"{values['PORTAL_DOMAIN']},localhost,127.0.0.1",
            "PLATFORM_API_SECRET": values.get("PLATFORM_API_SECRET") or values.get("HMAC_SECRET", ""),
            "PLATFORM_API_BASE_URL": f"https://{values['PLATFORM_DOMAIN']}/api"
            if mode == "split"
            else "http://127.0.0.1:8700/api",
            "PLATFORM_API_ALLOW_INSECURE_HTTP": "false" if mode == "split" else "true",
            "PORTAL_TRUSTED_PROXY_CIDRS": ",".join(LOOPBACK_CIDRS),
            "DJANGO_SECURE_SSL_REDIRECT": "false",
            "PRAHO_NATIVE_TOPOLOGY": mode,
        }
    )
    return platform, portal


@dataclass(frozen=True)
class NativeTarget:
    """SSH destinations are deliberately independent of public service addresses."""

    server: str
    user: str
    port: int
    identity: str
    known_hosts: str
    public_keys: str
    ssh_sources: str

    def connection(self) -> dict[str, object]:
        options = [
            "-F /dev/null",
            "-o StrictHostKeyChecking=yes",
            "-o BatchMode=yes",
            "-o PreferredAuthentications=publickey",
            "-o PasswordAuthentication=no",
            "-o KbdInteractiveAuthentication=no",
            "-o ControlMaster=no",
            "-o ControlPath=none",
            "-o ServerAliveInterval=30",
            "-o ServerAliveCountMax=4",
            "-o ConnectTimeout=10",
            f"-o HostKeyAlias={shlex.quote(self.server)}",
            f"-o UserKnownHostsFile={shlex.quote(self.known_hosts)}",
        ]
        if self.identity:
            options.append("-o IdentitiesOnly=yes")
        return {
            "ansible_host": self.server,
            "ansible_user": self.user,
            "ansible_port": self.port,
            "ansible_ssh_private_key_file": self.identity or None,
            "ansible_ssh_common_args": " ".join(options),
            "native_ssh_public_keys_file": self.public_keys,
            "native_ssh_known_hosts_file": self.known_hosts,
            "native_ssh_allowed_cidrs": self.ssh_sources,
        }


@dataclass(frozen=True)
class NativeTopology:
    mode: str
    platform: NativeTarget
    portal: NativeTarget
    # (hostname, exact set of unproxied ingress addresses); includes address-check hosts.
    origins: tuple[tuple[str, frozenset[str]], ...]

    def inventory(self) -> dict[str, object]:
        hosts = {"platform": self.platform.connection()}
        portal_name = "platform"
        if self.mode == "split":
            hosts["portal"] = self.portal.connection()
            portal_name = "portal"
        return {
            "all": {
                "children": {
                    "praho": {"hosts": hosts},
                    "praho_platform": {"hosts": {"platform": {}}},
                    "praho_portal": {"hosts": {portal_name: {}}},
                }
            }
        }

    def validate_dns(self, resolver: Callable[[str], set[str]]) -> None:
        for name, expected in self.origins:
            if not expected or resolver(name) != expected:
                raise ValueError(f"DNS ownership mismatch for {name}; direct unproxied origins are required")


def _target(values: dict[str, str], role: str, fallback: str) -> NativeTarget:
    prefix = f"PRAHO_{role.upper()}_"
    server = values.get(prefix + "SERVER") or fallback
    if not server or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.:-]*", server):
        raise ValueError(f"{prefix}SERVER must be an explicit SSH destination")
    settings = {
        key: values.get(prefix + key, values.get("PRAHO_" + key, ""))
        for key in (
            "SSH_USER",
            "SSH_PORT",
            "SSH_KEY",
            "DEPLOY_KNOWN_HOSTS_FILE",
            "SSH_PUBLIC_KEYS_FILE",
            "SSH_ALLOWED_CIDRS",
        )
    }
    try:
        port = int(settings["SSH_PORT"] or "9876")
    except ValueError:
        raise ValueError(f"{prefix}SSH_PORT must be between 1 and 65535") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{prefix}SSH_PORT must be between 1 and 65535")
    user = settings["SSH_USER"] or "root"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
        raise ValueError(f"{prefix}SSH_USER is invalid")
    return NativeTarget(
        server,
        user,
        port,
        settings["SSH_KEY"],
        settings["DEPLOY_KNOWN_HOSTS_FILE"],
        settings["SSH_PUBLIC_KEYS_FILE"],
        settings["SSH_ALLOWED_CIDRS"],
    )


def _domain(value: str, name: str) -> str:
    if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", value):
        raise ValueError(f"{name} must be a DNS hostname without scheme, path or port")
    return value.lower()


def normalize_topology(values: dict[str, str], environment: str) -> NativeTopology:
    """Normalize once on the controller; incomplete split configurations never fall back."""
    mode = values.get("PRAHO_NATIVE_TOPOLOGY", "split" if environment == "prod" else "combined")
    if mode not in {"split", "combined"}:
        raise ValueError("PRAHO_NATIVE_TOPOLOGY must be split or combined")
    validate_allowlists(values)
    legacy_targets = {values[key] for key in ("PRAHO_SERVER_IP", "PRAHO_DEV_IP") if values.get(key)}
    if len(legacy_targets) > 1:
        raise ValueError("Conflicting legacy server addresses")
    legacy = next(iter(legacy_targets), "")
    platform = _target(values, "platform", legacy if mode == "combined" else "")
    portal = _target(values, "portal", platform.server if mode == "combined" else "")
    if legacy and legacy != platform.server:
        raise ValueError("Conflicting legacy and per-role server addresses")
    if mode == "combined":
        if portal != platform:
            raise ValueError("Conflicting combined per-role SSH settings or server addresses")
        portal = platform
    elif portal.server == platform.server:
        raise ValueError("Split topology requires distinct targets")
    origins: list[tuple[str, frozenset[str]]] = []
    for role, target in (("platform", platform), ("portal", portal)):
        addresses = set()
        for family in (4, 6):
            key = f"PRAHO_{role.upper()}_PUBLIC_IPV{family}"
            address = values.get(key, "")
            if address:
                try:
                    parsed = ipaddress.ip_address(address)
                    if (
                        parsed.version != family
                        or parsed.is_unspecified
                        or parsed.is_loopback
                        or parsed.is_multicast
                        or parsed.is_link_local
                    ):
                        raise ValueError
                except ValueError:
                    raise ValueError(f"{key} must contain an ingress IPv{family} address") from None
                addresses.add(str(parsed))
        if not addresses and mode == "split":
            raise ValueError(f"Explicit {role} public ingress addresses are required")
        if not addresses:
            with suppress(ValueError):
                addresses.add(str(ipaddress.ip_address(target.server)))
        if domain := values.get(role.upper() + "_DOMAIN"):
            origins.append((_domain(domain, role.upper() + "_DOMAIN"), frozenset(addresses)))
        elif mode == "split":
            raise ValueError(f"{role.upper()}_DOMAIN is required")
    if mode == "split":
        for name in ("PRAHO_PORTAL_API_SOURCE_CIDRS", "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS"):
            if not values.get(name, "").strip():
                raise ValueError(f"{name} requires stable egress CIDRs")
        expected = f"https://{values['PLATFORM_DOMAIN']}/api"
        if values.get("PLATFORM_API_BASE_URL", expected) != expected or values.get(
            "PLATFORM_API_ALLOW_INSECURE_HTTP", "false"
        ).lower() not in {"false", "0", "no"}:
            raise ValueError("Split Portal API requires verified HTTPS without insecure overrides")
        callback = f"https://{values['PORTAL_DOMAIN']}/order/payment/webhook/"
        if values.get("PORTAL_PAYMENT_WEBHOOK_URL") and values["PORTAL_PAYMENT_WEBHOOK_URL"] != callback:
            raise ValueError("Split callback URL requires the configured Portal HTTPS origin")
    for name in ("PORTAL_TRUSTED_PROXY_CIDRS", "PLATFORM_TRUSTED_PROXY_CIDRS"):
        if name in values and set(values[name].replace(",", " ").split()) != set(LOOPBACK_CIDRS):
            raise ValueError(f"{name} must trust only local Caddy")
    v4, v6 = (values.get(f"PRAHO_ADDRESS_IPV{family}_DOMAIN", "") for family in (4, 6))
    if bool(v4) != bool(v6):
        raise ValueError("Address-check hostnames must be paired")
    if v4:
        portal_ips = origins[-1][1]
        for family, name in ((4, v4), (6, v6)):
            addresses = frozenset(address for address in portal_ips if ipaddress.ip_address(address).version == family)
            if not addresses:
                raise ValueError("Address-check hostnames require both Portal address families")
            origins.append((_domain(name, f"PRAHO_ADDRESS_IPV{family}_DOMAIN"), addresses))
    if len({name for name, _ in origins}) != len(origins):
        raise ValueError("Service and address-check hostnames must be distinct")
    return NativeTopology(mode, platform, portal, tuple(origins))


def resolve_release(repository: str, revision: str) -> str:
    """Peel annotated tags once; every host subsequently checks out this exact SHA."""
    if re.fullmatch(r"[a-fA-F0-9]{40}", revision):
        return revision.lower()
    if not revision or revision.startswith("-") or not re.fullmatch(r"[a-zA-Z0-9_./-]+", revision):
        raise ValueError("A valid release tag, branch or full SHA is required")
    result = subprocess.run(
        [
            shutil.which("git") or "git",
            "ls-remote",
            "--exit-code",
            repository,
            f"refs/tags/{revision}",
            f"refs/heads/{revision}",
            f"refs/tags/{revision}^{{}}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    refs = {ref: sha for sha, ref in (line.split() for line in result.stdout.splitlines())}
    sha = refs.get(
        f"refs/tags/{revision}^{{}}", refs.get(f"refs/tags/{revision}", refs.get(f"refs/heads/{revision}", ""))
    )
    if result.returncode or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("Requested release could not be resolved to a full commit SHA")
    if f"refs/heads/{revision}" in refs and f"refs/tags/{revision}" in refs:
        raise ValueError("Ambiguous release: both a tag and branch exist")
    return sha


def validate_release(repository: str, revision: str) -> None:
    """Fetch the pinned object on the controller and prove it is a commit, even for a supplied SHA."""
    if not re.fullmatch(r"[a-f0-9]{40}", revision) or repository.startswith("-"):
        raise ValueError("A full immutable commit and repository are required")
    git = shutil.which("git") or "git"
    with tempfile.TemporaryDirectory(prefix="praho-native-release-") as temporary:
        commands = (
            [git, "init", "--bare", "--quiet", temporary],
            [git, "--git-dir", temporary, "fetch", "--quiet", "--no-tags", "--depth=1", "--", repository, revision],
            [git, "--git-dir", temporary, "rev-parse", "FETCH_HEAD^{commit}"],
        )
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
            if result.returncode:
                raise ValueError("The pinned release is not an available commit in the configured repository")
        if result.stdout.strip() != revision:
            raise ValueError("The fetched commit differs from the pinned release")


def materialize_release(repository: str, revision: str, checkout: Path) -> None:
    """Rsync transports a clean, pinned checkout instead of the controller's working files."""
    git = shutil.which("git") or "git"
    commands = (
        [git, "init", "--quiet", str(checkout)],
        [git, "-C", str(checkout), "fetch", "--quiet", "--no-tags", "--depth=1", "--", repository, revision],
        [git, "-C", str(checkout), "checkout", "--quiet", "--detach", revision],
    )
    for command in commands:
        if subprocess.run(command, capture_output=True, check=False, timeout=60).returncode:
            raise ValueError("Cannot prepare the pinned release for rsync")
    # FETCH_HEAD can record the controller repository URL; targets need only the object and HEAD.
    (checkout / ".git/FETCH_HEAD").unlink(missing_ok=True)


def read_env(path: Path) -> dict[str, str]:
    """One assignment per line, last wins; single quotes preserve literal dollars/backticks."""
    values: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        key = match.group(1) if match else "assignment"
        try:
            if not match or "\x00" in line:
                raise ValueError
            raw = match.group(2).strip()
            if raw and raw[0] in "\"'" and raw[-1] != raw[0]:
                raise ValueError
            if not raw.startswith("'") and any(char in raw for char in ("$", "`")):
                raise ValueError
            if raw.startswith("#") or (not raw.startswith(("'", '"')) and re.search(r"\s+#", raw)):
                raise ValueError
            parts = shlex.split(raw, comments=False, posix=True)
            if len(parts) > 1:
                raise ValueError
            values[key] = parts[0] if parts else ""
        except ValueError:
            raise ValueError(
                f"line {number}:{key}: unsupported env syntax; quote values and use one assignment per line"
            ) from None
    validate_allowlists(values)
    return values


def validate_allowlists(values: dict[str, str]) -> None:
    """Allowlists hold canonical CIDRs and never the whole Internet."""
    for name in ALLOWLIST_KEYS:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in values.get(name, "").split():
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                raise ValueError(f"{name} must contain space-separated, canonical CIDRs") from None
            if network.prefixlen == 0:
                raise ValueError(f"{name} cannot allow the entire Internet")
            networks.append(network)
        for family in (4, 6):
            if any(
                network.prefixlen == 0
                for network in ipaddress.collapse_addresses(
                    network for network in networks if network.version == family
                )
            ):
                raise ValueError(f"{name} cannot collectively allow the entire Internet")


def systemd_env(values: dict[str, str]) -> str:
    """Quote for EnvironmentFile and the legacy maintenance cron's POSIX shell reader."""
    lines = []
    for key, value in values.items():
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        lines.append(f'{key}="{escaped}"\n')
    return "".join(lines)


def pgpass(values: dict[str, str]) -> str:
    """Escape libpq's colon/backslash separators without evaluating the credential."""
    fields = [
        values.get(key) or default
        for key, default in (
            ("DB_HOST", "localhost"),
            ("DB_PORT", "5432"),
            ("DB_NAME", "praho"),
            ("DB_USER", "praho"),
            ("DB_PASSWORD", ""),
        )
    ]
    return ":".join(field.replace("\\", "\\\\").replace(":", "\\:") for field in fields) + "\n"


def recover_ssh_port(connection: dict[str, str], environment: str) -> None:
    """Recover a completed cutover without weakening the original host-key trust."""
    port = int(connection.get("PRAHO_SSH_PORT", "9876"))
    if not 1 <= port <= 65535:
        raise ValueError("PRAHO_SSH_PORT must be between 1 and 65535")
    if port == 9876:
        return
    host = connection.get("PRAHO_DEV_IP" if environment == "dev" else "PRAHO_SERVER_IP", "")
    if not host:
        raise ValueError("An explicit server IP is required for SSH port recovery")
    try:
        with socket.create_connection((host, 9876), timeout=3):
            pass
    except (ConnectionRefusedError, TimeoutError):
        return
    known_hosts = connection.get("PRAHO_DEPLOY_KNOWN_HOSTS_FILE", "")
    if not known_hosts:
        raise ValueError("Port 9876 is reachable but no pinned known_hosts file was supplied")
    command = [
        shutil.which("ssh") or "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-p",
        "9876",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ConnectTimeout=10",
        "-o",
        f"HostKeyAlias={host}",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
    ]
    if identity := connection.get("PRAHO_SSH_KEY"):
        command += ["-o", "IdentitiesOnly=yes", "-i", identity]
    command += [f"{connection.get('PRAHO_SSH_USER', 'root')}@{host}", "/usr/bin/id -u"]
    proof = subprocess.run(command, capture_output=True, text=True, check=False, timeout=20)
    if proof.returncode != 0 or proof.stdout.strip() != "0":
        raise ValueError("Port 9876 rejected pinned root key access; refusing bootstrap-port fallback")
    connection["PRAHO_SSH_PORT"] = "9876"


def run_native(  # noqa: PLR0913 -- Keep the established launcher API while exposing the SSH-only operation.
    values: dict[str, str],
    path: Path,
    environment: str,
    *,
    fetch_backup: str | None,
    version: str,
    ssh_only: bool = False,
    caddy_only: bool = False,
    rollback: bool = False,
) -> int:
    """One controller topology and immutable release for all native operations."""
    connection_values = {
        key: value
        for key, value in os.environ.items()
        if key in CONNECTION_KEYS or key.startswith(("PRAHO_PLATFORM_", "PRAHO_PORTAL_"))
    }
    connection_values.update(values)
    # Per-role peer allowlists may accompany SSH overrides in the shell. Use
    # those same validated values when filtering each host's edge configuration.
    values = {**values, **{name: connection_values[name] for name in ALLOWLIST_KEYS if name in connection_values}}
    topology = normalize_topology(connection_values, environment)
    targets = []
    for target in dict.fromkeys((topology.platform, topology.portal)):
        if not target.known_hosts or not Path(target.known_hosts).is_file():
            raise ValueError("Every native target requires an existing pinned known_hosts file")
        if not target.public_keys or not Path(target.public_keys).is_file():
            raise ValueError("Every native target requires an approved SSH public keys file")
        if not target.ssh_sources:
            raise ValueError("Every native target requires PRAHO_SSH_ALLOWED_CIDRS")
        connection = {
            "PRAHO_SERVER_IP": target.server,
            "PRAHO_DEV_IP": target.server,
            "PRAHO_SSH_USER": target.user,
            "PRAHO_SSH_PORT": str(target.port),
            "PRAHO_SSH_KEY": target.identity,
            "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": target.known_hosts,
        }
        recover_ssh_port(connection, environment)
        targets.append(replace(target, port=int(connection["PRAHO_SSH_PORT"])))
    topology = replace(topology, platform=targets[0], portal=targets[-1])
    operation = "ssh" if ssh_only else "edge" if caddy_only else "backup" if fetch_backup is not None else "deploy"
    if rollback:
        operation = "rollback"
    method = values.get("DEPLOY_METHOD", "git")
    if method not in {"git", "rsync"} or (environment == "prod" and method != "git"):
        raise ValueError("Native production requires git; dev/staging support git or rsync")
    release = ""
    if operation in {"deploy", "rollback"}:
        validate_application_configuration(values, environment)
        revision = version or values.get(
            "PRAHO_VERSION" if environment == "prod" else "DEPLOY_BRANCH", "" if environment == "prod" else "staging"
        )
        release = resolve_release(
            values.get("PRAHO_GIT_REPO", "https://github.com/captainpragmatic/PRAHO.git"), revision
        )
        validate_release(values.get("PRAHO_GIT_REPO", "https://github.com/captainpragmatic/PRAHO.git"), release)
    if operation in {"deploy", "rollback", "edge"}:
        topology.validate_dns(resolve_addresses)
        if topology.mode == "split" and resolve_addresses(topology.platform.server) & resolve_addresses(
            topology.portal.server
        ):
            raise ValueError("Split SSH destinations resolve to the same host; distinct targets are required")
    local_controller = Path(sys.executable).with_name("ansible-playbook")
    controller = (
        str(local_controller)
        if local_controller.is_file()
        else (shutil.which("ansible-playbook") or "ansible-playbook")
    )
    with tempfile.TemporaryDirectory(prefix="praho-native-") as temporary:
        directory = Path(temporary)
        inventory = directory / "inventory.json"
        inventory.write_text(json.dumps(topology.inventory()), encoding="utf-8")
        parameters: dict[str, object] = {
            "praho_env": environment,
            "native_topology": topology.mode,
            "native_operation": operation,
            "native_coordinated": True,
            "deploy_method": method,
            "deploy_git_version": release,
            "praho_git_repo": values.get("PRAHO_GIT_REPO", "https://github.com/captainpragmatic/PRAHO.git"),
            "fetch_backup": fetch_backup or "false",
            "env_file_path": str(path),
            "native_journal_directory": str(directory),
            "native_operation_token": uuid.uuid4().hex,
            "native_operation_lock_directory": "/etc/praho-native-operation",
            "ansible_pipelining": True,
            "native_manage_swap": values.get("PRAHO_NATIVE_MANAGE_SWAP", "true").lower() not in {"false", "0", "no"},
        }
        if operation in {"deploy", "rollback"} and method == "rsync":
            checkout = directory / "source"
            materialize_release(str(parameters["praho_git_repo"]), release, checkout)
            parameters["native_source_directory"] = str(checkout) + "/"
        for name, parameter in (
            ("PRAHO_NATIVE_TLS_CERTIFICATE", "native_tls_certificate"),
            ("PRAHO_NATIVE_TLS_KEY", "native_tls_key"),
            ("PRAHO_NATIVE_UV_CACHE_DIRECTORY", "native_uv_cache_directory"),
        ):
            if value := values.get(name):
                if not re.fullmatch(r"/[a-zA-Z0-9_./-]+", value):
                    raise ValueError(f"{name} must be an absolute filesystem path")
                parameters[parameter] = value
        if bool(values.get("PRAHO_NATIVE_TLS_CERTIFICATE")) != bool(values.get("PRAHO_NATIVE_TLS_KEY")):
            raise ValueError("Explicit native TLS certificate and key must be paired")
        if operation in {"deploy", "rollback", "edge"}:
            platform, portal = runtime_environments(values, environment, topology.mode)
            for role, runtime in (("platform", platform), ("portal", portal)):
                runtime_file = directory / f"{role}.env"
                runtime_file.write_text(
                    "".join(f"{key}={shlex.quote(value)}\n" for key, value in runtime.items()), encoding="utf-8"
                )
                runtime_file.chmod(0o600)
                parameters[f"native_{role}_env_file"] = str(runtime_file)
        parameter_file = directory / "parameters.json"
        parameter_file.write_text(json.dumps(parameters), encoding="utf-8")
        command = [
            controller,
            "-i",
            str(inventory),
            "playbooks/native.yml",
            "-e",
            "@group_vars/all.yml",
            "-e",
            f"@{parameter_file}",
        ]
        interrupted = False
        try:
            result = subprocess.run(command, cwd=ROOT / "deploy/ansible", env=dict(os.environ), check=False).returncode
        except KeyboardInterrupt:
            result, interrupted = 130, True
        if (directory / "operation-acquired").is_file() or list(directory.glob("held-*")):
            recovered_targets = []
            for target in dict.fromkeys((topology.platform, topology.portal)):
                connection = {
                    "PRAHO_SERVER_IP": target.server,
                    "PRAHO_DEV_IP": target.server,
                    "PRAHO_SSH_PORT": str(target.port),
                    "PRAHO_SSH_USER": target.user,
                    "PRAHO_SSH_KEY": target.identity,
                    "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": target.known_hosts,
                }
                try:
                    recover_ssh_port(connection, environment)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    result = result or 1
                    print(
                        "A target's SSH recovery could not be verified; inspect its persistent holds using console access",
                        file=sys.stderr,
                    )
                recovered_targets.append(replace(target, port=int(connection["PRAHO_SSH_PORT"])))
            topology = replace(topology, platform=recovered_targets[0], portal=recovered_targets[-1])
            inventory.write_text(json.dumps(topology.inventory()), encoding="utf-8")
        if (result or interrupted) and operation in {"deploy", "rollback"} and list(directory.glob("held-*")):
            recovery_command = [*command]
            recovery_command[recovery_command.index("playbooks/native.yml")] = "playbooks/native-hold.yml"
            recovery = subprocess.run(recovery_command, cwd=ROOT / "deploy/ansible", env=dict(os.environ), check=False)
            print(
                f"Native {operation} failed at pinned SHA {release}; maintenance recovery exit={recovery.returncode}",
                file=sys.stderr,
            )
        if (directory / "operation-acquired").is_file():
            unlock_command = [*command]
            unlock_command[unlock_command.index("playbooks/native.yml")] = "playbooks/native-unlock.yml"
            unlocked = subprocess.run(unlock_command, cwd=ROOT / "deploy/ansible", env=dict(os.environ), check=False)
            if unlocked.returncode:
                print(
                    "Platform operation lock could not be released; follow the documented lock recovery procedure",
                    file=sys.stderr,
                )
                result = result or unlocked.returncode
        return result


def resolve_addresses(host: str) -> set[str]:
    return {str(ipaddress.ip_address(info[4][0])) for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}


def validate_application_configuration(values: dict[str, str], environment: str) -> None:
    required = [
        "PLATFORM_DOMAIN",
        "PORTAL_DOMAIN",
        "DJANGO_SECRET_KEY",
        "PORTAL_DJANGO_SECRET_KEY",
        "DB_PASSWORD",
        "HMAC_SECRET",
        "PLATFORM_TO_PORTAL_WEBHOOK_SECRET",
    ]
    if environment == "prod":
        required += [
            "DJANGO_ENCRYPTION_KEY",
            "CREDENTIAL_VAULT_MASTER_KEY",
            "COMPANY_NAME",
            "COMPANY_CUI",
            "COMPANY_COUNTRY_CODE",
        ]
    missing = [name for name in required if not values.get(name, "").strip()]
    if missing:
        raise ValueError("Missing required native configuration keys: " + ", ".join(missing))
    if environment in {"prod", "staging"}:
        validate_portal_credentials(values)
    if not values.get("PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS", "").strip():
        raise ValueError(
            "Native HTTPS callbacks require explicit Platform egress CIDRs, including combined self-connections"
        )


def validate_portal_credentials(values: dict[str, str]) -> None:
    """Check the deployed HMAC contract before transferring files or stopping services."""
    try:
        registry = json.loads(values.get("PORTAL_HMAC_CREDENTIALS", "{}"))
    except ValueError:
        raise ValueError("Portal HMAC credentials must contain a valid registry") from None
    portal_id = values.get("PORTAL_ID", "portal-001")
    secret = values.get("PORTAL_HMAC_SECRET", "")
    if values.get("PORTAL_HMAC_MODE", "enforce") != "enforce" or not isinstance(registry, dict) or not registry:
        raise ValueError("Portal HMAC requires enforce mode and a registered Portal")
    owners: dict[str, str] = {}
    keyrings: dict[str, list[str]] = {}
    for identity, raw in registry.items():
        keys = [raw] if isinstance(raw, str) else raw
        if (
            not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", identity)
            or not isinstance(keys, list)
            or not 1 <= len(keys) <= 3
        ):
            raise ValueError("Portal HMAC registry has an invalid identity or keyring")
        for key in keys:
            if (
                not isinstance(key, str)
                or len(key) < 32
                or not key.strip()
                or key == (values.get("PLATFORM_API_SECRET") or values.get("HMAC_SECRET"))
                or owners.get(key, identity) != identity
            ):
                raise ValueError("Portal HMAC requires strong isolated per-Portal credentials")
            owners[key] = identity
        keyrings[identity] = keys
    if len(secret) < 32 or secret not in keyrings.get(portal_id, []):
        raise ValueError("Portal HMAC signing key must match its registered Portal")


def validate_rollback_migrations(
    applied: set[tuple[str, str]], target_paths: set[str], *, service: str = "platform"
) -> None:
    target = {
        (parts[3], Path(parts[-1]).stem)
        for path in target_paths
        if len(parts := path.split("/")) == 6
        and parts[:3] == ["services", service, "apps"]
        and parts[4] == "migrations"
        and parts[-1].endswith(".py")
    }
    missing = applied - target
    if missing:
        raise ValueError(
            "Code-only rollback would discard applied migrations: "
            + ", ".join(f"{app}.{name}" for app, name in sorted(missing))
        )


def validate_backup_pair(database: Path, media: Path, revision: str) -> Path:
    """Validate a native recovery pair and publish private checksums and provenance atomically."""
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or database.suffix != ".dump"
        or media != database.with_suffix(".media.tar.gz")
        or any(path.is_symlink() or not path.is_file() or not path.stat().st_size for path in (database, media))
    ):
        raise ValueError("Invalid native backup pair or source release")
    checked = subprocess.run(
        ["/usr/lib/postgresql/16/bin/pg_restore", "--list", str(database)],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if checked.returncode:
        raise ValueError("Native database backup failed PostgreSQL 16 archive validation")
    archive_root: str | None = None
    try:
        with gzip.open(media, "rb") as compressed:
            with tarfile.open(fileobj=compressed, mode="r|") as archive:
                for entry in archive:
                    member = Path(entry.name)
                    if (
                        not member.parts
                        or member.is_absolute()
                        or ".." in member.parts
                        or entry.issym()
                        or entry.islnk()
                        or not (entry.isfile() or entry.isdir())
                    ):
                        raise ValueError("Native media backup contains an unsafe member")
                    if archive_root is None:
                        archive_root = member.parts[0]
                    if member.parts[0] != archive_root:
                        raise ValueError("Native media backup contains multiple archive roots")
            while compressed.read(1024 * 1024):
                pass
        if archive_root is None:
            raise ValueError("Native media backup contains no archive root")
    except (OSError, EOFError, tarfile.TarError):
        raise ValueError("Native media backup failed archive validation") from None
    artifacts: dict[str, object] = {"format_version": 1, "database_major": 16, "release_sha": revision}
    for role, path in (("database", database), ("media", media)):
        with path.open("rb") as source:
            artifact: dict[str, str | None] = {
                "file": path.name,
                "sha256": hashlib.file_digest(source, "sha256").hexdigest(),
            }
        if role == "media":
            artifact["archive_root"] = archive_root
        artifacts[role] = artifact
    destination = database.with_suffix(".recovery.json")
    with tempfile.NamedTemporaryFile(mode="w", dir=database.parent, prefix=".native-recovery-", delete=False) as output:
        temporary = Path(output.name)
        json.dump(artifacts, output)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def validate_adoption_plan(plan: object, existing_topology: str) -> None:
    """Reject unbound adoption evidence, server replacement/deletion, and RDNS retirement."""
    if not isinstance(plan, dict) or not isinstance(prior := plan.get("prior_state"), dict):
        raise ValueError("Saved adoption plan must contain the prior native state")
    if not isinstance(values := prior.get("values"), dict) or not isinstance(root := values.get("root_module"), dict):
        raise ValueError("Saved adoption plan has invalid prior state")
    resources = root.get("resources", [])
    if not isinstance(resources, list):
        raise ValueError("Saved adoption plan has invalid prior resources")
    servers = set()
    for resource in resources:
        if isinstance(resource, dict) and resource.get("type") == "hcloud_server":
            if not isinstance(attributes := resource.get("values"), dict) or not isinstance(
                resource.get("address"), str
            ):
                raise ValueError("Saved adoption plan has invalid prior server data")
            if attributes.get("id"):
                servers.add(resource["address"])
    expected = {"hcloud_server.platform"}
    if existing_topology == "split":
        expected.add("hcloud_server.portal[0]")
    elif existing_topology != "combined":
        raise ValueError("Existing topology must be split or combined")
    if servers != expected:
        raise ValueError("Saved plan's prior server addresses do not match the recorded topology")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError("Saved adoption plan must contain resource_changes")
    for resource in changes:
        if not isinstance(resource, dict) or resource.get("type") not in {"hcloud_server", "hcloud_rdns"}:
            continue
        change = resource.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if (
            not isinstance(actions, list)
            or not actions
            or any(action not in ("create", "update", "no-op") for action in actions)
        ):
            raise ValueError("Adoption plan contains server/RDNS deletion, replacement or state removal")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run",))
    parser.add_argument("--env", choices=("prod", "staging", "dev"), default="prod")
    parser.add_argument("--env-file", type=Path)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--backup", action="store_true")
    operation.add_argument("--ssh-only", action="store_true")
    operation.add_argument("--caddy-only", action="store_true")
    operation.add_argument("--rollback", action="store_true")
    parser.add_argument("--fetch", choices=("true", "false"), default="false")
    parser.add_argument("--version", default="")
    args = parser.parse_args()
    path = (args.env_file or ROOT / f".env.{args.env}").resolve()
    try:
        values = read_env(path)
    except (OSError, UnicodeError, ValueError) as error:
        message = (
            str(error)
            if isinstance(error, ValueError) and not isinstance(error, UnicodeError)
            else "cannot read UTF-8 env file"
        )
        print(message, file=sys.stderr)
        return 1
    try:
        return run_native(
            values,
            path,
            args.env,
            fetch_backup=args.fetch if args.backup else None,
            version=args.version,
            ssh_only=args.ssh_only,
            caddy_only=args.caddy_only,
            rollback=args.rollback,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(
            str(error) if isinstance(error, ValueError) else "SSH/deployment connection failed or timed out",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
