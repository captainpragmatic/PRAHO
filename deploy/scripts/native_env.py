"""Decode native deployment configuration as data; never source it as shell code."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
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
)


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
    for cidr in values.get("PLATFORM_ALLOWED_CIDRS", "").split():
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            raise ValueError("PLATFORM_ALLOWED_CIDRS must contain space-separated, canonical CIDRs") from None
        if network.prefixlen == 0:
            raise ValueError("PLATFORM_ALLOWED_CIDRS cannot allow the entire Internet")
    return values


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
) -> int:
    """Export inventory connection values, never application credentials, to Ansible."""
    inventory = "dev.yml" if environment == "dev" else "native-single-server.yml"
    local_controller = Path(sys.executable).with_name("ansible-playbook")
    controller = (
        str(local_controller)
        if local_controller.is_file()
        else (shutil.which("ansible-playbook") or "ansible-playbook")
    )
    playbook = "ssh-hardening" if ssh_only else ("backup" if fetch_backup is not None else "native-single-server")
    command = [
        controller,
        "-i",
        f"inventory/{inventory}",
        f"playbooks/{playbook}.yml",
        "-e",
        f"praho_env={environment}",
        "-e",
        f"env_file_path={path}",
    ]
    if fetch_backup is not None:
        command += ["-e", f"fetch_backup={fetch_backup}"]
    if version:
        command += ["-e", f"cli_version={version}"]
    if caddy_only:
        command += ["--tags", "caddy"]
    child_env = {**os.environ, **{key: values[key] for key in CONNECTION_KEYS if key in values}}
    recover_ssh_port(child_env, environment)
    return subprocess.run(command, cwd=ROOT / "deploy/ansible", env=child_env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run",))
    parser.add_argument("--env", choices=("prod", "staging", "dev"), default="prod")
    parser.add_argument("--env-file", type=Path)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--backup", action="store_true")
    operation.add_argument("--ssh-only", action="store_true")
    operation.add_argument("--caddy-only", action="store_true")
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
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(
            str(error) if isinstance(error, ValueError) else "SSH/deployment connection failed or timed out",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
