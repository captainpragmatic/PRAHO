"""Durable node host identities and ephemeral recovery of an interrupted SSH cutover."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.common.ssh import parse_ssh_host_keys
from apps.infrastructure.models import NodeDeployment

TARGET_SSH_PORT = 9876
BOOTSTRAP_SSH_PORT = 22
KNOWN_HOST_FIELDS = 3
TRANSITION_IN_PROGRESS = 73


def node_hostnames(deployment: NodeDeployment) -> tuple[str, ...]:
    hosts = tuple(dict.fromkeys((str(deployment.ipv4_address or ""), deployment.fqdn)))
    if any(not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host) for host in hosts):
        raise ValueError("Node SSH trust requires a valid IP and hostname")
    return hosts


def _canonical_scan_keys(content: str) -> str:
    public_keys = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < KNOWN_HOST_FIELDS or fields[0].startswith("@"):
            raise ValueError("Unsupported configured SSH host-key policy")
        public_keys.append(" ".join(fields[1:3]))
    keys = parse_ssh_host_keys("\n".join(public_keys))
    return "\n".join(f"{key.get_name()} {key.get_base64()}" for key in keys)


def _configured_keys(deployment: NodeDeployment) -> str:
    configured = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
    if not configured or not Path(configured).is_file():
        raise ValueError("Legacy node needs an operator-verified known_hosts entry before migration")
    content: list[str] = []
    for host in node_hostnames(deployment):
        for alias in (host, f"[{host}]:{deployment.ssh_port}", f"[{host}]:{TARGET_SSH_PORT}"):
            lookup = subprocess.run(  # noqa: S603 -- fixed command, validated host alias, no shell.
                [shutil.which("ssh-keygen") or "ssh-keygen", "-F", alias, "-f", configured],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if lookup.returncode not in (0, 1):
                raise ValueError("Cannot read the configured SSH host-key trust")
            if lookup.returncode == 0:
                content.append(lookup.stdout)
    if not content:
        raise ValueError("Legacy node has no verified SSH host-key entry; refusing network re-enrollment")
    return _canonical_scan_keys("\n".join(content))


def _enroll(deployment: NodeDeployment, public_keys: str) -> None:
    expected = deployment.ssh_host_keys
    updated = NodeDeployment.objects.filter(
        pk=deployment.pk,
        external_node_id=deployment.external_node_id,
        ipv4_address=deployment.ipv4_address,
        ssh_host_keys=expected,
    ).update(ssh_host_keys=public_keys, updated_at=timezone.now())
    if updated != 1:
        raise ValueError("Node identity changed during SSH enrollment; refusing to replace its pin")
    deployment.ssh_host_keys = public_keys


def resolve_node_host_keys(deployment: NodeDeployment) -> str:
    """Honor verified legacy operator trust without scanning a managed node again."""
    if deployment.ssh_host_keys is None:
        raise ValueError("Fresh node requires bootstrap host-key enrollment before SSH validation")
    if not deployment.ssh_host_keys:
        _enroll(deployment, _configured_keys(deployment))
    parse_ssh_host_keys(deployment.ssh_host_keys)
    return deployment.ssh_host_keys


def trusted_node_known_hosts(
    deployment: NodeDeployment,
    scan_bootstrap: Callable[[str], Path | None],
) -> Path:
    """Enroll only an explicitly fresh VM, then render the same pin for every port."""
    hosts = node_hostnames(deployment)
    if deployment.ssh_host_keys is None:
        if not deployment.external_node_id or deployment.ssh_port != BOOTSTRAP_SSH_PORT:
            raise ValueError("Invalid fresh-node SSH enrollment state")
        scanned = scan_bootstrap(str(deployment.ipv4_address))
        if scanned is None:
            raise ValueError("Fresh-node SSH host-key enrollment failed")
        try:
            public_keys = _canonical_scan_keys(scanned.read_text())
        finally:
            scanned.unlink(missing_ok=True)
        _enroll(deployment, public_keys)
    keys = parse_ssh_host_keys(resolve_node_host_keys(deployment))
    aliases = list(hosts)
    for port in dict.fromkeys((BOOTSTRAP_SSH_PORT, TARGET_SSH_PORT, deployment.ssh_port)):
        aliases.extend(f"[{host}]:{port}" for host in hosts)
    fd, filename = tempfile.mkstemp(prefix="praho_node_pins_")
    path = Path(filename)
    written = False
    try:
        with os.fdopen(fd, "w") as output:
            for key in keys:
                output.write(f"{','.join(aliases)} {key.get_name()} {key.get_base64()}\n")
        written = True
        return path
    finally:
        if not written:
            path.unlink(missing_ok=True)


def verify_idle_ssh(deployment: NodeDeployment, key_file: Path, known_hosts: Path, port: int) -> None:
    """A pending rollback must not turn a successful connection into persisted bad state."""
    host = node_hostnames(deployment)[0]
    proof = subprocess.run(  # noqa: S603 -- SSH argv, pinned identity, fixed remote command.
        [
            shutil.which("ssh") or "ssh",
            "-F",
            "/dev/null",
            "-p",
            str(port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            str(key_file),
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            f"HostKeyAlias={host}",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ConnectTimeout=10",
            f"root@{host}",
            "if test -d /run/praho-ssh-transition.lock; then exit 73; fi; /usr/bin/id -u",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proof.returncode == TRANSITION_IN_PROGRESS:
        raise ValueError("Node has an active or unrecovered SSH transition; wait for rollback or inspect its owner")
    if proof.returncode != 0 or proof.stdout.strip() != "0":
        raise ValueError("Pinned root key access failed; refusing SSH bootstrap-port fallback")


def recover_connection_port(deployment: NodeDeployment, key_file: Path, known_hosts: Path) -> int:
    """Return an ephemeral connection port. Never persist state from reachability alone."""
    if deployment.ssh_port == TARGET_SSH_PORT:
        return TARGET_SSH_PORT
    try:
        with socket.create_connection((str(deployment.ipv4_address), TARGET_SSH_PORT), timeout=3):
            pass
    except (ConnectionRefusedError, TimeoutError):
        return deployment.ssh_port
    verify_idle_ssh(deployment, key_file, known_hosts, TARGET_SSH_PORT)
    return TARGET_SSH_PORT


def persist_verified_ssh_port(deployment: NodeDeployment) -> None:
    """Call only after a successful dedicated transition and fresh idle-host proof."""
    with transaction.atomic():
        current = NodeDeployment.objects.select_for_update().get(pk=deployment.pk)
        if (current.external_node_id, current.ipv4_address, current.ssh_host_keys) != (
            deployment.external_node_id,
            deployment.ipv4_address,
            deployment.ssh_host_keys,
        ):
            raise ValueError("Node identity changed before SSH commit")
        current.ssh_port = TARGET_SSH_PORT
        current.save(update_fields=["ssh_port", "updated_at"])
        if current.virtualmin_server_id:
            server = current.virtualmin_server
            server.ssh_port = TARGET_SSH_PORT
            server.save(update_fields=["ssh_port", "updated_at"])
    deployment.ssh_port = TARGET_SSH_PORT
