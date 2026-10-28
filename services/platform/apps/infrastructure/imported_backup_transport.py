"""Local readiness for imported servers: explicit root key and exact enrolled trust."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import paramiko
from django.conf import settings

from apps.common.ssh import MAX_SSH_PORT
from apps.common.types import Err, Ok, Result, Retriability

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apps.provisioning.virtualmin_models import VirtualminServer

BACKUP_PLAYBOOKS = frozenset(
    {
        "virtualmin_backup_fetch.yml",
        "virtualmin_backup_push.yml",
        "virtualmin_remote_cleanup.yml",
        "virtualmin_chain_backup.yml",
        "virtualmin_pair_restore.yml",
    }
)
# The recovery playbook's other actions mutate a held target. Over the archive transport only the
# owner-aging capture that precedes a recovery-capable backup may run.
ACTION_SCOPED_PLAYBOOKS: dict[str, tuple[str, frozenset[str]]] = {
    "virtualmin_recovery.yml": ("recovery_action", frozenset({"capture-owner"})),
}
DEFAULT_SSH_PORT = 22


def transport_allows(playbook: str, extra_vars: Mapping[str, Any] | None) -> bool:
    """Whether the archive transport may run this playbook with these variables."""
    if playbook in BACKUP_PLAYBOOKS:
        return True
    scoped = ACTION_SCOPED_PLAYBOOKS.get(playbook)
    return scoped is not None and (extra_vars or {}).get(scoped[0]) in scoped[1]


def server_transport_ready(server: VirtualminServer) -> Result[None, str]:
    if getattr(server, "node_deployment", None) is not None:
        return Ok(None)
    try:
        imported_identity(server)
        return Ok(None)
    except (OSError, ValueError) as error:
        return Err(str(error), retriability=Retriability.NOT_RETRIABLE)


@dataclass(frozen=True)
class ImportedIdentity:
    host: str
    port: int
    key: Path
    trusted_keys: tuple[str, ...]


def imported_identity(server: VirtualminServer) -> ImportedIdentity:
    """No network, key discovery, trust enrollment or managed-node fallback."""
    host = server.hostname
    port = server.ssh_port
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host) or not 1 <= port <= MAX_SSH_PORT:
        raise ValueError("Configure a valid registered SSH hostname and port")
    configured_key = str(getattr(settings, "VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH", "")).strip()
    key = Path(configured_key)
    if (
        not configured_key
        or key.is_symlink()
        or not key.is_file()
        or not os.access(key, os.R_OK)
        or key.stat().st_mode & 0o077
    ):
        raise ValueError(
            "Configure a readable private root SSH key with private permissions using VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH"
        )
    configured_trust = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
    if not configured_trust:
        raise ValueError("Configure enrolled SSH trust using PRAHO_SSH_KNOWN_HOSTS_PATH")
    try:
        trust = paramiko.HostKeys(configured_trust)
        alias = host if port == DEFAULT_SSH_PORT else f"[{host}]:{port}"
        keys = trust.lookup(alias)
        if not keys:
            raise ValueError("No enrolled SSH trust for the registered hostname and exact port")
        trusted_keys = tuple(f"{alias} {key.get_name()} {key.get_base64()}" for key in keys.values())
    except (OSError, paramiko.SSHException, paramiko.hostkeys.InvalidHostKey) as error:
        raise ValueError("Cannot read configured enrolled SSH trust") from error
    return ImportedIdentity(host, port, key, trusted_keys)
