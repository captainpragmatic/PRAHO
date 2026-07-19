"""Shared fail-closed SSH host-key trust configuration."""

from __future__ import annotations

import paramiko
from django.conf import settings


def configure_strict_host_key_checking(client: paramiko.SSHClient) -> None:
    """Load pre-provisioned known hosts and reject every unknown host key."""
    client.load_system_host_keys()
    known_hosts_path = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
    if known_hosts_path:
        client.load_host_keys(known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
