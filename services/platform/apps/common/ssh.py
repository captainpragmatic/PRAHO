"""Shared fail-closed SSH host-key trust configuration."""

from __future__ import annotations

import base64
import binascii
import struct

import paramiko
from django.conf import settings

PUBLIC_KEY_FIELDS = 2
MIN_RSA_BITS = 2048
MAX_SSH_PORT = 65535


def parse_ssh_host_keys(value: str) -> list[paramiko.PKey]:
    """Validate canonical public host keys before using them as durable trust."""
    keys: dict[str, paramiko.PKey] = {}
    allowed = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != PUBLIC_KEY_FIELDS or parts[0] not in allowed:
            raise ValueError("Invalid enrolled SSH host public key")
        try:
            key = paramiko.PKey.from_type_string(parts[0], base64.b64decode(parts[1], validate=True))
        except (ValueError, binascii.Error, struct.error, paramiko.SSHException) as error:
            raise ValueError("Invalid enrolled SSH host public key") from error
        if key.get_name() != parts[0] or (parts[0] == "ssh-rsa" and key.get_bits() < MIN_RSA_BITS):
            raise ValueError("Unsupported enrolled SSH host public key")
        previous = keys.get(parts[0])
        if previous is not None and previous.get_base64() != key.get_base64():
            raise ValueError("Conflicting enrolled SSH host public keys")
        keys[parts[0]] = key
    if not keys:
        raise ValueError("Missing enrolled SSH host public keys")
    return list(keys.values())


def configure_strict_host_key_checking(
    client: paramiko.SSHClient,
    *,
    host_keys: str | None = None,
    hostnames: tuple[str, ...] = (),
    port: int = 22,
) -> None:
    """An enrolled node pin outranks ambient trust; manual servers use configured pins."""
    if host_keys is not None:
        # Paramiko exposes no public getter for system trust; its stubs omit this attribute.
        system_host_keys: object = getattr(client, "_system_host_keys", None)
        if client.get_host_keys() or system_host_keys is None or system_host_keys:
            raise ValueError("Enrolled SSH pins require a fresh client without ambient trust")
        keys = parse_ssh_host_keys(host_keys)
        if not hostnames or not 1 <= port <= MAX_SSH_PORT:
            raise ValueError("Enrolled SSH trust requires explicit hostnames and a valid port")
        for host in hostnames:
            if not host or any(character.isspace() or character in ",[]" for character in host):
                raise ValueError("Invalid SSH host alias")
            for key in keys:
                client.get_host_keys().add(host, key.get_name(), key)
                client.get_host_keys().add(f"[{host}]:{port}", key.get_name(), key)
    else:
        client.load_system_host_keys()
        known_hosts_path = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
        if known_hosts_path:
            client.load_host_keys(known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
