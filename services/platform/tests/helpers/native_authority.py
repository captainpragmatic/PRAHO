"""Plain private native authority fixtures, independent of warnings and SMTP models."""

import json
import os
import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.infrastructure.native_lab import NativeAuthority, native_authority


def make_authority(root: Path) -> NativeAuthority:
    """Real private manifest and original SSH key; no provider call or native VM claim."""
    run = str(uuid4())
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    key_path = root / (run + ".key")
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    path = root / "vm.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "owner": "praho-quota-776",
                "provider": "hetzner",
                "run": run,
                "phase": "created",
                "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
                "server_id": 13,
                "ssh_key_id": 17,
                "firewall_id": 19,
                "ipv4": "192.0.2.13",
                "ssh_port": 22,
                "admin_cidr": "192.0.2.17/32",
                "host_public_key": public,
            }
        )
    )
    path.chmod(0o600)
    return native_authority(path)


def native_settings(
    authority: NativeAuthority, capture: Path | None = None, *, cleanup: bool = False
) -> dict[str, Any]:
    environment = {
        "PRAHO_NATIVE_LAB": "1",
        "DB_NAME": "praho_native_smtp_test",
        "NATIVE_VM_MANIFEST": str(authority.path),
        "PRAHO_NATIVE_CLEANUP_ONLY": "1" if cleanup else "0",
        "EMAIL_HOST": "smtp.production.invalid",
        "EMAIL_HOST_USER": "must-never-be-used",
        "EMAIL_HOST_PASSWORD": "fixture-ambient-auth",
        "EMAIL_USE_TLS": "true",
        "EMAIL_USE_SSL": "true",
    }
    with patch.dict(os.environ, environment):
        os.environ.pop("PRAHO_NATIVE_SMTP_MANIFEST", None)
        if capture:
            os.environ["PRAHO_NATIVE_SMTP_MANIFEST"] = str(capture)
        return runpy.run_module("config.settings.native")
