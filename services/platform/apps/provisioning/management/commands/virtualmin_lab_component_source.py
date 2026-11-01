"""Opt-in real mail/DNS source, registered as an import without a managed deployment."""

from __future__ import annotations

import secrets
import subprocess
import time
from typing import TYPE_CHECKING, Any

import paramiko
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from ._virtualmin_lab import (
    COMPONENT_SOURCE,
    lab_state_dir,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
    write_private,
)
from .virtualmin_lab_bootstrap import _certificate_sha256, _scan_host_keys

SOURCE_NAME = "lab-imported-component-source"

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminServer


def _run(arguments: list[str], *, timeout: int = 60) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise CommandError(f"Disposable component source step failed: {result.stderr.strip()[:2000]}")
    return result.stdout.strip()


class Command(BaseCommand):
    help = "Start an opt-in imported Virtualmin source with real SMTP, IMAP and authoritative DNS (lab only)"

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        state = load_state()
        directory = lab_state_dir() / "component-source"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        inject = directory / "inject"
        inject.mkdir(mode=0o700, parents=True, exist_ok=True)
        inject.chmod(0o700)
        key = directory / "identity"
        if key.is_symlink():
            raise CommandError("The imported fixture key must not be a symlink")
        if not key.exists():
            private_key = paramiko.RSAKey.generate(3072)
            private_key.write_private_key_file(str(key))
            key.chmod(0o600)
        if key.is_symlink() or key.stat().st_mode & 0o077:
            raise CommandError("The imported fixture key must be a private file")
        private_key = paramiko.RSAKey.from_private_key_file(str(key))
        write_private(inject / "authorized_keys", private_key.get_name() + " " + private_key.get_base64() + "\n")
        password_file = inject / "root_password"
        if password_file.is_symlink():
            raise CommandError("The imported fixture password must not be a symlink")
        if not password_file.exists():
            write_private(password_file, secrets.token_urlsafe(24) + "\n")
        password = password_file.read_text().strip()
        _run(
            [
                "docker",
                "compose",
                "--env-file",
                str(lab_state_dir() / "lab.env"),
                "-f",
                str(lab_state_dir().parent / "compose.yml"),
                "--profile",
                "component-source",
                "up",
                "-d",
                "--no-deps",
                "--no-build",
                "--no-recreate",
                "component-source",
            ],
            timeout=180,
        )
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            status = _run(["docker", "inspect", "--format", "{{.State.Health.Status}}", COMPONENT_SOURCE.container])
            if status == "healthy":
                break
            time.sleep(2)
        else:
            raise CommandError(
                "Mixed-service source did not become healthy; inspect its native first-boot service logs"
            )
        server = self._register(password)
        from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415
        from apps.provisioning.virtualmin_security_tasks import collect_inspection  # noqa: PLC0415

        with lab_transport(state):
            connected = VirtualminGateway(VirtualminConfig(server=server)).test_connection()
            if connected.is_err() or not connected.unwrap()["healthy"]:
                raise CommandError("The imported fixture's pinned native API did not authenticate")
            collect_inspection(server)
        self.stdout.write(
            "Imported mixed-service source ready; no NodeDeployment or web-destination verification created"
        )

    @staticmethod
    @transaction.atomic
    def _register(password: str) -> VirtualminServer:
        from apps.common.credential_vault import CredentialData, get_credential_vault  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        fingerprint = _certificate_sha256(COMPONENT_SOURCE.api_port)
        keys = "\n".join(
            sorted({" ".join(line.split()[1:3]) for line in _scan_host_keys(COMPONENT_SOURCE.ssh_port).splitlines()})
        )
        existing = VirtualminServer.objects.filter(hostname=COMPONENT_SOURCE.server_hostname).first()
        if existing is not None:
            if (
                existing.name != SOURCE_NAME
                or existing.api_port != COMPONENT_SOURCE.api_port
                or existing.ssh_port != COMPONENT_SOURCE.ssh_port
                or existing.ssl_cert_fingerprint != fingerprint
                or existing.imported_ssh_host_keys != keys
                or getattr(existing, "node_deployment", None) is not None
            ):
                raise CommandError(
                    "Existing source identity changed; resolve its fixture records before registering again"
                )
            return existing
        server = VirtualminServer.objects.create(
            name=SOURCE_NAME,
            hostname=COMPONENT_SOURCE.server_hostname,
            api_port=COMPONENT_SOURCE.api_port,
            ssh_port=COMPONENT_SOURCE.ssh_port,
            api_username="root",
            imported_ssh_host_keys=keys,
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint=fingerprint,
            status="active",
            legacy_security_admission=False,
            last_health_check=timezone.now(),
        )
        server.set_api_password(password)
        server.save()
        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=server.hostname,
                username="root",
                password=password,
                metadata={"created_by": "virtualmin_lab_component_source"},
                create_only=True,
            )
        )
        if stored.is_err():
            raise CommandError("Could not persist the imported fixture's native API credential")
        return server
