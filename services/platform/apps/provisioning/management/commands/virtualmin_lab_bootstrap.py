"""Register the Docker Virtualmin lab (deploy/virtualmin-lab) in the lab database.

Creates or refreshes, for each lab node:
- a VirtualminServer, pinned to the node's live TLS certificate, with a fresh
  random API password (root's password on the node);
- a NodeDeployment with a fresh managed SSH key in the credential vault;
- the node's credential files under .state/<node>/inject, which
  `lab.sh apply-credentials` installs (no credential ever lives in the image).

It also writes the port-keyed known_hosts file, points the backup.* settings at
the lab MinIO, gives the lab a private transfer spool, and creates the customer,
service and VirtualminAccount the round-trip gate backs up.

Refuses to run unless DJANGO_SETTINGS_MODULE=config.settings.lab and DEBUG.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import shutil
import ssl
import subprocess
from argparse import ArgumentParser
from decimal import Decimal
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.provisioning.management.commands._virtualmin_lab import (
    LAB_LOOPBACK,
    LabNode,
    LabState,
    container_address,
    lab_state_dir,
    read_env_file,
    refuse_unless_lab_settings,
)
from apps.provisioning.virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE

logger = logging.getLogger(__name__)

NODES: tuple[LabNode, ...] = (
    LabNode("vm-a", "vmlab-a", "vm-a.praho.test", "dev-sha-lab-ro-vmla-001", 10101, 2522),
    LabNode("vm-b", "vmlab-b", "vm-b.praho.test", "dev-sha-lab-ro-vmlb-002", 10102, 2622),
)
LAB_DOMAIN = "roundtrip.praho.test"
LAB_DOMAIN_USER = "roundtrip"
S3_PORT = 19000


def _certificate_sha256(port: int) -> str:
    pem = ssl.get_server_certificate((LAB_LOOPBACK, port), timeout=10)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def _scan_host_keys(port: int) -> str:
    keyscan = shutil.which("ssh-keyscan") or "ssh-keyscan"
    scan = subprocess.run(  # Fixed argv against the local lab port
        [keyscan, "-T", "10", "-p", str(port), LAB_LOOPBACK],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    lines = [line for line in scan.stdout.splitlines() if line and not line.startswith("#")]
    if scan.returncode != 0 or not lines:
        raise CommandError(f"ssh-keyscan found no host key on {LAB_LOOPBACK}:{port}: {scan.stderr.strip()}")
    return "\n".join(lines) + "\n"


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content)
    tmp.chmod(0o600)
    tmp.replace(path)


class Command(BaseCommand):
    help = "Register the Docker Virtualmin lab nodes, keys and MinIO backup settings (lab settings only)"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--s3-port", type=int, default=S3_PORT, help="Published MinIO API port")

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        state_dir = lab_state_dir()
        lab_env_path = state_dir / "lab.env"
        if not lab_env_path.is_file():
            raise CommandError(f"{lab_env_path} is missing; run `make virtualmin-lab-up` first")
        lab_env = read_env_file(lab_env_path)

        known_hosts = "".join(_scan_host_keys(node.ssh_port) for node in NODES)
        known_hosts_path = state_dir / "known_hosts"
        _write_private(known_hosts_path, known_hosts)

        spool = state_dir / "spool"
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        spool.chmod(0o700)

        with transaction.atomic():
            for node in NODES:
                self._register_node(node, state_dir)
            self._configure_backup_settings(lab_env, options["s3_port"], spool)
            self._ensure_account()

        state = LabState(
            state_dir=str(state_dir),
            nodes=NODES,
            known_hosts=str(known_hosts_path),
            s3_endpoint=f"http://{LAB_LOOPBACK}:{options['s3_port']}",
            bucket=lab_env.get("LAB_BUCKET", "praho-backups"),
            domain=LAB_DOMAIN,
            domain_user=LAB_DOMAIN_USER,
        )
        state.save()
        logger.info("✅ [VirtualminLab] Registered %s nodes; state in %s", len(NODES), state_dir)
        self.stdout.write(self.style.SUCCESS(f"Lab registered: {', '.join(n.server_hostname for n in NODES)}"))
        self.stdout.write("Next: deploy/virtualmin-lab/lab.sh apply-credentials")

    def _register_node(self, node: LabNode, state_dir: Path) -> None:
        from apps.infrastructure.models import (  # noqa: PLC0415
            CloudProvider,
            NodeDeployment,
            NodeRegion,
            NodeSize,
            PanelType,
        )
        from apps.infrastructure.ssh_key_manager import get_ssh_key_manager  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        password = secrets.token_urlsafe(24)
        server, _ = VirtualminServer.objects.update_or_create(
            hostname=node.server_hostname,
            defaults={
                "name": f"lab-{node.key}",
                "api_port": node.api_port,
                "api_username": "root",
                "use_ssl": True,
                "ssl_verify": False,
                "ssl_cert_fingerprint": _certificate_sha256(node.api_port),
                "status": "active",
                "max_domains": 50,
                "health_check_error": "",
                "last_health_check": timezone.now(),
            },
        )
        server.set_api_password(password)
        server.save()

        # No provider type fits a local container; these rows exist only so the
        # transport has the NodeDeployment it requires, and stay inactive.
        provider, _ = CloudProvider.objects.get_or_create(
            code="lab",
            defaults={
                "name": "Virtualmin lab (Docker)",
                "provider_type": "hetzner",
                "is_active": False,
                "credential_identifier": "virtualmin-lab",
            },
        )
        region, _ = NodeRegion.objects.get_or_create(
            provider=provider,
            provider_region_id="lab1",
            defaults={
                "name": "Virtualmin lab",
                "normalized_code": "lab1",
                "country_code": "ro",
                "city": "Docker",
                "is_active": False,
            },
        )
        size, _ = NodeSize.objects.get_or_create(
            provider=provider,
            provider_type_id="lab",
            defaults={
                "name": "Virtualmin lab node",
                "display_name": "Lab",
                "vcpus": 1,
                "memory_gb": 2,
                "disk_gb": 10,
                "hourly_cost_eur": Decimal("0"),
                "monthly_cost_eur": Decimal("0"),
                "is_active": False,
            },
        )
        panel, _ = PanelType.objects.get_or_create(
            panel_type="virtualmin",
            defaults={"name": "Virtualmin", "ansible_playbook": "virtualmin.yml"},
        )
        deployment, _ = NodeDeployment.objects.update_or_create(
            hostname=node.deployment_hostname,
            defaults={
                "environment": "dev",
                "node_type": "sha",
                "provider": provider,
                "region": region,
                "node_size": size,
                "panel_type": panel,
                "node_number": int(node.deployment_hostname.rsplit("-", 1)[1]),
                "display_name": f"Virtualmin lab {node.key}",
                "ipv4_address": LAB_LOOPBACK,
                "virtualmin_server": server,
                "status": "completed",
                "backup_enabled": True,
                "backup_storage": "local",
            },
        )

        key = get_ssh_key_manager().generate_deployment_key(deployment)
        if key.is_err():
            raise CommandError(f"SSH key generation failed for {node.key}: {key.unwrap_err()}")

        inject = state_dir / node.key / "inject"
        _write_private(inject / "root_password", password + "\n")
        _write_private(inject / "authorized_keys", key.unwrap().public_key.strip() + "\n")
        self.stdout.write(f"{node.key}: server {server.hostname}:{node.api_port}, ssh {node.ssh_port}")

    def _configure_backup_settings(self, lab_env: dict[str, str], s3_port: int, spool: Path) -> None:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        values: dict[str, Any] = {
            "backup.s3_endpoint_url": f"http://{LAB_LOOPBACK}:{s3_port}",
            "backup.s3_bucket_name": lab_env.get("LAB_BUCKET", "praho-backups"),
            "backup.aws_access_key_id": lab_env["MINIO_ROOT_USER"],
            "backup.aws_secret_access_key": lab_env["MINIO_ROOT_PASSWORD"],
            "backup.aws_region": "us-east-1",
            "provisioning.migration_spool_dir": str(spool),
            # Platform reaches every lab node from the compose network gateway
            # (ADR-0060 allowlist); the nodes' own addresses stay outside it.
            "infrastructure.node_admin_allowed_cidrs": [f"{container_address(NODES[0].container, 'Gateway')}/32"],
        }
        for key, value in values.items():
            result = SettingsService.update_setting(key, value)
            if result.is_err():
                raise CommandError(f"Could not set {key}: {result.unwrap_err()}")

    def _ensure_account(self) -> None:
        from apps.billing.models import Currency  # noqa: PLC0415
        from apps.customers.models import Customer  # noqa: PLC0415
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer  # noqa: PLC0415

        server = VirtualminServer.objects.get(hostname=NODES[0].server_hostname)
        customer, _ = Customer.objects.get_or_create(
            primary_email="lab@praho.test",
            defaults={
                "name": "Virtualmin Lab SRL",
                "customer_type": "company",
                "status": "active",
                "company_name": "Virtualmin Lab SRL",
            },
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan, _ = ServicePlan.objects.get_or_create(
            name="Virtualmin lab hosting",
            defaults={"plan_type": "shared_hosting", "price_monthly": Decimal("0.00")},
        )
        service, _ = Service.objects.get_or_create(
            domain=LAB_DOMAIN,
            defaults={
                "customer": customer,
                "service_plan": plan,
                "currency": currency,
                "service_name": LAB_DOMAIN,
                "username": LAB_DOMAIN_USER,
                "billing_cycle": "monthly",
                "price": Decimal("0.00"),
                "status": "active",
            },
        )
        account, created = VirtualminAccount.objects.get_or_create(
            domain=LAB_DOMAIN,
            defaults={
                "service": service,
                "server": server,
                "virtualmin_username": LAB_DOMAIN_USER,
                "template_name": DEFAULT_VIRTUALMIN_TEMPLATE,
                "status": "active",
                "praho_customer_id": customer.id,
            },
        )
        if created or not account.encrypted_password:
            account.set_password(secrets.token_urlsafe(18))
        account.server = server
        account.save()
