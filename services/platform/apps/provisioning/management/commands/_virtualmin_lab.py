"""Shared plumbing for the Virtualmin lab commands (deploy/virtualmin-lab).

The lab publishes two Virtualmin nodes on 127.0.0.1 under distinct ports. PRAHO's
production transport assumes things a Docker host cannot offer, so
`lab_transport()` adapts exactly four of them, and only inside lab commands:

1. Virtualmin API hostnames resolve through DNS and must be globally routable.
   The lab node names (vm-a.praho.test, ...) resolve to 127.0.0.1 here, and only
   those names: every other host still goes through the real resolver and the
   SSRF check.
2. Ansible always connects to port 22 (the inventory has no port). Each lab
   deployment gets its published SSH port as `ansible_port`.
3. `_wait_for_ssh()` probes port 22, which on a Mac is the host's own sshd. Here
   it probes the lab ports instead.
4. The known_hosts lookup is keyed by bare IP, so it never matches the
   port-keyed lab entries and would fall back to ssh-keyscan on port 22, pinning
   the host's key. The lab known_hosts file (written by the bootstrap) is used
   instead, and strict host-key checking stays on.

Everything else (gateway, TLS pinning, credentials, job layer, playbooks, S3)
is the production code path.
"""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

from django.conf import settings
from django.core.management.base import CommandError
from django.test import override_settings

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
    from apps.provisioning.virtualmin_models import VirtualminServer

LAB_SETTINGS_MODULES = frozenset({"config.settings.lab"})
LAB_LOOPBACK = "127.0.0.1"


@dataclass(frozen=True)
class LabNode:
    key: str
    container: str
    server_hostname: str
    deployment_hostname: str
    api_port: int
    ssh_port: int


# The bare Debian node a from-scratch deploy installs Virtualmin on (make test-virtualmin-node-deploy). It is
# not part of lab.json: the lab commands never see it unless `with_deploy_node` adds it. Its server hostname
# is the deployment's FQDN, as a production registration records it.
DEPLOY_NODE_ZONE = "praho.test"
DEPLOY_NODE = LabNode(
    "node-c", "vmlab-debian-node", f"dev-sha-lab-ro-vmlc-003.{DEPLOY_NODE_ZONE}", "dev-sha-lab-ro-vmlc-003", 10103, 2722
)


@dataclass(frozen=True)
class LabState:
    state_dir: str
    nodes: tuple[LabNode, ...]
    known_hosts: str
    s3_endpoint: str
    bucket: str
    domain: str
    domain_user: str

    def node(self, key: str) -> LabNode:
        for node in self.nodes:
            if node.key == key:
                return node
        raise CommandError(f"Unknown lab node {key!r}")

    def save(self) -> None:
        path = Path(self.state_dir) / "lab.json"
        payload = asdict(self)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n")
        tmp.chmod(0o600)
        tmp.replace(path)


def with_deploy_node(state: LabState) -> LabState:
    """The lab plus the node-deploy node, with the known_hosts file that holds all three nodes' host keys.

    The deploy node's host keys are generated at every boot, so the node-deploy command writes that file
    after the node is up; the ordinary lab keeps its own.
    """
    known_hosts = Path(state.state_dir) / "known_hosts-with-node-c"
    return replace(state, nodes=(*state.nodes, DEPLOY_NODE), known_hosts=str(known_hosts))


def write_private(path: Path, content: str) -> None:
    """Write a file only its owner can read, replacing any earlier one in one step."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content)
    tmp.chmod(0o600)
    tmp.replace(path)


def ensure_lab_deployment(
    node: LabNode, state_dir: Path, *, server: VirtualminServer | None = None, dns_zone: str = ""
) -> NodeDeployment:
    """The NodeDeployment the transport needs for a lab node, with a fresh managed SSH key.

    No provider type fits a local container; the provider, region and size rows exist only so the
    deployment has the foreign keys it requires, and stay inactive. The public key is written to the node's
    inject directory, where `lab-node-credentials` installs it.
    """
    from decimal import Decimal  # noqa: PLC0415

    from apps.infrastructure.models import (  # noqa: PLC0415
        CloudProvider,
        NodeDeployment,
        NodeRegion,
        NodeSize,
        PanelType,
    )
    from apps.infrastructure.ssh_key_manager import get_ssh_key_manager  # noqa: PLC0415

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
            "dns_zone": dns_zone,
            "virtualmin_server": server,
            "status": "completed",
            "backup_enabled": True,
            "backup_storage": "local",
        },
    )
    key = get_ssh_key_manager().generate_deployment_key(deployment)
    if key.is_err():
        raise CommandError(f"SSH key generation failed for {node.key}: {key.unwrap_err()}")
    write_private(state_dir / node.key / "inject" / "authorized_keys", key.unwrap().public_key.strip() + "\n")
    return deployment


def refuse_unless_lab_settings() -> None:
    """Lab commands write servers, keys and backup settings: never outside the lab."""
    module = str(getattr(settings, "SETTINGS_MODULE", ""))
    if not settings.DEBUG or module not in LAB_SETTINGS_MODULES:
        raise CommandError(
            f"Refusing to run under {module or 'unknown settings'} (DEBUG={settings.DEBUG}); "
            "lab commands only run with DJANGO_SETTINGS_MODULE=config.settings.lab"
        )


def lab_state_dir() -> Path:
    state_dir = getattr(settings, "VIRTUALMIN_LAB_STATE_DIR", None)
    if state_dir is None:
        raise CommandError("VIRTUALMIN_LAB_STATE_DIR is not configured")
    return Path(str(state_dir))


def load_state() -> LabState:
    path = lab_state_dir() / "lab.json"
    if not path.is_file():
        raise CommandError(f"{path} is missing; run `manage.py virtualmin_lab_bootstrap` first")
    raw: dict[str, Any] = json.loads(path.read_text())
    nodes = tuple(LabNode(**node) for node in raw.pop("nodes"))
    return LabState(nodes=nodes, **raw)


def container_address(container: str, field: str = "IPAddress") -> str:
    """One address of a lab container on its compose network (`IPAddress` or `Gateway`).

    Platform reaches the lab nodes through Docker's port publishing, so a node
    sees every Platform call (API and SSH) coming from the network `Gateway`.
    That address is the lab's node admin allowlist; the other node's
    `IPAddress` is a host on the same network that is deliberately not on it.
    """
    if field not in {"IPAddress", "Gateway"}:
        raise CommandError(f"Unknown container address field {field!r}")
    result = subprocess.run(  # Fixed argv against a local lab container
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{." + field + "}} {{end}}", container],  # noqa: S607  # docker from PATH, dev-only command
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    addresses = result.stdout.split()
    if result.returncode != 0 or len(addresses) != 1:
        raise CommandError(f"Cannot read the {field} of {container}: {result.stderr.strip() or addresses}")
    return addresses[0]


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


@contextmanager
def lab_transport(state: LabState) -> Iterator[None]:
    """Route PRAHO's production transport to the lab nodes (see module docstring).

    Refuses outside the lab settings itself, so no caller (a script, a shell,
    a future command) can loosen the SSRF guard or the port-22 assumptions of
    a production process by importing it.
    """
    refuse_unless_lab_settings()
    from apps.common import outbound_http  # noqa: PLC0415
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

    lab_names = {node.server_hostname for node in state.nodes}
    ports_by_deployment = {node.deployment_hostname: node.ssh_port for node in state.nodes}
    real_resolve = outbound_http._resolve_dns
    real_build_vars = AnsibleService._build_vars

    def resolve(hostname: str, port: int) -> list[str]:
        if hostname in lab_names:
            return [LAB_LOOPBACK]
        return real_resolve(hostname, port)

    def wait_for_ssh(ip: str, port: int = 22, timeout: int = 180, interval: float = 3.0) -> Result[bool, str]:
        del port, interval
        for node in state.nodes:
            try:
                with socket.create_connection((ip, node.ssh_port), timeout=min(5, timeout)):
                    pass
            except OSError as error:
                return Err(f"Lab node {node.key} SSH port {node.ssh_port} unreachable: {error}")
        return Ok(True)

    def known_hosts_covers(ip: str) -> bool:
        return ip == LAB_LOOPBACK

    def build_vars(self: AnsibleService, deployment: Any, extra_vars: dict[str, Any] | None = None) -> dict[str, Any]:
        built = real_build_vars(self, deployment, extra_vars)
        port = ports_by_deployment.get(str(deployment.hostname))
        if port is None:
            raise CommandError(f"Deployment {deployment.hostname} is not a lab node")
        built["ansible_port"] = port
        return built

    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(outbound_http, "_resolve_dns", resolve))
        stack.enter_context(mock.patch.object(AnsibleService, "_wait_for_ssh", staticmethod(wait_for_ssh)))
        stack.enter_context(
            mock.patch.object(AnsibleService, "_configured_known_hosts_covers", staticmethod(known_hosts_covers))
        )
        stack.enter_context(mock.patch.object(AnsibleService, "_build_vars", build_vars))
        stack.enter_context(override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=state.known_hosts))
        yield
