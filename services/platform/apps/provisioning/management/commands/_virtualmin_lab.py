"""Shared plumbing for the Virtualmin lab commands (deploy/virtualmin-lab).

The lab publishes Virtualmin nodes on 127.0.0.1 under distinct ports.
`lab_transport()` adapts the following only inside validated lab commands:

1. Virtualmin API hostnames resolve through DNS and must be globally routable.
   The lab node names (vm-a.praho.test, ...) resolve to 127.0.0.1 here, and only
   those names: every other host still goes through the real resolver and the
   SSRF check.
2. Each lab deployment uses its published SSH port for inventory and readiness
   probes. Container firewall rules still use the daemon's internal port 22.
3. Bootstrap imports the lab's verified, port-specific host keys into its
   deployment record. The normal strict enrolled-identity checks remain active.
4. The Ubuntu port transition is skipped for these disposable Debian containers.
   The hook refuses any non-lab hostname or address; there is no production skip
   setting. Real Ubuntu transitions are exercised by the SSH Docker suite.

Everything else (gateway, TLS pinning, credentials, job layer, playbooks, S3)
is the production code path.
"""

from __future__ import annotations

import importlib
import json
import logging
import secrets
import socket
import subprocess
import traceback
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

import paramiko
from django.conf import settings
from django.core.management.base import CommandError
from django.test import override_settings
from django_q.models import OrmQ

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
    from apps.provisioning.virtualmin_models import VirtualminServer

logger = logging.getLogger(__name__)

LAB_SETTINGS_MODULES = frozenset({"config.settings.lab"})
LAB_LOOPBACK = "127.0.0.1"
# The staff login of the lab database: a developer's `make dev` and the browser smoke tests sign in as this user.
LAB_STAFF_EMAIL = "lab-staff@praho.test"
LAB_STAFF_FILE = "staff.env"


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
            "ssh_port": node.ssh_port,
            "ssh_host_keys": lab_ssh_host_keys(node, state_dir),
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


def lab_ssh_host_keys(node: LabNode, state_dir: Path) -> str:
    """Use bootstrap-pinned keys for the published lab endpoint, never the Mac's SSH daemon."""
    for filename in ("known_hosts", "known_hosts-with-node-c"):
        path = state_dir / filename
        if not path.is_file():
            continue
        keys = paramiko.HostKeys(str(path)).lookup(f"[{LAB_LOOPBACK}]:{node.ssh_port}")
        if keys:
            return "\n".join(f"{key.get_name()} {key.get_base64()}" for key in keys.values())
    raise CommandError(f"No bootstrap-verified SSH host key for lab node {node.key}")


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


# The opt-in hosting features a lab server switches on (migration, drain, differential backups).
LAB_FEATURE_SETTINGS = (
    "provisioning.migration_enabled",
    "infrastructure.drain_enabled",
    "provisioning.incremental_backups_enabled",
)


def enable_lab_features() -> None:
    """Switch the opt-in hosting features on, through the settings service (so this process's cache sees it)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Cross-domain: lab-only wiring

    for key in LAB_FEATURE_SETTINGS:
        result = SettingsService.update_setting(key, True)
        if result.is_err():
            raise CommandError(f"Could not enable {key}: {result.unwrap_err()}")


# Only these task modules do hosting work in the lab; the rest of the queue (e-mail, notifications) is discarded.
LAB_WORKER_MODULES = ("apps.provisioning.virtualmin_tasks", "apps.provisioning.tasks")


@dataclass
class QueuedRun:
    """One queued task a lab worker ran (or tried to)."""

    func: str
    args: tuple[Any, ...]
    result: Any = None
    error: str = ""

    @property
    def name(self) -> str:
        return self.func.rsplit(".", 1)[-1]


def run_queued_once(modules: tuple[str, ...] = LAB_WORKER_MODULES) -> list[QueuedRun]:
    """Run, once and in queue order, what is waiting on the ORM broker, the way a Django-Q worker does.

    The lab has no Django-Q cluster: its worker processes are spawned, so they would not inherit the lab
    transport (`lab_transport` patches the running process). The lab server, the workflow bench and the fault
    suite call this in a process that already runs inside the transport instead. A task that raises is recorded,
    not propagated (a worker records the failure and moves on); a row another caller already took is skipped.
    """
    ran: list[QueuedRun] = []
    for row in list(OrmQ.objects.order_by("id")):
        task = row.task
        if OrmQ.objects.filter(pk=row.pk).delete()[0] == 0:
            continue  # taken by another caller between the listing and now
        func = str(task.get("func", ""))
        module, _, name = func.rpartition(".")
        if module not in modules:
            continue
        run = QueuedRun(func=func, args=tuple(task.get("args", ())))
        try:
            run.result = getattr(importlib.import_module(module), name)(*run.args, **dict(task.get("kwargs", {})))
        except Exception:  # A worker records a failed task and carries on
            run.error = traceback.format_exc()
            logger.warning("⚠️ [VirtualminLab] task %s raised:\n%s", name, run.error)
        ran.append(run)
    return ran


def ensure_lab_staff(state_dir: Path) -> None:
    """Create (or reset) the lab's staff superuser with a fresh random password, kept in `staff.env`.

    The password lives only in the git-ignored lab state directory, like the node credentials, and is
    rotated by every bootstrap.
    """
    from apps.users.models import User  # noqa: PLC0415  # Cross-domain: the lab database holds the staff login

    password = secrets.token_urlsafe(18)
    user, _ = User.objects.update_or_create(
        email=LAB_STAFF_EMAIL,
        defaults={
            "first_name": "Lab",
            "last_name": "Staff",
            "is_active": True,
            "is_staff": True,
            "is_superuser": True,
            "staff_role": "admin",
        },
    )
    user.set_password(password)
    user.save(update_fields=["password"])
    write_private(state_dir / LAB_STAFF_FILE, f"LAB_STAFF_EMAIL={LAB_STAFF_EMAIL}\nLAB_STAFF_PASSWORD={password}\n")


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

    def checked_lab_port(deployment: NodeDeployment) -> int:
        port = ports_by_deployment.get(str(deployment.hostname))
        if port is None or str(deployment.ipv4_address) != LAB_LOOPBACK:
            raise CommandError("Refusing non-lab deployment in lab SSH transport")
        return port

    def recover_lab_port(deployment: NodeDeployment, key_file: Path, known_hosts: Path) -> int:
        del key_file, known_hosts
        return checked_lab_port(deployment)

    def lab_ssh_policy(
        self: AnsibleService, deployment: NodeDeployment, *, operator_public_keys: tuple[str, ...] | None = None
    ) -> Result[bool, str]:
        del self, operator_public_keys
        checked_lab_port(deployment)
        # The Debian lab's key-only daemon stays on its published NAT endpoint.
        # The Ubuntu SSH transition itself is exercised by test-ssh-docker.
        return Ok(True)

    def build_vars(self: AnsibleService, deployment: Any, extra_vars: dict[str, Any] | None = None) -> dict[str, Any]:
        built = real_build_vars(self, deployment, extra_vars)
        port = checked_lab_port(deployment)
        built["ansible_port"] = port
        built["ssh_port"] = 22  # Host forwarding port differs from the daemon's container port.
        return built

    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(outbound_http, "_resolve_dns", resolve))
        stack.enter_context(mock.patch.object(AnsibleService, "_wait_for_ssh", staticmethod(wait_for_ssh)))
        stack.enter_context(mock.patch("apps.infrastructure.ansible_service.recover_connection_port", recover_lab_port))
        stack.enter_context(mock.patch.object(AnsibleService, "_ensure_ssh_policy", lab_ssh_policy))
        stack.enter_context(mock.patch.object(AnsibleService, "_build_vars", build_vars))
        stack.enter_context(override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=state.known_hosts))
        yield
