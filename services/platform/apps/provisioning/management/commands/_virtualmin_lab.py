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
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from django.conf import settings
from django.core.management.base import CommandError
from django.test import override_settings

from apps.common.types import Err, Ok, Result

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
