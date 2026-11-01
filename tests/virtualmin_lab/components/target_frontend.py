"""Explicit neutral-frontend preparation for the fixed, managed component lab target."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.management.commands._virtualmin_lab import (
    LAB_LOOPBACK,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)
from apps.provisioning.management.commands.virtualmin_lab_bootstrap import NODES
from apps.provisioning.virtualmin_models import VirtualminServer

_PREPARE = r"""
import importlib.util,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);info=root.lstat()
assert os.geteuid()==os.getegid()==0 and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
spec=importlib.util.spec_from_file_location('component_default',root/'praho-component-default.py')
defaults=importlib.util.module_from_spec(spec);spec.loader.exec_module(defaults)
bindings=defaults.apache.ApacheBindings()
default=Path('/etc/apache2/conf-enabled/praho-default-site.conf')
prepared=(root/'praho-default-site.conf').read_bytes()
assert not bindings.pending.exists() and not bindings.pending.is_symlink(),'Existing Apache binding work must be resolved explicitly'
if default.exists() or default.is_symlink():
 target=default.resolve(strict=True)
 assert target.parent in {default.parent,Path('/etc/apache2/conf-available')},'Foreign neutral default'
 assert target.stat().st_gid==0 and stat.S_IMODE(target.stat().st_mode)==0o644,'Unexpected neutral default ownership/mode'
 assert bindings.read(target,0o644)==prepared,'Existing neutral default differs from the shipped asset'
 assert not defaults.qualify_default(),'Existing neutral default needs explicit operator preparation'
 print('qualified')
else:
 if bindings.metadata.exists() or bindings.configuration.exists() or bindings.configuration.is_symlink():
  assert bindings.read(bindings.configuration,0o644)==bindings.render(bindings.current()),'Unqualified Apache binding state'
 docroot=Path('/var/www/praho-default')
 bindings.directory(docroot)
 assert docroot.stat().st_gid==0 and stat.S_IMODE(docroot.stat().st_mode)==0o755,'Unexpected neutral document-root ownership/mode'
 with bindings.transaction({default:0o644}):
  assert not default.exists() and not default.is_symlink(),'Neutral default appeared during fixture preparation'
  bindings.write(default,prepared,0o644)
  bindings.refresh();bindings.reload()
  assert not defaults.qualify_default(policy=bindings),'Explicit neutral default preparation failed'
 print('installed')
"""


def _managed_target() -> VirtualminServer:
    refuse_unless_lab_settings()
    node = load_state().node("vm-b")
    assert node == next(item for item in NODES if item.key == "vm-b"), "Unexpected managed lab target identity"
    server = VirtualminServer.objects.get(hostname=node.server_hostname)
    deployment = getattr(server, "node_deployment", None)
    assert deployment is not None and deployment.hostname == node.deployment_hostname
    assert deployment.ipv4_address == LAB_LOOPBACK and deployment.ssh_port == node.ssh_port
    assert server.api_port == node.api_port
    return server


def ensure_target_usage() -> None:
    """Qualify the actual managed-target writer even in the standalone suite."""
    server = _managed_target()
    with lab_transport(load_state()):
        outcome = AnsibleService().run_playbook(server.node_deployment, "virtualmin_usage.yml", timeout_seconds=600)
    assert outcome.is_ok(), "Managed lab target usage preparation failed"
    assert outcome.unwrap().success, "Managed lab target usage preparation did not complete"


def ensure_target_frontend() -> str:
    """Prepare only an absent lab-B default; existing qualified policy is read-only."""
    _managed_target()

    def execute(*arguments: str, payload: str | None = None) -> str:
        result = subprocess.run(  # noqa: S603 -- fixed managed lab B and literal fixture operations; no credentials
            ["docker", "exec", "-i", "--user", "root", "vmlab-b", *arguments],  # noqa: S607
            input=payload,
            text=True,
            capture_output=True,
            check=True,
            timeout=90,
        )
        return result.stdout.strip()

    directory = execute("mktemp", "-d", "/var/lib/praho-component-frontend.XXXXXXXX")
    assert re.fullmatch(r"/var/lib/praho-component-frontend\.[A-Za-z0-9]{8}", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        for name in ("praho-apache-bindings.py", "praho-component-default.py", "praho-default-site.conf"):
            execute("tee", directory + "/" + name, payload=(helpers / name).read_text())
        outcome = execute("python3", "-c", _PREPARE, directory)
        assert outcome in {"qualified", "installed"}, "Missing actual native frontend qualification"
        return outcome
    finally:
        execute("rm", "-rf", "--", directory)
