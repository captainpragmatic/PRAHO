"""The effective role must keep Platform responsibilities off Portal hosts."""

import os
import shutil
import subprocess
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/praho-native"


def test_split_portal_unit_can_start_without_platform_paths() -> None:
    context = {"project_root": "/opt/praho", "portal_user": "praho-portal", "portal_group": "praho-portal",
               "portal_state_directory": "/var/lib/praho-portal", "portal_memory_max": "512M", "portal_port": 8701,
               "gunicorn_worker_class_portal": "gthread", "gunicorn_workers_portal": 2,
               "gunicorn_threads_portal": 4, "native_topology": "split"}
    unit = Environment(undefined=StrictUndefined).from_string(  # noqa: S701 -- systemd unit
        (ROLE / "templates/praho-portal.service.j2").read_text()).render(context)
    assert "praho-platform.service" not in unit
    assert "InaccessiblePaths=-/opt/praho/.env -/opt/praho/credentials -/opt/praho/media" in unit
    context.update(deployed_env={"MEDIA_ROOT": "/opt/praho/private-uploads"}, native_topology="combined")
    combined = Environment(undefined=StrictUndefined).from_string(  # noqa: S701 -- systemd unit
        (ROLE / "templates/praho-portal.service.j2").read_text()).render(context)
    assert "InaccessiblePaths=-/opt/praho/private-uploads" in combined


def test_workers_and_backup_scheduling_obey_persistent_holds() -> None:
    for name in ("praho-qcluster.service.j2", "praho-backup.service.j2"):
        unit = (ROLE / "templates" / name).read_text()
        assert "ConditionPathExists=!/etc/praho-native/hold-workers" in unit


def test_portal_contamination_check_is_read_only_and_precedes_roles() -> None:
    playbook = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native.yml").read_text())
    first = playbook[0]
    assert first["any_errors_fatal"] is True
    tasks = first["tasks"]
    inspect = next(task for task in tasks if task["name"] == "Inspect Portal contamination")
    assert inspect["stat"]["path"] == "{{ item }}"
    assert {"/opt/praho/.env", "/opt/praho/credentials", "/var/lib/postgresql",
            "/etc/systemd/system/praho-platform.service", "/etc/praho/operator_authorized_keys"} <= set(inspect["loop"])
    assert tasks[-1]["assert"]["that"]
    assert "roles" not in first


def test_coordinated_playbook_passes_real_ansible_syntax_check(tmp_path: Path) -> None:
    result = subprocess.run([shutil.which("ansible-playbook") or "ansible-playbook",  # noqa: S603
                             "--syntax-check", "-i", "inventory/native-single-server.yml", "playbooks/native.yml",
                             "-e", "@group_vars/all.yml", "-e", "native_operation=deploy", "-e", "praho_env=staging"],
                            cwd=ROOT / "deploy/ansible", capture_output=True, text=True,
                            env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local")}, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_portal_health_utility_only_probes_owned_services(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "systemctl"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NATIVE_HEALTH_CALLS"\n')
    stub.chmod(0o755)
    (tmp_path / "curl").write_text("#!/bin/sh\nexit 0\n")
    (tmp_path / "curl").chmod(0o755)
    script = tmp_path / "health.sh"
    script.write_text(Environment(undefined=StrictUndefined).from_string(  # noqa: S701 -- shell script
        (ROLE / "templates/health-check.sh.j2").read_text()
    ).render(native_platform=False, native_portal=True, platform_port=8700, portal_port=8701))
    result = subprocess.run([shutil.which("bash") or "bash", str(script)], capture_output=True, text=True, check=False,  # noqa: S603 -- rendered repository script in a temporary fixture
                            env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "NATIVE_HEALTH_CALLS": str(calls)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == ["is-active --quiet praho-portal", "is-active --quiet caddy"]
