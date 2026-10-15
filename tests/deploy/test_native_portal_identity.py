"""Native Portal owns its session/log state without sharing Platform's identity."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/praho-native"


def test_identity_and_filesystem_boundaries_cover_every_portal_writer() -> None:
    unit = (ROLE / "templates/praho-portal.service.j2").read_text()
    assert "User={{ portal_user }}" in unit and "Group={{ portal_group }}" in unit
    assert "ProtectSystem=strict" in unit and "ProtectHome=yes" in unit
    assert "ReadWritePaths=/var/log/praho/portal {{ portal_state_directory }}" in unit
    assert "InaccessiblePaths={{ project_root }}/.env {{ project_root }}/credentials {{ project_root }}/media" in unit
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    named = {task["name"]: task for task in tasks}
    state = named["Create private Portal writable directories"]
    assert state["file"]["owner"] == "{{ portal_user }}" and state["file"]["mode"] == "0700"
    for name in ("Run Portal migrations", "Check Portal deployment"):
        assert named[name]["become_user"] == "{{ portal_user }}"
    assert named["Collect Portal static files"]["become_user"] == "{{ project_user }}"
    env = named["Install filtered Portal runtime environment"]["copy"]
    assert env["owner"] == "root" and env["group"] == "{{ portal_group }}" and env["mode"] == "0640"
    cron = named["Setup Portal counter cull cron job"]["cron"]
    assert cron["user"] == "{{ portal_user }}" and ">> /var/log/praho/portal/cull.log" in cron["job"]
    assert "su {{ portal_user }} {{ portal_group }}" in (ROLE / "templates/praho-portal.logrotate.j2").read_text()


def test_legacy_state_and_log_gates_precede_host_mutation() -> None:
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    names = [task["name"] for task in tasks]
    gate = names.index("Require explicit Portal log migration on existing hosts")
    assert gate < names.index("Create isolated Portal group") < names.index("Create keyrings directory")
    path_gate = tasks[names.index("Require explicit Portal state migration on existing hosts")]
    assert "SESSION_DB_PATH" in str(path_gate["assert"]["that"])
    assert "portal.sqlite3" in str(path_gate["assert"]["that"])
    ownership_gate = tasks[gate]["assert"]["that"]
    assert "pw_name" in str(ownership_gate) and "portal_user" in str(ownership_gate)


def test_real_preflight_refuses_legacy_state_before_any_host_change(tmp_path: Path) -> None:
    import os  # noqa: PLC0415
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    names = {task["name"]: task for task in tasks}
    selected = [names["Inspect legacy Portal session store"], names["Require explicit Portal state migration on existing hosts"]]
    legacy = tmp_path / "src/services/portal/portal.sqlite3"
    legacy.parent.mkdir(parents=True)
    play = [{"hosts": "localhost", "gather_facts": False, "vars": {
        "project_root": str(tmp_path), "deployed_env": {}, "portal_state_directory": str(tmp_path / "state")},
        "tasks": [*selected, {"copy": {"content": "changed", "dest": str(tmp_path / "mutation")}}]}]
    path = tmp_path / "preflight.yml"
    path.write_text(yaml.safe_dump(play))
    command = [shutil.which("ansible-playbook") or "ansible-playbook", "-i", "localhost,", "-c", "local", str(path)]
    environment = {**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible"), "ANSIBLE_NOCOLOR": "1"}
    fresh = subprocess.run(command, env=environment, capture_output=True, text=True, check=False, timeout=40)  # noqa: S603
    assert fresh.returncode == 0, fresh.stdout + fresh.stderr
    (tmp_path / "mutation").unlink()
    legacy.write_bytes(b"preserved-session-state")
    existing = subprocess.run(command, env=environment, capture_output=True, text=True, check=False, timeout=40)  # noqa: S603
    assert existing.returncode != 0
    assert "Move Portal state while stopped" in existing.stdout
    assert not (tmp_path / "mutation").exists()
    assert legacy.read_bytes() == b"preserved-session-state"
