"""Legacy retirement is explicit, installation-bound and never undone by ordinary deploys."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLATION = "11111111-2222-4333-8444-555555555555"
DIGEST = "a" * 64


def helper():
    path = ROOT / "deploy/ansible/roles/common/files/fail2ban_state.py"
    spec = importlib.util.spec_from_file_location("fail2ban_state", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = helper()
    tmp_path.chmod(0o700)
    for name, filename in (
        ("MARKER", "retired.json"),
        ("CONFIG", "config.json"),
        ("INSTALLATION", "installation.json"),
        ("DATABASE", "crowdsec.db"),
    ):
        monkeypatch.setattr(module, name, tmp_path / filename)
    monkeypatch.setattr(module, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(module, "ROOT_GID", tmp_path.stat().st_gid)
    with closing(sqlite3.connect(module.DATABASE)) as connection:
        connection.execute("CREATE TABLE machines(machine_id TEXT)")
        connection.execute("INSERT INTO machines VALUES (?)", ["praho-installation-" + INSTALLATION])
        connection.commit()
    module.DATABASE.chmod(0o640)
    info = module.DATABASE.stat()
    witness = {"device": info.st_dev, "inode": info.st_ino}
    for path, value in (
        (module.INSTALLATION, {"installation_id": INSTALLATION, "database_witness": witness}),
        (
            module.CONFIG,
            {
                "protocol": 1,
                "installation_id": INSTALLATION,
                "database_witness": witness,
                "configuration_digest": DIGEST,
                "simulation": False,
            },
        ),
    ):
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    return module


def write_marker(module, **changes):
    value = {
        "schema": 1,
        "installation_id": INSTALLATION,
        "configuration_digest": DIGEST,
        "state": "complete",
        **changes,
    }
    module.MARKER.write_text(json.dumps(value))
    module.MARKER.chmod(0o600)


def healthy():
    return {
        "simulation": False,
        "engine": {"active": True, "version": "1.8.2"},
        "bouncer": {"active": True, "version": "0.0.36-praho.1"},
        "configuration": {"qualified": True},
        "firewall": {"qualified": True},
    }


def test_no_marker_preserves_legacy_without_requiring_crowdsec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = helper()
    monkeypatch.setattr(module, "MARKER", tmp_path / "absent.json")
    assert module.inspect_state() == {"state": "absent"}


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": True},
        {"state": "ignored"},
        {"installation_id": "not-a-uuid"},
        {"installation_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"},
        {"configuration_digest": "broken"},
        {"extra": True},
    ],
)
def test_bad_retirement_state_cannot_fall_back_to_legacy(state, changes) -> None:
    write_marker(state, **changes)
    with pytest.raises(ValueError):
        state.inspect_state()


def test_retirement_survives_later_policy_changes_and_simulation(state) -> None:
    write_marker(state)
    config = json.loads(state.CONFIG.read_text())
    config.update(simulation=True, configuration_digest="b" * 64)
    state.CONFIG.write_text(json.dumps(config))
    assert state.inspect_state()["state"] == "complete"


@pytest.mark.parametrize("mode", [0o644, 0o660])
def test_retirement_marker_must_remain_private(state, mode: int) -> None:
    write_marker(state)
    state.MARKER.chmod(mode)
    with pytest.raises(ValueError):
        state.inspect_state()


def test_symlink_and_duplicate_json_keys_are_not_retirement_evidence(state) -> None:
    write_marker(state)
    other = state.MARKER.with_suffix(".other")
    state.MARKER.rename(other)
    state.MARKER.symlink_to(other)
    with pytest.raises(ValueError):
        state.inspect_state()
    state.MARKER.unlink()
    state.MARKER.write_text('{"schema":1,"schema":1}')
    state.MARKER.chmod(0o600)
    with pytest.raises(ValueError):
        state.inspect_state()


def test_marker_cannot_follow_a_replaced_database(state) -> None:
    write_marker(state)
    original = state.DATABASE.stat()
    replacement = state.DATABASE.with_suffix(".replacement")
    # Keep the old inode allocated until the valid replacement exists. Both databases
    # contain the same machine marker, so rejection must come from the physical witness.
    replacement.write_bytes(state.DATABASE.read_bytes())
    replacement.chmod(0o640)
    changed = replacement.stat()
    assert (changed.st_dev, changed.st_ino) != (original.st_dev, original.st_ino)
    replacement.replace(state.DATABASE)
    with closing(sqlite3.connect(state.DATABASE.as_uri() + "?mode=ro", uri=True)) as connection:
        assert connection.execute("SELECT machine_id FROM machines").fetchall() == [
            ("praho-installation-" + INSTALLATION,)
        ]
    with pytest.raises(ValueError, match="Installation database changed"):
        state.inspect_state()


@pytest.mark.parametrize(
    "group,key,value",
    [
        ("engine", "active", False),
        ("bouncer", "active", False),
        ("configuration", "qualified", False),
        ("firewall", "qualified", False),
    ],
)
def test_qualified_active_replacement_precedes_any_retirement_intent(
    state, monkeypatch: pytest.MonkeyPatch, group, key, value
) -> None:
    health = healthy()
    health[group][key] = value
    monkeypatch.setattr(state, "_health", lambda _config: health)
    with pytest.raises(ValueError):
        state.begin()
    assert not state.MARKER.exists()


def test_begin_records_durable_intent_only_after_qualified_enforcement(state, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state, "_health", lambda _config: healthy())
    first = state.begin()
    second = state.begin()
    assert first["changed"] is True and second["changed"] is False
    assert state.inspect_state()["state"] == "pending"
    assert state.MARKER.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "profile,remove_legacy",
    [(None, True), ("virtualmin-web-only-v2", True), ("virtualmin-web-only-v2+crowdsec-v1", False)],
)
def test_node_base_purge_is_unchanged_but_selected_extension_defers_retirement(profile, remove_legacy) -> None:
    import re  # noqa: PLC0415  # Test-local native expression evaluator.

    import yaml  # noqa: PLC0415
    from jinja2.nativetypes import NativeEnvironment  # noqa: PLC0415

    play = yaml.safe_load(
        (ROOT / "services/platform/infrastructure/ansible/playbooks/virtualmin_harden.yml").read_text()
    )[0]
    task = next(
        item for item in play["tasks"] if item.get("name") == "Purge unused authentication and file transfer packages"
    )
    context = {"ansible_facts": {"packages": {"fail2ban": [], "usermin": [], "proftpd-basic": [], "crowdsec": []}}}
    if profile is not None:
        context["security_policy_version"] = profile
    environment = NativeEnvironment()
    environment.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
    for name, value in task.get("vars", {}).items():
        context[name] = environment.from_string(value).render(context)
    removed = environment.from_string(task["ansible.builtin.apt"]["name"]).render(context)
    assert ("fail2ban" in removed) is remove_legacy
    assert {"usermin", "proftpd-basic"}.issubset(removed)
    assert "crowdsec" not in removed


@pytest.mark.parametrize("installed,active", [(True, False), (False, True)])
def test_completion_does_not_claim_retirement_while_legacy_remains(
    state, monkeypatch: pytest.MonkeyPatch, installed: bool, active: bool
) -> None:
    import subprocess  # noqa: PLC0415

    write_marker(state, state="pending")
    monkeypatch.setattr(state, "_health", lambda _config: healthy())
    monkeypatch.setattr(state, "JAIL", state.MARKER.parent / "absent-jail.local")

    def query(arguments, **_kwargs):
        if "dpkg-query" in arguments[0]:
            return subprocess.CompletedProcess(arguments, 0 if installed else 1, "installed" if installed else "", "")
        return subprocess.CompletedProcess(arguments, 0 if active else 3, "active" if active else "inactive", "")

    monkeypatch.setattr(state.subprocess, "run", query)
    with pytest.raises(ValueError, match="not been retired"):
        state.complete()
    assert state.inspect_state()["state"] == "pending"


def test_common_package_and_handler_paths_always_consult_retirement_state() -> None:
    import yaml  # noqa: PLC0415

    base = ROOT / "deploy/ansible/roles/common"
    tasks = yaml.safe_load((base / "tasks/main.yml").read_text())
    packages = next(task["apt"]["name"] for task in tasks if task.get("name") == "Install common packages")
    assert "fail2ban" not in packages
    assert any(task.get("ansible.builtin.import_tasks") == "fail2ban.yml" for task in tasks)
    legacy = yaml.safe_load((base / "tasks/fail2ban.yml").read_text())
    assert legacy[0]["ansible.builtin.import_tasks"] == "fail2ban_state.yml"
    assert all(task.get("when") == "praho_fail2ban_state.state == 'absent'" for task in legacy[1:])
    restart = yaml.safe_load((base / "tasks/fail2ban_restart.yml").read_text())
    assert restart[0]["ansible.builtin.import_tasks"] == "fail2ban_state.yml"
    assert restart[-1]["when"] == "praho_fail2ban_state.state == 'absent'"
