"""Exercise the deployment boundaries reported by the PR review."""

import json
import os
import runpy
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/praho-native/tasks"


def ansible(tmp_path: Path, tasks: list[dict], variables: dict) -> subprocess.CompletedProcess[str]:
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars": {"ansible_python_interpreter": sys.executable, **variables},
                    "tasks": tasks,
                }
            ]
        )
    )
    executable = Path(sys.executable).with_name("ansible-playbook")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"all": {"children": {"praho_platform": {"hosts": {"localhost": {}}}}}}))
    return subprocess.run(  # noqa: S603 -- repository tasks against disposable local state
        [
            str(executable) if executable.is_file() else (shutil.which("ansible-playbook") or "ansible-playbook"),
            "-i",
            str(inventory),
            "-c",
            "local",
            str(playbook),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
        },
        timeout=60,
    )


@pytest.mark.parametrize("mode", ["combined", "split"])
def test_effective_portal_environment_uses_topology_instead_of_operator_api_override(tmp_path: Path, mode: str) -> None:
    task = yaml.safe_load((ROLE / "portal.yml").read_text())[0]
    output = tmp_path / "effective.json"
    result = ansible(
        tmp_path,
        [task, {"copy": {"content": "{{ portal_django_env | to_json }}", "dest": str(output)}}],
        {
            "native_topology": mode,
            "project_root": "/opt/praho",
            "platform_port": 8700,
            "portal_state_directory": "/var/lib/praho-portal",
            "django_settings_module": "config.settings.prod",
            "deployed_env": {
                "PORTAL_DJANGO_SECRET_KEY": "fixture",
                "PORTAL_DOMAIN": "portal.example.test",
                "PLATFORM_API_BASE_URL": "https://staff.example.test/api",
            },
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    effective = json.loads(output.read_text())
    assert effective["PLATFORM_API_BASE_URL"] == (
        "http://127.0.0.1:8700/api" if mode == "combined" else "https://staff.example.test/api"
    )


def test_rsync_repairs_receiver_ownership_before_git_verification() -> None:
    tasks = yaml.safe_load((ROLE / "shared.yml").read_text())
    names = [task["name"] for task in tasks]
    assert (
        names.index("Deploy code via rsync") < names.index("Set source ownership") < names.index("Get deployed git SHA")
    )


@pytest.mark.parametrize("service", ["platform", "portal"])
@pytest.mark.parametrize("existing_state", [False, True])
def test_checkout_alone_does_not_mean_a_recoverable_installation(
    tmp_path: Path, service: str, existing_state: bool
) -> None:
    name = "quiesce.yml" if service == "platform" else "portal-rollback.yml"
    tasks = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native" / name).read_text())
    if service == "platform":
        guard = next(task for task in tasks if task["name"] == "Check rollback migration compatibility before checkout")
        condition = guard["when"]
    else:
        plays = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native.yml").read_text())
        play = next(play for play in plays if play["name"] == "Protect applied Portal migrations before code checkout")
        condition = play["tasks"][0]["when"]
    invoked = tmp_path / "recovery-invoked"
    result = ansible(
        tmp_path,
        [{"copy": {"content": "guard invoked", "dest": str(invoked)}, "when": condition}],
        {
            "native_checkout": {"stat": {"exists": True}},
            "native_operation": "deploy",
            "native_platform_state": existing_state,
            "native_portal_state": existing_state,
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert invoked.exists() is existing_state, "An empty checkout cannot supply installed backup/migration helpers"


def test_existing_operation_cannot_clear_another_owners_holds(tmp_path: Path) -> None:
    gate = tmp_path / "hold-platform"
    gate.touch()
    tasks = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native/release.yml").read_text())
    # Exercise the actual release prefix through its first gate removal. Systemd
    # restoration follows this boundary and is covered by real deployment tests.
    release = []
    for task in tasks:
        if "file" in task and task["file"].get("state") == "absent":
            task["file"]["path"] = str(gate)
            release.append(task)
            break
        release.append(task)
    for task in release:
        if task.get("include_tasks") == "lock-owner.yml":
            task["include_tasks"] = str(ROOT / "deploy/ansible/playbooks/native/lock-owner.yml")
    lock = tmp_path / "operation"
    lock.mkdir()
    (lock / "owner").write_text("another-controller\n")
    result = ansible(
        tmp_path, release, {"native_operation_token": "this-controller", "native_operation_lock_directory": str(lock)}
    )
    assert result.returncode != 0 and gate.exists(), "Another controller's maintenance hold was cleared"
    assert "This controller no longer owns" in result.stdout, result.stdout + result.stderr
    (lock / "owner").write_text("this-controller\n")
    owned = ansible(
        tmp_path, release, {"native_operation_token": "this-controller", "native_operation_lock_directory": str(lock)}
    )
    assert owned.returncode == 0 and not gate.exists(), owned.stdout + owned.stderr


def test_saved_plan_is_decoded_with_initialized_provider_schemas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "deploy/scripts"))
    plan = tmp_path / "adoption.tfplan"
    plan.touch()
    evidence = {
        "prior_state": {
            "values": {
                "root_module": {
                    "resources": [
                        {"address": "hcloud_server.platform", "type": "hcloud_server", "values": {"id": "1"}},
                        {"address": "hcloud_server.portal[0]", "type": "hcloud_server", "values": {"id": "2"}},
                    ]
                }
            }
        },
        "resource_changes": [],
    }
    with (
        patch.object(
            sys, "argv", ["check_native_adoption_plan.py", "--plan", str(plan), "--existing-topology", "split"]
        ),
        patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(evidence), "")) as run,
        pytest.raises(SystemExit) as exit_info,
    ):
        runpy.run_path(str(ROOT / "deploy/scripts/check_native_adoption_plan.py"), run_name="__main__")
    assert exit_info.value.code == 0
    assert run.call_args.kwargs.get("cwd") == ROOT / "deploy/terraform"
    assert run.call_args.args[0][-1] == str(plan.resolve())


def test_independent_controllers_acquire_one_persistent_platform_lock(tmp_path: Path) -> None:
    lock = tmp_path / "platform-operation"
    controllers = [tmp_path / name for name in ("controller-one", "controller-two")]
    for directory in controllers:
        directory.mkdir()
    tasks = yaml.safe_load((ROOT / "deploy/ansible/playbooks/native/lock.yml").read_text())
    for task in tasks:
        if "copy" in task:
            # The disposable local target uses the test user's identity. Native
            # acceptance separately verifies the actual root-owned host lock.
            task["copy"].pop("owner", None)
            task["copy"].pop("group", None)
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [
            executor.submit(
                ansible,
                directory,
                tasks,
                {
                    "native_operation_token": directory.name,
                    "native_operation_lock_directory": str(lock),
                    "native_journal_directory": str(directory),
                },
            )
            for directory in controllers
        ]
        results = [future.result() for future in pending]
    assert sorted(result.returncode == 0 for result in results) == [False, True], [result.stdout for result in results]
    winner = next(directory for directory, result in zip(controllers, results, strict=True) if result.returncode == 0)
    assert (lock / "owner").read_text().strip() == winner.name
    assert lock.stat().st_mode & 0o777 == 0o700
    assert (winner / "operation-acquired").exists()
    loser = next(directory for directory in controllers if directory != winner)
    assert not (loser / "operation-acquired").exists()


def test_rsync_command_preserves_the_targets_pinned_ssh_policy(tmp_path: Path) -> None:
    recorded = tmp_path / "rsync-arguments"
    sender = tmp_path / "rsync"
    sender.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$RSYNC_CAPTURE_FILE"\n')
    sender.chmod(0o755)
    task = next(
        task for task in yaml.safe_load((ROLE / "shared.yml").read_text()) if task["name"] == "Deploy code via rsync"
    )
    task.pop("notify")
    inventory, playbook = tmp_path / "hosts.json", tmp_path / "transport.yml"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        "target": {
                            "ansible_host": "192.0.2.10",
                            "ansible_user": "root",
                            "ansible_connection": "ssh",
                            "ansible_rsync_path": str(sender),
                            "ansible_ssh_common_args": f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={tmp_path}/pins",
                        }
                    }
                }
            }
        )
    )
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "target",
                    "gather_facts": False,
                    "vars": {
                        "project_root": str(tmp_path / "target"),
                        "native_source_directory": str(tmp_path),
                        "deploy_method": "rsync",
                    },
                    "tasks": [task],
                }
            ]
        )
    )
    controller = Path(sys.executable).with_name("ansible-playbook")
    result = subprocess.run(  # noqa: S603 -- real action/module; capture only the external rsync boundary
        [str(controller), "-i", str(inventory), str(playbook)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
            "RSYNC_CAPTURE_FILE": str(recorded),
        },
    )
    assert result.returncode == 0 and recorded.exists(), result.stdout + result.stderr
    arguments = recorded.read_text()
    assert "StrictHostKeyChecking=no" not in arguments and "UserKnownHostsFile=/dev/null" not in arguments, arguments
    assert "StrictHostKeyChecking=yes" in arguments and f"UserKnownHostsFile={tmp_path}/pins" in arguments, arguments
