"""Native configuration stays data, and secrets never enter deployment output or argv."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from deploy.scripts.native_env import pgpass, read_env, run_native, systemd_env

ROOT = Path(__file__).resolve().parents[2]
PASSWORD_KEY = "DB_" + "PASSWORD"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("plain", "plain"),
        ("'a$b#c'", "a$b#c"),
        ('"two words"', "two words"),
        (r"'a\b'", r"a\b"),
        ("", ""),
        ('"a\\"b"', 'a"b'),
    ],
)
def test_values_decode_once(tmp_path: Path, raw: str, expected: str) -> None:
    path = tmp_path / "config"
    path.write_text(f"VALUE={raw}\n")
    assert read_env(path) == {"VALUE": expected}


@pytest.mark.parametrize(
    "raw",
    [
        "${OTHER}",
        "$(touch /tmp/unwanted)",
        "`id`",
        "'unterminated",
        '"value"#comment',
        "value #comment",
        "two words",
        "value\\",
    ],
)
def test_unsupported_forms_fail_without_values(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "config"
    path.write_text(f"VALUE={raw}\n")
    with pytest.raises(ValueError) as caught:
        read_env(path)
    assert "1:VALUE" in str(caught.value)
    assert raw not in str(caught.value)


def test_last_declaration_wins_and_encoded_env_cannot_execute(tmp_path: Path) -> None:
    path = tmp_path / "config"
    path.write_text("VALUE=old\nVALUE='$(touch marker) `id` $literal # value'\n")
    values = read_env(path)
    encoded = tmp_path / "runtime.env"
    encoded.write_text(systemd_env(values))
    result = subprocess.run(  # noqa: S603  # fixed script and disposable env fixture
        [shutil.which("bash") or "/bin/bash", "-c", '. "$1"; printf "%s" "$VALUE"', "_", str(encoded)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == values["VALUE"]
    assert not (tmp_path / "marker").exists()


def test_passfile_escapes_libpq_separators() -> None:
    assert pgpass({PASSWORD_KEY: r"a:b\c"}) == "localhost:5432:praho:praho:a\\:b\\\\c\n"


@pytest.mark.parametrize("name", ["PLATFORM_ALLOWED_CIDRS", "PRAHO_SSH_ALLOWED_CIDRS"])
@pytest.mark.parametrize("cidrs", ["0.0.0.0/0", "::/0", "192.0.2.1/24", "192.0.2.1/32,::1/128", "invalid"])
def test_staff_cidrs_reject_invalid_or_world_access(tmp_path: Path, name: str, cidrs: str) -> None:
    path = tmp_path / "config"
    path.write_text(f"{name}='{cidrs}'\n")
    with pytest.raises(ValueError, match=name):
        read_env(path)


def test_launcher_forwards_the_ssh_allowlist_to_ansible(tmp_path: Path) -> None:
    cidrs = "192.0.2.10/32 2001:db8::/64"
    path = tmp_path / "config"
    path.write_text(f"PRAHO_SSH_ALLOWED_CIDRS='{cidrs}'\n")
    with patch.dict(os.environ, {}, clear=True), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 0
        assert run_native(read_env(path), path, "staging", fetch_backup=None, version="", ssh_only=True) == 0
    assert run.call_args.kwargs["env"]["PRAHO_SSH_ALLOWED_CIDRS"] == cidrs


def test_launcher_rejects_a_world_allowlist_from_the_shell(tmp_path: Path) -> None:
    with (
        patch.dict(os.environ, {"PRAHO_SSH_ALLOWED_CIDRS": "0.0.0.0/0"}, clear=True),
        patch("deploy.scripts.native_env.subprocess.run") as run,
        pytest.raises(ValueError, match="PRAHO_SSH_ALLOWED_CIDRS"),
    ):
        run_native({}, tmp_path / "env", "staging", fetch_backup=None, version="", ssh_only=True)
    run.assert_not_called()


def test_launcher_ignores_an_unused_platform_allowlist_in_the_shell(tmp_path: Path) -> None:
    with (
        patch.dict(os.environ, {"PLATFORM_ALLOWED_CIDRS": "0.0.0.0/0"}, clear=True),
        patch("deploy.scripts.native_env.subprocess.run") as run,
    ):
        run.return_value.returncode = 0
        assert run_native({}, tmp_path / "env", "staging", fetch_backup=None, version="", ssh_only=True) == 0


def test_caddy_only_launcher_selects_only_caddy_tasks(tmp_path: Path) -> None:
    with patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 0
        assert run_native({}, tmp_path / "env", "staging", fetch_backup=None, version="", caddy_only=True) == 0
    assert run.call_args.args[0][-2:] == ["--tags", "caddy"]


def test_launcher_does_not_export_application_secrets(tmp_path: Path) -> None:
    marker = secrets.token_urlsafe(24)
    with patch.dict(os.environ, {}, clear=True), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 0
        assert (
            run_native(
                {PASSWORD_KEY: marker, "PRAHO_SERVER_IP": "192.0.2.1"},
                tmp_path / "env",
                "prod",
                fetch_backup=None,
                version="v1.2.3",
            )
            == 0
        )
    assert marker not in str(run.call_args)
    assert run.call_args.kwargs["env"] == {"PRAHO_SERVER_IP": "192.0.2.1"}
    assert "cli_version=v1.2.3" in run.call_args.args[0]


def test_launcher_recovers_verified_new_port_after_interrupted_deployment(tmp_path: Path) -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22",
              "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(tmp_path / "known_hosts")}
    with patch("deploy.scripts.native_env.socket.create_connection"), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "0\n"
        assert run_native(values, tmp_path / "env", "staging", fetch_backup=None, version="", ssh_only=True) == 0
    assert run.call_count == 2
    proof = run.call_args_list[0].args[0]
    assert "StrictHostKeyChecking=yes" in proof
    assert "ControlPath=none" in proof
    assert "PreferredAuthentications=publickey" in proof
    assert run.call_args.kwargs["env"]["PRAHO_SSH_PORT"] == "9876"


def test_launcher_does_not_fall_back_after_new_port_rejects_identity(tmp_path: Path) -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22",
              "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(tmp_path / "known_hosts")}
    with patch("deploy.scripts.native_env.socket.create_connection"), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 255
        with pytest.raises(ValueError, match="9876"):
            run_native(values, tmp_path / "env", "staging", fetch_backup=None, version="")
    assert run.call_count == 1  # No Ansible invocation after a trust/authentication failure.


def test_launcher_uses_explicit_bootstrap_port_only_when_new_listener_is_absent(tmp_path: Path) -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22"}
    with patch("deploy.scripts.native_env.socket.create_connection", side_effect=ConnectionRefusedError), patch(
        "deploy.scripts.native_env.subprocess.run"
    ) as run:
        run.return_value.returncode = 0
        assert run_native(values, tmp_path / "env", "staging", fetch_backup=None, version="") == 0
    assert run.call_count == 1
    assert run.call_args.kwargs["env"]["PRAHO_SSH_PORT"] == "22"


@pytest.mark.parametrize("copy_fails", [False, True])
def test_lookup_and_private_copy_hide_secrets_under_verbose_diff(tmp_path: Path, copy_fails: bool) -> None:
    marker = secrets.token_urlsafe(24)
    env_file = tmp_path / "operator.env"
    env_file.write_text(f"{PASSWORD_KEY}='{marker}:$literal'\n")
    destination = tmp_path / "missing/passfile" if copy_fails else tmp_path / "passfile"
    role_tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml").read_text())
    selected = [
        task
        for task in role_tasks
        if task.get("name")
        in {
            "Read .env file locally for role variables",
            "Parse .env vars for role use",
            "Install private PostgreSQL passfile for unattended backups",
        }
    ]
    assert len(selected) == 3
    for task in selected:
        task.pop("notify", None)
        assert task["no_log"] is True
    selected[-1]["copy"] = {"content": "{{ native_configuration['pgpass'] }}", "dest": str(destination), "mode": "0600"}
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {"env_file_path": str(env_file)},
                    "tasks": selected,
                }
            ]
        )
    )
    result = subprocess.run(  # noqa: S603  # local-only playbook and disposable credentials
        [shutil.which("ansible-playbook") or "ansible-playbook", "-i", "localhost,", str(playbook), "--diff", "-vvv"],
        cwd=ROOT / "deploy/ansible",
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode != 0) == copy_fails, result.stdout + result.stderr
    assert marker not in result.stdout + result.stderr
    if copy_fails:
        assert not destination.exists()
        assert "censored" in result.stdout
    else:
        assert destination.stat().st_mode & 0o777 == 0o600
        assert destination.read_text() == pgpass(read_env(env_file))
    assert "PGPASSWORD" not in (ROOT / "deploy/ansible/roles/praho-native/templates/backup-native.sh.j2").read_text()
