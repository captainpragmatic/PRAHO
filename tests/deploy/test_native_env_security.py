"""Native configuration stays data, and secrets never enter deployment output or argv."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from deploy.scripts.native_env import pgpass, read_env, recover_ssh_port, run_native, systemd_env
from tests.native_role_helpers import native_tasks

ROOT = Path(__file__).resolve().parents[2]
PASSWORD_KEY = "DB_" + "PASSWORD"


def test_native_application_environment_never_enters_ansible_ssh_arguments() -> None:
    # Ansible serializes `environment` into the SSH command, including with no_log.
    paths = [*ROOT.glob("deploy/ansible/roles/praho-native/tasks/*.yml"),
             *ROOT.glob("deploy/ansible/playbooks/native*.yml"),
             *ROOT.glob("deploy/ansible/playbooks/native/*.yml")]
    violations = []

    def inspect(nodes: list[dict], path: Path) -> None:
        for node in nodes:
            environment = str(node.get("environment", ""))
            if any(key in environment for key in ("django_env", "deployed_env", "SECRET", "PASSWORD", "ENCRYPTION", "CREDENTIAL")):
                violations.append(f"{path.name}: {node.get('name')}")
            for section in ("tasks", "pre_tasks", "post_tasks", "block", "rescue", "always"):
                inspect(node.get(section, []), path)

    for path in paths:
        inspect(yaml.safe_load(path.read_text()), path)
    assert not violations, "Application credentials enter SSH argv: " + "; ".join(violations)


def test_native_command_loads_literal_credentials_from_a_private_file(tmp_path: Path) -> None:
    values = {"DJANGO_SECRET_KEY": secrets.token_urlsafe(40) + '$`"\\ complex', "PORTAL_LOG_DIR": "private"}
    environment = tmp_path / "private.env"
    environment.write_text(systemd_env(values))
    environment.chmod(0o600)
    wrapper = ROOT / "deploy/scripts/native_exec.sh"
    assert wrapper.is_file()
    completed = subprocess.run(  # noqa: S603 -- fixed helper; credentials travel only in a private file.
        ["/bin/bash", str(wrapper), str(environment), "--console", "--", shutil.which("env") or "/usr/bin/env"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert f"DJANGO_SECRET_KEY={values['DJANGO_SECRET_KEY']}\n" in completed.stdout
    assert "PORTAL_LOG_DIR=\n" in completed.stdout


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


@pytest.fixture
def launcher_values(tmp_path: Path) -> dict[str, str]:
    pins, keys = tmp_path / "known_hosts", tmp_path / "keys.pub"
    pins.write_text("fixture host key\n")
    keys.write_text("ssh-ed25519 fixture\n")
    return {"PRAHO_NATIVE_TOPOLOGY": "combined", "PRAHO_SERVER_IP": "192.0.2.1",
            "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(pins), "PRAHO_SSH_PUBLIC_KEYS_FILE": str(keys),
            "PRAHO_SSH_ALLOWED_CIDRS": "192.0.2.10/32", "PLATFORM_DOMAIN": "staff.example.test",
            "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": "192.0.2.1/32",
            "PORTAL_DOMAIN": "portal.example.test", "DJANGO_SECRET_KEY": "platform-key",
            "PORTAL_DJANGO_SECRET_KEY": "portal-key", "DB_PASSWORD": "private-fixture",
            "HMAC_SECRET": "peer-key", "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "callback-key",
            "PORTAL_HMAC_SECRET": "p" * 40, "PORTAL_HMAC_CREDENTIALS": json.dumps({"portal-001": "p" * 40})}


def launch_snapshot(values: dict[str, str], tmp_path: Path, **options: bool) -> dict:
    snapshot = {}
    def run(command: list[str], **kwargs: object):
        inventory = json.loads(Path(command[command.index("-i") + 1]).read_text())
        parameters = json.loads(Path(command[-1][1:]).read_text())
        snapshot.update(inventory=inventory, parameters=parameters, command=command)
        for role in ("platform", "portal"):
            if key := parameters.get(f"native_{role}_env_file"):
                snapshot[role] = read_env(Path(key))
                assert Path(key).stat().st_mode & 0o777 == 0o600
        return subprocess.CompletedProcess(command, 0)
    with patch("deploy.scripts.native_env.validate_release") as release_check, patch("deploy.scripts.native_env.subprocess.run", side_effect=run), patch(
        "deploy.scripts.native_env.resolve_addresses", return_value={"192.0.2.1"}
    ):
        assert run_native(values, tmp_path / "env", "staging", fetch_backup=None, version="a" * 40, **options) == 0
        if not (options.get("ssh_only") or options.get("caddy_only")):
            release_check.assert_called_once_with("https://github.com/captainpragmatic/PRAHO.git", "a" * 40)
    return snapshot


def test_launcher_forwards_the_ssh_allowlist_to_ansible(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    snapshot = launch_snapshot(launcher_values, tmp_path, ssh_only=True)
    host = snapshot["inventory"]["all"]["children"]["praho"]["hosts"]["platform"]
    assert host["native_ssh_allowed_cidrs"] == "192.0.2.10/32"


def test_launcher_rejects_a_world_allowlist_from_the_shell(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    del launcher_values["PRAHO_SSH_ALLOWED_CIDRS"]
    with patch.dict(os.environ, {"PRAHO_SSH_ALLOWED_CIDRS": "0.0.0.0/0"}, clear=True), pytest.raises(ValueError, match="CIDRS"):
        run_native(launcher_values, tmp_path / "env", "staging", fetch_backup=None, version="", ssh_only=True)


def test_launcher_ignores_an_unused_platform_allowlist_in_the_shell(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    with patch.dict(os.environ, {"PLATFORM_ALLOWED_CIDRS": "0.0.0.0/0"}, clear=True):
        assert launch_snapshot(launcher_values, tmp_path, ssh_only=True)["parameters"]["native_operation"] == "ssh"


def test_peer_allowlists_use_the_same_effective_values_in_validation_and_role_files(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    name, cidrs = "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS", "192.0.2.15/32 2001:db8::15/128"
    del launcher_values[name]
    with patch.dict(os.environ, {name: cidrs}, clear=True):
        snapshot = launch_snapshot(launcher_values, tmp_path)
    assert snapshot["platform"][name] == cidrs
    assert snapshot["portal"][name] == cidrs


def test_caddy_only_launcher_selects_only_caddy_tasks(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    assert launch_snapshot(launcher_values, tmp_path, caddy_only=True)["parameters"]["native_operation"] == "edge"


def test_launcher_does_not_export_application_secrets(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    marker = secrets.token_urlsafe(24)
    launcher_values[PASSWORD_KEY] = marker
    snapshot = launch_snapshot(launcher_values, tmp_path)
    assert marker not in json.dumps(snapshot["inventory"])
    assert marker not in json.dumps(snapshot["parameters"])
    assert marker not in json.dumps(snapshot["command"])
    assert marker not in json.dumps(snapshot["portal"])
    assert snapshot["platform"][PASSWORD_KEY] == marker
    assert snapshot["parameters"]["deploy_git_version"] == "a" * 40


def test_combined_https_callbacks_require_explicit_self_egress_before_mutation(tmp_path: Path, launcher_values: dict[str, str]) -> None:
    del launcher_values["PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS"]
    with pytest.raises(ValueError, match=r"callback.*egress"):
        launch_snapshot(launcher_values, tmp_path)


def test_launcher_recovers_verified_new_port_after_interrupted_deployment(tmp_path: Path) -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22", "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(tmp_path / "pins")}
    with patch("deploy.scripts.native_env.socket.create_connection"), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode, run.return_value.stdout = 0, "0\n"
        recover_ssh_port(values, "staging")
    proof = run.call_args.args[0]
    assert "StrictHostKeyChecking=yes" in proof and "ControlPath=none" in proof
    assert "PreferredAuthentications=publickey" in proof
    assert values["PRAHO_SSH_PORT"] == "9876"


def test_launcher_does_not_fall_back_after_new_port_rejects_identity(tmp_path: Path) -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22", "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": str(tmp_path / "pins")}
    with patch("deploy.scripts.native_env.socket.create_connection"), patch("deploy.scripts.native_env.subprocess.run") as run:
        run.return_value.returncode = 255
        with pytest.raises(ValueError, match="9876"):
            recover_ssh_port(values, "staging")
    assert values["PRAHO_SSH_PORT"] == "22"


def test_launcher_uses_explicit_bootstrap_port_only_when_new_listener_is_absent() -> None:
    values = {"PRAHO_SERVER_IP": "192.0.2.1", "PRAHO_SSH_PORT": "22"}
    with patch("deploy.scripts.native_env.socket.create_connection", side_effect=ConnectionRefusedError):
        recover_ssh_port(values, "staging")
    assert values["PRAHO_SSH_PORT"] == "22"


@pytest.mark.parametrize("copy_fails", [False, True])
def test_lookup_and_private_copy_hide_secrets_under_verbose_diff(tmp_path: Path, copy_fails: bool) -> None:
    marker = secrets.token_urlsafe(24)
    env_file = tmp_path / "operator.env"
    env_file.write_text(f"{PASSWORD_KEY}='{marker}:$literal'\n")
    destination = tmp_path / "missing/passfile" if copy_fails else tmp_path / "passfile"
    role_tasks = native_tasks(ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml")
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
