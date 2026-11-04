"""Actual native Ansible rendering exposes only explicitly enabled service-specific protection."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from deploy.scripts.native_env import read_env, runtime_environments
from tests.native_role_helpers import native_tasks

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/praho-native"
LOG_PATH = "/var/log/praho/portal/portal-auth.jsonl"
PLATFORM_FLAGS = {
    "PRAHO_CROWDSEC_SYNC_ENABLED": "true",
    "PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED": "true",
    "PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH": "/etc/praho/security/gateway.pub",
    "PRAHO_CROWDSEC_SSH_PRIVATE_KEY_PATH": "/var/lib/praho/security/gateway",
    "PRAHO_CROWDSEC_ACTIONS_ENABLED": "true",
    "PRAHO_CROWDSEC_REPLICATION_ENABLED": "true",
    "CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED": "true",
}


def _render_native_env(tmp_path: Path, configured: dict[str, str]):
    marker = secrets.token_hex(20)
    role_tasks = native_tasks(ROLE / "tasks/main.yml")
    named = {task["name"]: task for task in role_tasks}
    tasks = [named["Set Django environment variables from .env file"], named["Set Portal Django environment"]]
    assert all(task["no_log"] is True for task in tasks)
    gate = named.get("Require the qualified Portal authentication log path")
    if gate is not None:
        tasks.append(gate)
    for name, content, destination in (
        ("Write test Platform environment", "{{ django_env | to_json }}", "platform.json"),
        ("Write test Portal environment", "{{ portal_django_env | native_systemd_env }}", "portal.env"),
    ):
        tasks.append(
            {
                "name": name,
                "no_log": True,
                "diff": False,
                "copy": {
                    "content": content,
                    "dest": str(tmp_path / destination),
                    "mode": "0600",
                },
            }
        )
    deployed = {
        "DB_PASSWORD": "platform-db-" + marker,
        "DJANGO_SECRET_KEY": "platform-key-" + marker,
        "PORTAL_DJANGO_SECRET_KEY": "portal-key-" + marker,
        "PORTAL_DOMAIN": "portal.example.test",
        "PLATFORM_DOMAIN": "staff.example.test",
        "PLATFORM_API_BASE_URL": "https://staff.example.test/api",
        **configured,
    }
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "deployed_env": deployed,
                        "project_root": str(tmp_path),
                        "platform_port": 8700,
                        "portal_state_directory": str(tmp_path / "state"),
                        "django_settings_module": "config.settings.prod",
                        "native_topology": "split",
                    },
                    "tasks": tasks,
                }
            ]
        )
    )
    result = subprocess.run(  # noqa: S603  # Executes only extracted set_fact/assert and private test-output tasks locally.
        [
            shutil.which("ansible-playbook") or str(ROOT / ".venv-darwin/bin/ansible-playbook"),
            "-i",
            "localhost,",
            str(playbook),
            "--diff",
            "-vvv",
        ],
        cwd=ROOT / "deploy/ansible",
        capture_output=True,
        text=True,
        check=False,
        timeout=40,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
        },
    )
    assert marker not in result.stdout + result.stderr
    return result


def test_controller_preserves_portal_protection_settings_before_transfer() -> None:
    key = secrets.token_hex(20)
    platform, portal = runtime_environments(
        {
            "DJANGO_SECRET_KEY": "platform-only-key",
            "PORTAL_DJANGO_SECRET_KEY": "portal-only-key",
            "PLATFORM_DOMAIN": "staff.example.test",
            "PORTAL_DOMAIN": "portal.example.test",
            **PLATFORM_FLAGS,
            "CROWDSEC_AUTH_EVENTS_ENABLED": "true",
            "CROWDSEC_AUTH_PSEUDONYM_KEY": key,
            "CROWDSEC_AUTH_LOG_PATH": LOG_PATH,
        },
        "prod",
        "split",
    )
    assert portal["CROWDSEC_AUTH_EVENTS_ENABLED"] == "true"
    assert portal["CROWDSEC_AUTH_PSEUDONYM_KEY"] == key
    assert portal["CROWDSEC_AUTH_LOG_PATH"] == LOG_PATH
    assert not (set(PLATFORM_FLAGS) & set(portal))
    assert {name: platform[name] for name in PLATFORM_FLAGS} == PLATFORM_FLAGS


def test_controller_refuses_unqualified_enabled_auth_log_path_before_transfer() -> None:
    with pytest.raises(ValueError, match="qualified Portal authentication log path"):
        runtime_environments(
            {
                "DJANGO_SECRET_KEY": "platform-only-key",
                "PORTAL_DJANGO_SECRET_KEY": "portal-only-key",
                "PLATFORM_DOMAIN": "staff.example.test",
                "PORTAL_DOMAIN": "portal.example.test",
                "CROWDSEC_AUTH_EVENTS_ENABLED": "true",
                "CROWDSEC_AUTH_LOG_PATH": "/private/unacquired/auth.jsonl",
            },
            "prod",
            "split",
        )


@pytest.mark.parametrize("enabled", [True, False])
def test_native_protection_settings_reach_only_their_intended_service(tmp_path: Path, enabled: bool) -> None:
    key = secrets.token_hex(20)
    configured = {
        **PLATFORM_FLAGS,
        "CROWDSEC_AUTH_PSEUDONYM_KEY": key,
        "CROWDSEC_AUTH_EVENTS_ENABLED": str(enabled).lower(),
        "CROWDSEC_AUTH_LOG_PATH": LOG_PATH,
    }
    configured.update({name: "false" for name in PLATFORM_FLAGS if name.endswith("ENABLED") and not enabled})
    result = _render_native_env(tmp_path, configured)
    assert result.returncode == 0, result.stdout + result.stderr
    platform = json.loads((tmp_path / "platform.json").read_text())
    portal = read_env(tmp_path / "portal.env")
    assert {name: platform.get(name) for name in PLATFORM_FLAGS} == {name: configured[name] for name in PLATFORM_FLAGS}
    assert portal["CROWDSEC_AUTH_EVENTS_ENABLED"] == str(enabled).lower()
    assert portal["CROWDSEC_AUTH_PSEUDONYM_KEY"] == key
    assert portal["CROWDSEC_AUTH_LOG_PATH"] == LOG_PATH
    assert not (set(PLATFORM_FLAGS) & set(portal))
    assert "DB_PASSWORD" not in portal and "DJANGO_ENCRYPTION_KEY" not in portal
    assert "CROWDSEC_AUTH_PSEUDONYM_KEY" not in platform
    assert key not in result.stdout + result.stderr
    assert (tmp_path / "portal.env").stat().st_mode & 0o777 == 0o600


def test_native_protection_remains_disabled_without_explicit_flags(tmp_path: Path) -> None:
    result = _render_native_env(tmp_path, {})
    assert result.returncode == 0, result.stdout + result.stderr
    platform = json.loads((tmp_path / "platform.json").read_text())
    portal = read_env(tmp_path / "portal.env")
    assert not (set(PLATFORM_FLAGS) & set(platform))
    assert "CROWDSEC_AUTH_EVENTS_ENABLED" not in portal
    assert "CROWDSEC_AUTH_PSEUDONYM_KEY" not in portal
    assert portal["CROWDSEC_AUTH_LOG_PATH"] == LOG_PATH


@pytest.mark.parametrize("enabled", [True, False])
def test_enabled_native_acquisition_refuses_a_different_log_path_before_runtime_env_write(
    tmp_path: Path, enabled: bool
) -> None:
    result = _render_native_env(
        tmp_path,
        {
            "CROWDSEC_AUTH_EVENTS_ENABLED": str(enabled).lower(),
            "CROWDSEC_AUTH_LOG_PATH": "/private/unacquired/auth.jsonl",
        },
    )
    if enabled:
        assert result.returncode != 0
        assert not (tmp_path / "portal.env").exists()
        assert "qualified Portal authentication log path" in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert read_env(tmp_path / "portal.env")["CROWDSEC_AUTH_LOG_PATH"] == "/private/unacquired/auth.jsonl"
