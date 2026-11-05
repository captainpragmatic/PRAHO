"""Native acceptance commands keep private authority and arguments explicit."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _invoke(
    tmp_path: Path, target: str, *, missing: str | None = None
) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
    report = tmp_path / "invocations.jsonl"
    spy = tmp_path / "record-python"
    spy.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        "with open(os.environ['NATIVE_COMMAND_REPORT'],'a') as target:\n"
        " target.write(json.dumps({'argv':sys.argv[1:],'primary':os.environ.get('NATIVE_VM_MANIFEST'),"
        "'cleanup':os.environ.get('PRAHO_NATIVE_CLEANUP_ONLY'),'native':os.environ.get('PRAHO_NATIVE_LAB')})+'\\n')\n"
    )
    spy.chmod(0o700)
    environment = {
        **os.environ,
        "NATIVE_COMMAND_REPORT": str(report),
        "NATIVE_VM_MANIFEST": str(tmp_path / "primary authority ' $(not-a-command).json"),
        "NATIVE_PEER_MANIFEST": str(tmp_path / "peer authority.json"),
        "PRAHO_NATIVE_SMTP_MANIFEST": str(tmp_path / "smtp authority.json"),
        "NATIVE_UI_AUTHORITY": str(tmp_path / "ui authority.json"),
        "NATIVE_SMTP_EMAIL_LOG_ID": "6ab71902-36b1-4abe-a37f-713ff2f5d42b",
        "NATIVE_BOUNDARY_MINUTES": "75",
        "NATIVE_ACCEPTANCE_LIFETIME_SECONDS": "10800",
        "PRAHO_NATIVE_CLEANUP_ONLY": "1",
    }
    if missing:
        environment[missing] = ""
    result = subprocess.run(  # noqa: S603 -- Canonical recipes, with both Python commands replaced by an owned recorder.
        [
            shutil.which("make") or "make",
            "--no-print-directory",
            target,
            "PYTHON_SHARED=" + shlex.quote(str(spy)),
            "PYTHON_PLATFORM_MANAGE=" + shlex.quote(str(spy)),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    records = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
    return result, records


@pytest.mark.parametrize(
    ("target", "action"),
    [
        ("native-commercial-staff-setup", "staff-setup"),
        ("native-commercial-setup", "setup"),
        ("native-peer-intent", "peer-intent"),
        ("native-peer-create", "create-peer"),
        ("native-peer-export", "export-peer"),
        ("native-commercial-verify", "verify"),
        ("native-peer-destroy", "peer-destroy"),
    ],
)
def test_commercial_commands_use_primary_authority_and_closed_actions(tmp_path: Path, target: str, action: str) -> None:
    result, records = _invoke(tmp_path, target)
    assert result.returncode == 0, result.stderr
    assert len(records) == 1
    record = records[0]
    assert record["argv"] == [
        "hosting_native_acceptance",
        action,
        "--manifest",
        str(tmp_path / "primary authority ' $(not-a-command).json"),
        "--peer-manifest",
        str(tmp_path / "peer authority.json"),
        "--boundary-minutes",
        "75",
        "--settings=config.settings.native",
    ]
    assert record["native"] == "1"
    assert record["cleanup"] == ("1" if action == "peer-destroy" else None)
    assert record["primary"] == str(tmp_path / "primary authority ' $(not-a-command).json")


@pytest.mark.parametrize(
    ("target", "script", "authority_flag", "authority_name"),
    [
        ("native-smtp-serve", "smtp_capture.py", "--smtp-manifest", "smtp authority.json"),
        ("native-portal-serve", "portal_runner.py", "--ui-authority", "ui authority.json"),
    ],
)
def test_transport_servers_receive_literal_owned_paths(
    tmp_path: Path, target: str, script: str, authority_flag: str, authority_name: str
) -> None:
    result, records = _invoke(tmp_path, target)
    assert result.returncode == 0, result.stderr
    assert len(records) == 1
    assert records[0]["argv"] == [
        "tests/virtualmin_lab/native/" + script,
        "serve",
        "--manifest",
        str(tmp_path / "primary authority ' $(not-a-command).json"),
        authority_flag,
        str(tmp_path / authority_name),
        "--lifetime-seconds",
        "10800",
    ]
    assert records[0]["cleanup"] is None


def test_smtp_verification_passes_one_explicit_log_id_as_data(tmp_path: Path) -> None:
    result, records = _invoke(tmp_path, "native-smtp-verify")
    assert result.returncode == 0, result.stderr
    assert records[0]["argv"] == [
        "tests/virtualmin_lab/native/smtp_capture.py",
        "verify",
        "--manifest",
        str(tmp_path / "primary authority ' $(not-a-command).json"),
        "--smtp-manifest",
        str(tmp_path / "smtp authority.json"),
        "--email-log-id",
        "6ab71902-36b1-4abe-a37f-713ff2f5d42b",
    ]


def test_peer_kernel_probe_never_switches_the_primary_django_authority(tmp_path: Path) -> None:
    result, records = _invoke(tmp_path, "test-virtualmin-peer-quotas")
    assert result.returncode == 0, result.stderr
    assert records[0]["argv"] == [
        "tests/virtualmin_lab/native/provider_vm.py",
        "verify",
        "--manifest",
        str(tmp_path / "peer authority.json"),
    ]
    assert records[0]["primary"] == str(tmp_path / "primary authority ' $(not-a-command).json")


@pytest.mark.parametrize(
    ("target", "command", "option"),
    [
        ("native-virtualmin-schedules", "setup_scheduled_tasks", "--virtualmin-only"),
        ("native-billing-schedules", "setup_scheduled_tasks", "--billing-only"),
        ("native-worker", "qcluster", None),
    ],
)
def test_schedules_and_worker_use_the_same_native_profile(
    tmp_path: Path, target: str, command: str, option: str | None
) -> None:
    result, records = _invoke(tmp_path, target)
    assert result.returncode == 0, result.stderr
    assert records[0]["argv"] == [command, *([option] if option else []), "--settings=config.settings.native"]
    assert records[0]["native"] == "1"
    assert records[0]["cleanup"] is None


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("native-commercial-setup", "NATIVE_VM_MANIFEST"),
        ("native-peer-intent", "NATIVE_PEER_MANIFEST"),
        ("native-smtp-serve", "PRAHO_NATIVE_SMTP_MANIFEST"),
        ("native-smtp-verify", "NATIVE_SMTP_EMAIL_LOG_ID"),
        ("native-portal-serve", "NATIVE_UI_AUTHORITY"),
    ],
)
def test_missing_authority_refuses_before_launching_python(tmp_path: Path, target: str, field: str) -> None:
    result, records = _invoke(tmp_path, target, missing=field)
    assert result.returncode != 0
    assert field in result.stderr
    assert records == []
