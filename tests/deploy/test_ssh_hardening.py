"""The SSH policy must reject unsafe adoption before touching live configuration."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from threading import Event
from types import ModuleType

import pytest
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "deploy/ansible/roles/ssh-hardening/files/check_config.py"


def check_config(tmp_path: Path, content: str, fragment: str = "") -> subprocess.CompletedProcess[str]:
    config = tmp_path / "sshd_config"
    config.write_text(content)
    snippets = tmp_path / "sshd_config.d"
    snippets.mkdir()
    (snippets / "50-cloud-init.conf").write_text(fragment)
    return subprocess.run(  # noqa: S603 -- fixed validator against disposable config
        [sys.executable, str(PREFLIGHT), str(config)], capture_output=True, text=True, check=False
    )


def test_stock_cloud_init_password_setting_is_adoptable(tmp_path: Path) -> None:
    result = check_config(
        tmp_path,
        "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nUsePAM yes\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n",
        "PasswordAuthentication yes\n",
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "restriction",
    [
        "Match User customer\n ChrootDirectory /srv/customer\n",
        "AllowUsers root deploy\n",
        "DenyGroups customers\n",
        "AuthorizedKeysCommand /usr/local/bin/keys\n",
        "AuthorizedKeysFile /custom/keys\n",
        "TrustedUserCAKeys /etc/ssh/ca.pub\n",
        "Include /opt/other/ssh.conf\n",
        "ListenAddress 192.0.2.1\n",
        "Subsystem sftp /opt/custom-sftp\n",
    ],
)
def test_custom_access_policy_is_rejected_in_includes(tmp_path: Path, restriction: str) -> None:
    result = check_config(tmp_path, "Include /etc/ssh/sshd_config.d/*.conf\n", restriction)
    assert result.returncode == 1
    assert "custom SSH policy" in result.stderr
    assert (tmp_path / "sshd_config.d/50-cloud-init.conf").read_text() == restriction


def test_repeated_include_cannot_recurse(tmp_path: Path) -> None:
    result = check_config(
        tmp_path, "Include /etc/ssh/sshd_config.d/*.conf\n", "Include /etc/ssh/sshd_config.d/*.conf\n"
    )
    assert result.returncode == 1
    assert "custom SSH policy" in result.stderr


def load_helper(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"ssh_{name}", PREFLIGHT.parent / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def transaction(tmp_path: Path) -> ModuleType:
    module = load_helper("transaction")
    module.LOCK_DIRECTORY = tmp_path / "lock"
    module.acquire("first")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "token").write_text("first")
    module.prepare(snapshot, "first")
    return module


def test_committed_phase_cannot_be_rolled_back_by_a_dispatched_timer(transaction: ModuleType, tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    transaction.commit(snapshot)
    transaction.release("first")
    transaction.acquire("new-owner")
    restored: list[Path] = []
    transaction.rollback(snapshot, restored.append)
    transaction.release("first")
    assert restored == []
    assert (snapshot / "state").read_text() == "committed"
    assert (transaction.LOCK_DIRECTORY / "owner").read_text() == "new-owner"


def test_commit_waits_for_rollback_and_refuses_to_report_success(transaction: ModuleType, tmp_path: Path) -> None:
    restoring, finish_restore, committing = Event(), Event(), Event()
    snapshot = tmp_path / "snapshot"
    restored: list[Path] = []

    def restore(path: Path) -> None:
        restoring.set()
        assert finish_restore.wait(5)
        restored.append(path)

    def commit() -> None:
        committing.set()
        transaction.commit(snapshot)

    with ThreadPoolExecutor(max_workers=2) as executor:
        rollback = executor.submit(transaction.rollback, snapshot, restore)
        assert restoring.wait(5)
        attempt = executor.submit(commit)
        assert committing.wait(5)
        try:
            with pytest.raises(FutureTimeout):
                attempt.result(timeout=0.05)
        finally:
            finish_restore.set()
        rollback.result(timeout=5)
        with pytest.raises(RuntimeError, match="rollback already started"):
            attempt.result(timeout=5)
    assert restored == [snapshot]
    assert (snapshot / "state").read_text() == "rolled-back"
    assert not transaction.LOCK_DIRECTORY.exists()


def test_failed_rollback_retains_ownership_and_can_resume(transaction: ModuleType, tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"

    def failed_restore(_path: Path) -> None:
        raise RuntimeError("simulated service restart failure")

    with pytest.raises(RuntimeError, match="restart failure"):
        transaction.rollback(snapshot, failed_restore)
    with pytest.raises(RuntimeError, match="unfinished"):
        transaction.release("first")
    with pytest.raises(FileExistsError):
        transaction.acquire("other")
    restored: list[Path] = []
    transaction.rollback(snapshot, restored.append)
    assert restored == [snapshot]
    assert not transaction.LOCK_DIRECTORY.exists()


def test_rollback_before_activation_prevents_stale_controller_writes(transaction: ModuleType, tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    restored: list[Path] = []
    transaction.rollback(snapshot, restored.append)
    transaction.acquire("new-owner")
    applied: list[Path] = []
    with pytest.raises(RuntimeError, match="refusing activation"):
        transaction.activate(snapshot, applied.append)
    assert applied == []
    assert restored == [snapshot]
    assert (transaction.LOCK_DIRECTORY / "owner").read_text() == "new-owner"


def test_activation_and_rollback_cannot_write_concurrently(transaction: ModuleType, tmp_path: Path) -> None:
    applying, finish_apply, rolling_back = Event(), Event(), Event()
    snapshot = tmp_path / "snapshot"
    writes: list[str] = []

    def apply(_path: Path) -> None:
        applying.set()
        assert finish_apply.wait(5)
        writes.append("activate")

    def rollback() -> None:
        rolling_back.set()
        transaction.rollback(snapshot, lambda _path: writes.append("restore"))

    with ThreadPoolExecutor(max_workers=2) as executor:
        activation = executor.submit(transaction.activate, snapshot, apply)
        assert applying.wait(5)
        recovery = executor.submit(rollback)
        assert rolling_back.wait(5)
        try:
            with pytest.raises(FutureTimeout):
                recovery.result(timeout=0.05)
        finally:
            finish_apply.set()
        activation.result(timeout=5)
        recovery.result(timeout=5)
    assert writes == ["activate", "restore"]
    assert (snapshot / "state").read_text() == "rolled-back"


@pytest.mark.parametrize("keys", [[".ssh/authorized_keys"], [".ssh/authorized_keys", ".ssh/authorized_keys2"]])
def test_key_paths_are_preserved_without_activating_disabled_keys(keys: list[str]) -> None:
    environment = Environment(autoescape=False)  # noqa: S701 -- SSH configuration, not HTML.
    template = environment.from_string((PREFLIGHT.parent.parent / "templates/sshd_config.j2").read_text())
    rendered = template.render(ssh_phase_ports=[9876], ssh_authorized_keys_files=keys)
    assert f"AuthorizedKeysFile {' '.join(keys)}\n" in rendered
    assert ("authorized_keys2" in rendered) == (".ssh/authorized_keys2" in keys)


@pytest.mark.parametrize(
    "override,options",
    [
        ({}, "SSHD_OPTS = -oPasswordAuthentication=yes\n"),
        ({"FragmentPath": "/etc/systemd/system/ssh.service"}, "SSHD_OPTS=\n"),
        ({"ExecStart": "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -f /custom/config ; ignore_errors=no ; }"}, "SSHD_OPTS=\n"),
        ({"Environment": "SSHD_OPTS=-f /custom/config"}, "SSHD_OPTS=\n"),
        ({"EnvironmentFiles": "/etc/custom-ssh (ignore_errors=yes)"}, "SSHD_OPTS=\n"),
    ],
)
def test_service_startup_cannot_override_verified_config(override: dict[str, str], options: str) -> None:
    validator = load_helper("check_config")
    properties = {
        "FragmentPath": "/usr/lib/systemd/system/ssh.service", "KillMode": "process",
        "DropInPaths": "", "Environment": "", "EnvironmentFiles": "/etc/default/ssh (ignore_errors=yes)",
        "ExecStart": "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; }",
    }
    validator.validate_startup(properties, 'SSHD_OPTS = ""\n')
    with pytest.raises(ValueError, match="custom SSH"):
        validator.validate_startup({**properties, **override}, options)
