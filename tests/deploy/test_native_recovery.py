"""Code rollback cannot discard applied business migrations."""

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from deploy.scripts import native_env


def test_deploy_cannot_skip_migration_compatibility_without_a_rollback_flag(tmp_path: Path) -> None:
    # Exercise the actual orchestration condition. A working explicit rollback
    # is the positive control for the same known migration refusal during deploy.
    root = tmp_path / "host"
    (root / "src").mkdir(parents=True)
    (root / ".venv-linux/bin").mkdir(parents=True)
    (root / ".venv-linux/bin/python").symlink_to(sys.executable)
    (root / ".env").write_text("")
    invoked, mutated = tmp_path / "guard-invoked", tmp_path / "checkout-mutated"
    helper = tmp_path / "guard.py"
    helper.write_text(
        f"import sys\nsys.path.insert(0, {str(native_env.ROOT)!r})\n"
        "from pathlib import Path\nfrom deploy.scripts.native_env import validate_rollback_migrations\n"
        f"Path({str(invoked)!r}).touch()\n"
        "validate_rollback_migrations({('common', '0002')}, {'services/platform/apps/common/migrations/0001.py'})\n"
    )
    tasks = yaml.safe_load((native_env.ROOT / "deploy/ansible/playbooks/native/quiesce.yml").read_text())
    guard = next(task for task in tasks if task["name"] == "Check rollback migration compatibility before checkout")
    guard.pop("become_user")
    guard["shell"] = guard["shell"].replace("/usr/local/lib/praho/native_migration_guard.py", str(helper))
    controller = Path(sys.executable).with_name("ansible-playbook")
    executable = str(controller) if controller.is_file() else (shutil.which("ansible-playbook") or "ansible-playbook")
    for operation in ("rollback", "deploy"):
        invoked.unlink(missing_ok=True)
        playbook = tmp_path / "play.yml"
        playbook.write_text(yaml.safe_dump([{
            "hosts": "localhost", "gather_facts": False,
            "vars": {"project_root": str(root), "native_operation": operation,
                     "native_checkout": {"stat": {"exists": True}}, "django_settings_module": "config.settings.test",
                     "praho_git_repo": str(tmp_path), "deploy_git_version": "a" * 40},
            "tasks": [guard, {"copy": {"content": "checkout happened", "dest": str(mutated)}}],
        }]))
        result = subprocess.run([executable, "-i", "localhost,", "-c", "local", str(playbook)],  # noqa: S603 -- actual local task, known refusal and disposable paths.
                                capture_output=True, text=True, check=False,
                                env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
                                     "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote")})
        assert result.returncode != 0, f"{operation} bypassed the migration guard and changed its checkout"
        assert invoked.exists() and not mutated.exists(), result.stdout + result.stderr


def test_rollback_rejects_applied_migrations_absent_from_target_revision() -> None:
    with pytest.raises(ValueError, match=r"billing\.0002"):
        native_env.validate_rollback_migrations({("billing", "0001"), ("billing", "0002")}, {
            "services/platform/apps/billing/migrations/0001.py",
        })


def test_rollback_accepts_a_target_retaining_every_applied_business_migration() -> None:
    native_env.validate_rollback_migrations({("billing", "0001")}, {
        "services/platform/apps/billing/migrations/0001.py",
        "services/platform/apps/billing/migrations/0002.py",
    })


def test_rollback_also_protects_applied_portal_session_state_migrations() -> None:
    paths = {"services/portal/apps/common/migrations/0001_initial.py"}
    native_env.validate_rollback_migrations({("common", "0001_initial")}, paths, service="portal")
    with pytest.raises(ValueError, match=r"common\.0002"):
        native_env.validate_rollback_migrations({("common", "0001_initial"), ("common", "0002")}, paths, service="portal")


def backup_pair(tmp_path: Path, root: str = "media") -> tuple[Path, Path]:
    dump = tmp_path / "praho_backup_fixture.dump"
    media = tmp_path / "praho_backup_fixture.media.tar.gz"
    dump.write_bytes(b"fixture-custom-format-database")
    with tarfile.open(media, "w:gz") as archive:
        entry = tarfile.TarInfo(f"{root}/example.txt")
        entry.size = 7
        archive.addfile(entry, io.BytesIO(b"fixture"))
    return dump, media


def test_recovery_metadata_binds_the_validated_exact_pair_to_the_prior_sha(tmp_path: Path) -> None:
    dump, media = backup_pair(tmp_path)
    with patch("deploy.scripts.native_env.subprocess.run") as restore:
        restore.return_value.returncode = 0
        metadata = native_env.validate_backup_pair(dump, media, "a" * 40)
    recorded = json.loads(metadata.read_text())
    assert recorded["release_sha"] == "a" * 40 and recorded["database_major"] == 16
    assert recorded["database"]["file"] == dump.name and recorded["media"]["file"] == media.name
    assert recorded["database"]["sha256"] != recorded["media"]["sha256"]
    assert metadata.stat().st_mode & 0o777 == 0o600
    assert restore.call_args.args[0][-2:] == ["--list", str(dump)]


def test_recovery_pair_preserves_an_explicit_custom_media_directory(tmp_path: Path) -> None:
    dump, media = backup_pair(tmp_path, root="private_uploads")
    with patch("deploy.scripts.native_env.subprocess.run") as restore:
        restore.return_value.returncode = 0
        metadata = native_env.validate_backup_pair(dump, media, "a" * 40)
    assert json.loads(metadata.read_text())["media"]["archive_root"] == "private_uploads"


def test_empty_tar_cannot_be_a_validated_media_recovery_point(tmp_path: Path) -> None:
    dump, media = backup_pair(tmp_path)
    with tarfile.open(media, "w:gz"):
        pass
    with patch("deploy.scripts.native_env.subprocess.run") as restore, pytest.raises(ValueError, match="backup"):
        restore.return_value.returncode = 0
        native_env.validate_backup_pair(dump, media, "a" * 40)
    assert not list(tmp_path.glob("*.recovery.json"))


@pytest.mark.parametrize("name,kind", [("../outside", tarfile.REGTYPE), ("/etc/outside", tarfile.REGTYPE),
                                     ("media/../../outside", tarfile.REGTYPE), ("other/outside", tarfile.REGTYPE),
                                     ("media/link", tarfile.SYMTYPE), ("media/link", tarfile.LNKTYPE)])
def test_media_pair_rejects_traversal_links_and_mixed_roots(tmp_path: Path, name: str, kind: bytes) -> None:
    dump, media = backup_pair(tmp_path)
    with tarfile.open(media, "w:gz") as archive:
        archive.addfile(tarfile.TarInfo("media/valid.txt"), io.BytesIO())
        unsafe = tarfile.TarInfo(name)
        unsafe.type, unsafe.linkname = kind, "/etc/outside"
        archive.addfile(unsafe, io.BytesIO())
    with patch("deploy.scripts.native_env.subprocess.run") as restore, pytest.raises(ValueError, match="backup"):
        restore.return_value.returncode = 0
        native_env.validate_backup_pair(dump, media, "a" * 40)
    assert not list(tmp_path.glob("*.recovery.json"))


@pytest.mark.parametrize("damage", ["database", "media"])
def test_invalid_pair_does_not_publish_recovery_metadata(tmp_path: Path, damage: str) -> None:
    dump, media = backup_pair(tmp_path)
    if damage == "media":
        media.write_bytes(b"damaged-archive")
    with patch("deploy.scripts.native_env.subprocess.run") as restore, pytest.raises(ValueError, match="backup"):
        restore.return_value.returncode = 1 if damage == "database" else 0
        native_env.validate_backup_pair(dump, media, "a" * 40)
    assert list(tmp_path.glob("*.recovery.json")) == []
