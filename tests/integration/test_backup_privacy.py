"""Backup permissions do not depend on the caller's umask or traverse links."""

import shlex
import stat
from pathlib import Path

import pytest

from tests.integration.test_deploy_scripts import Project
from tests.integration.test_media_root import _native, _render, _run


@pytest.mark.parametrize("native", [False, True])
def test_backup_is_private_under_a_permissive_umask(tmp_path: Path, native: bool) -> None:
    if native:
        root, env = _native(tmp_path)
        script = _render("backup-native.sh.j2", root)
    else:
        project = Project(tmp_path)
        root, env = project.root, project.env
        script = (root / "deploy/scripts/backup.sh").read_text()
    backups = root / "backups"
    backups.mkdir(mode=0o755)
    legacy = backups / "praho_backup_legacy.dump"
    legacy.write_bytes(b"existing backup")
    legacy.chmod(0o644)
    metadata = backups / "praho_backup_legacy.metadata.json"
    metadata.write_text("{}")
    metadata.chmod(0o644)
    outside = root / "outside"
    outside.write_bytes(b"outside")
    outside.chmod(0o644)
    (backups / "praho_backup_link.dump").symlink_to(outside)
    nested = backups / "unrelated"
    nested.mkdir()
    nested_file = nested / "praho_backup_nested.dump"
    nested_file.write_bytes(b"nested")
    nested_file.chmod(0o644)
    executable = root / "backup-private.sh" if native else root / "deploy/scripts/backup.sh"
    if native:
        executable.write_text(script)
    completed = _run("umask 000;\nexec bash " + shlex.quote(str(executable)), env)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert stat.S_IMODE(backups.stat().st_mode) == 0o700
    assert stat.S_IMODE(legacy.stat().st_mode) == 0o600
    produced = [path for path in backups.iterdir() if path.is_file() and not path.is_symlink()]
    assert len(produced) >= 3
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in produced)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert stat.S_IMODE(nested_file.stat().st_mode) == 0o644
    assert list(backups.glob("*.partial")) == []


@pytest.mark.parametrize("native", [False, True])
def test_linked_backup_directory_fails_before_dumping(tmp_path: Path, native: bool) -> None:
    if native:
        root, env = _native(tmp_path)
        script = _render("backup-native.sh.j2", root)
    else:
        project = Project(tmp_path)
        root, env = project.root, project.env
        script = (root / "deploy/scripts/backup.sh").read_text()
    outside = tmp_path / "outside-backups"
    outside.mkdir(mode=0o755)
    (root / "backups").symlink_to(outside, target_is_directory=True)
    completed = _run(script, env)
    assert completed.returncode != 0
    assert "must not be a symlink" in completed.stderr
    assert list(outside.iterdir()) == []
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755
