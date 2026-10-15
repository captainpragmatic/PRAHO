"""A complete Docker backup records immutable source identity and an exact artifact pair."""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from deploy.scripts.backup_manifest import create, manifest_path
from tests.integration.test_deploy_scripts import Project


@pytest.mark.parametrize("platform_only", [False, True])
def test_complete_backup_records_private_identity_and_pair(tmp_path: Path, platform_only: bool) -> None:
    project = Project(tmp_path)
    completed = project.run("backup.sh", DOCKER_ABSENT_PORTAL="1" if platform_only else "")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    [dump] = (tmp_path / "backups").glob("praho_backup_*.sql.gz")
    path = manifest_path(dump)
    data = json.loads(path.read_text())
    assert data["format_version"] == 1 and data["database_major"] == 16
    assert set(data["images"]) == ({"platform", "qcluster"} if platform_only else {"platform", "portal", "qcluster"})
    assert data["images"]["platform"]["id"] == "sha256:" + "a" * 64
    assert data["images"]["platform"]["reference"] == "praho-platform:v1.0.0"
    for key in ("database", "media"):
        artifact = dump.parent / data[key]["file"]
        assert data[key]["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(dump.parent.glob("*.partial")) == []


def test_a_partial_pair_has_no_manifest(tmp_path: Path) -> None:
    dump = tmp_path / "praho_backup_incomplete.sql.gz"
    dump.write_bytes(b"database")
    with pytest.raises(ValueError, match="both nonempty"):
        create(dump)
    assert not manifest_path(dump).exists()


def test_metadata_failure_is_visible_but_preserves_pair_and_applies_retention(tmp_path: Path) -> None:
    project = Project(tmp_path)
    backups = tmp_path / "backups"
    backups.mkdir()
    old = backups / "praho_backup_old.metadata.json"
    old.write_text("{}")
    os.utime(old, (0, 0))
    completed = project.run("backup.sh", DOCKER_SOURCE_IMAGE="not-an-immutable-image")
    assert completed.returncode != 0
    assert "Backup pair retained" in completed.stdout
    assert len(list(backups.glob("*.sql.gz"))) == 1
    assert len(list(backups.glob("*.media.tar.gz"))) == 1
    assert list(backups.glob("*.metadata.json")) == []
