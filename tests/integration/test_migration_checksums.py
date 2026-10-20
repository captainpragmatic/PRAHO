"""The repository migration baseline is append-only, including across manifest edits."""

from pathlib import Path

import pytest

from scripts.migration_checksums import ManifestError, extend_manifest, verify_manifest


def initial(tmp_path: Path) -> tuple[Path, dict]:
    migration = tmp_path / "services/platform/apps/example/migrations/0001_initial.py"
    migration.parent.mkdir(parents=True)
    migration.write_text("original migration\n")
    manifest = {"version": 1, "baseline_commit": "a" * 40, "files": {}}
    return migration, extend_manifest(tmp_path, manifest)


def test_edited_or_deleted_frozen_migrations_fail(tmp_path: Path) -> None:
    migration, manifest = initial(tmp_path)
    migration.write_text("edited migration\n")
    with pytest.raises(ManifestError, match="changed"):
        verify_manifest(tmp_path, manifest)
    migration.unlink()
    with pytest.raises(ManifestError, match="missing"):
        verify_manifest(tmp_path, manifest)


def test_extension_only_adds_new_migrations(tmp_path: Path) -> None:
    migration, manifest = initial(tmp_path)
    new = migration.with_name("0002_add_field.py")
    new.write_text("new migration\n")
    with pytest.raises(ManifestError, match="unlisted"):
        verify_manifest(tmp_path, manifest)
    extended = extend_manifest(tmp_path, manifest)
    verify_manifest(tmp_path, extended, previous=manifest)
    assert manifest["files"].items() <= extended["files"].items()
    assert len(extended["files"]) == 2


def test_extension_cannot_regenerate_a_changed_baseline(tmp_path: Path) -> None:
    migration, manifest = initial(tmp_path)
    migration.write_text("edited migration\n")
    with pytest.raises(ManifestError, match="changed"):
        extend_manifest(tmp_path, manifest)


def test_ci_rejects_concealment_by_replacing_manifest_hashes(tmp_path: Path) -> None:
    migration, previous = initial(tmp_path)
    migration.write_text("edited migration\n")
    forged = extend_manifest(tmp_path, {**previous, "files": {}})
    with pytest.raises(ManifestError, match="baseline"):
        verify_manifest(tmp_path, forged, previous=previous)


def test_ci_rejects_removing_a_frozen_entry(tmp_path: Path) -> None:
    _, previous = initial(tmp_path)
    forged = {**previous, "files": {}}
    with pytest.raises(ManifestError, match="baseline"):
        verify_manifest(tmp_path, forged, previous=previous)
