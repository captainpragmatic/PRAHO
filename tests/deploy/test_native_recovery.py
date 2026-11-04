"""Code rollback cannot discard applied business migrations."""

import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from deploy.scripts import native_env


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
