"""Runtime media stays out of both the repository index and integration test checkout."""

from __future__ import annotations

import subprocess
from pathlib import Path

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, default_storage

from scripts.lint_runtime_media import MEDIA_PATHS, tracked_media_files


def _git(root: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 -- fixed Git operations in this test's temporary repository
        ["git", *args], cwd=root, check=True, capture_output=True,  # noqa: S607 -- project Git on PATH
    )


def test_force_added_runtime_media_is_rejected_but_fixture_sources_are_allowed(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".gitignore").write_text("".join(f"/{path}/\n" for path in MEDIA_PATHS))
    fixture = tmp_path / "tests/fixtures/media/example.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("{}")
    _git(tmp_path, "add", "tests/fixtures/media/example.json")
    assert tracked_media_files(tmp_path) == []

    paths = [f"{directory}/probe.txt" for directory in MEDIA_PATHS]
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("runtime output")
    assert tracked_media_files(tmp_path) == [], "ignored and untracked local files are left alone"
    _git(tmp_path, "add", "--force", "--", *paths)
    assert tracked_media_files(tmp_path) == sorted(paths)
    _git(tmp_path, "update-index", "--force-remove", "--", *paths)
    assert tracked_media_files(tmp_path) == []
    assert all((tmp_path / name).read_text() == "runtime output" for name in paths)


def test_repository_tracks_no_runtime_media() -> None:
    assert tracked_media_files() == []


def test_integration_default_storage_writes_to_disposable_media() -> None:
    assert isinstance(default_storage, FileSystemStorage)
    root = Path(settings.MEDIA_ROOT)
    assert root.resolve() != (settings.BASE_DIR / "media").resolve()
    name = default_storage.save("integration/probe.txt", ContentFile(b"integration media"))
    assert (root / name).read_bytes() == b"integration media"
