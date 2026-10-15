"""Reject runtime media in the Git index, including files force-added past .gitignore."""

from __future__ import annotations

import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MEDIA_PATHS = ("media", "services/platform/media", "services/portal/media")


def tracked_media_files(root: Path = PROJECT_ROOT) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", *MEDIA_PATHS],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return sorted(path.decode() for path in result.stdout.split(b"\0") if path)


def main() -> int:
    paths = tracked_media_files()
    for path in paths:
        print(f"❌ [Media] Runtime media must not be tracked: {path}")
    if not paths:
        print("✅ [Media] No runtime media is tracked")
    return int(bool(paths))


if __name__ == "__main__":
    raise SystemExit(main())
