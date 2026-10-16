"""PRAHO ships no deployment's identity (ADR-0061).

A deployment brings its name, contacts and marks through its environment, settings and brand
folder, so no tracked source, template, setting, script or document names one. Tests and
translation catalogs are exempt: tests may describe any operator, and catalogs keep obsolete
entries until the next extraction. QA reports and the changelog are history.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
# Built at runtime so this file does not match itself.
PREVIOUS_OPERATOR = "pragmatic" + "host"
EXEMPT_PARTS = {"tests", "test", "locale", "QA"}
EXEMPT_FILES = {"CHANGELOG.md"}
BINARY_SUFFIXES = {".mo", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip"}


def _tracked_files() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607  # git from PATH, as every developer and CI job has it
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [
        REPO_ROOT / name
        for name in listing.split("\0")
        if name
        and not EXEMPT_PARTS.intersection(Path(name).parts)
        and Path(name).name not in EXEMPT_FILES
        and Path(name).suffix.lower() not in BINARY_SUFFIXES
    ]


class NeutralIdentityTests(TestCase):
    def test_no_tracked_file_names_the_previous_operator(self) -> None:
        files = _tracked_files()
        # A listing that silently came back short would pass vacuously.
        self.assertGreater(len(files), 1000)
        offenders = [
            str(path.relative_to(REPO_ROOT))
            for path in files
            if path.is_file() and PREVIOUS_OPERATOR in path.read_text(encoding="utf-8", errors="ignore").lower()
        ]
        self.assertEqual(offenders, [])
