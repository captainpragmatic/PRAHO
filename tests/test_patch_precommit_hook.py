"""#386: patch_precommit_hook.resolve_hooks_dir must work in a git worktree.

The script hard-coded `.git/hooks`. In a worktree `.git` is a *file* pointing at the
real gitdir, so that path does not exist and `make install` failed at the hook-patch
step. resolve_hooks_dir() now uses `git rev-parse --git-path hooks`, which resolves the
shared hooks directory in both a normal checkout and a worktree.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "patch_precommit_hook.py"


def _load_script_module() -> object:
    """Import the repo-root script as a module (it isn't on the import path)."""
    spec = importlib.util.spec_from_file_location("patch_precommit_hook", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(cwd: Path, *args: str) -> None:
    # Test helper with hardcoded git args in a throwaway temp repo — not untrusted input.
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603, S607


class ResolveHooksDirTests(unittest.TestCase):
    """resolve_hooks_dir resolves the shared hooks dir in both layouts."""

    def setUp(self) -> None:
        self.module = _load_script_module()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir()
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "t@example.com")
        _git(self.root, "config", "user.name", "T")
        (self.root / "f.txt").write_text("x\n")
        _git(self.root, "add", "f.txt")
        _git(self.root, "commit", "-q", "-m", "init")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _resolve_in(self, cwd: Path) -> Path:
        """Run resolve_hooks_dir() with the process cwd set to `cwd`."""
        prev = Path.cwd()
        os.chdir(cwd)
        try:
            return self.module.resolve_hooks_dir()
        finally:
            os.chdir(prev)

    def test_normal_checkout_resolves_hooks(self) -> None:
        resolved = self._resolve_in(self.root)
        # git rev-parse --git-path hooks yields a real, existing hooks directory.
        self.assertTrue((self.root / resolved).exists() or resolved.is_absolute())

    def test_worktree_dot_git_is_a_file(self) -> None:
        """Sanity: a worktree's .git is a file, which broke the old .git/hooks lookup."""
        wt = Path(self._tmp.name) / "wt"
        _git(self.root, "worktree", "add", "-q", "--detach", str(wt))
        self.assertTrue((wt / ".git").is_file())

    def test_worktree_resolves_to_existing_hooks(self) -> None:
        """The fix: from inside a worktree, resolve to an existing shared hooks directory."""
        wt = Path(self._tmp.name) / "wt"
        _git(self.root, "worktree", "add", "-q", "--detach", str(wt))

        resolved = self._resolve_in(wt)

        # Must be a real, existing directory — the old `.git/hooks` relative path did not exist.
        abs_resolved = resolved if resolved.is_absolute() else (wt / resolved)
        self.assertTrue(abs_resolved.exists(), f"resolved hooks dir does not exist: {abs_resolved}")


if __name__ == "__main__":
    unittest.main()
