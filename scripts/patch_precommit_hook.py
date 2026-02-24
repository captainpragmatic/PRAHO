#!/usr/bin/env python3
"""
Patch .git/hooks/pre-commit for cross-platform venv resolution.

Replaces the static INSTALL_PYTHON line written by `pre-commit install` with
a dynamic block that resolves the correct venv based on the current OS:
  - macOS  → .venv-darwin/bin/python
  - Linux  → .venv-linux/bin/python

Also exports UV_PROJECT_ENVIRONMENT (absolute path) so that `uv run` calls
inside hooks use the same venv, regardless of the hook's working directory.

Safe to run multiple times (idempotent).
"""
from __future__ import annotations

import pathlib
import re
import sys

HOOK_PATH = pathlib.Path(".git/hooks/pre-commit")

DYNAMIC_BLOCK = """\
# Cross-platform venv resolution — injected by `make install` (patch_precommit_hook.py)
_PRAHO_UNAME=$(uname -s | tr '[:upper:]' '[:lower:]')
_PRAHO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
export UV_PROJECT_ENVIRONMENT="${_PRAHO_ROOT}/.venv-${_PRAHO_UNAME}"
INSTALL_PYTHON="${UV_PROJECT_ENVIRONMENT}/bin/python"\
"""

ALREADY_PATCHED_MARKER = "Cross-platform venv resolution"


def main() -> int:
    if not HOOK_PATH.exists():
        print(
            "❌  No pre-commit hook found at .git/hooks/pre-commit",
            file=sys.stderr,
        )
        print("   Run `pre-commit install` first, then re-run `make install`.", file=sys.stderr)
        return 1

    text = HOOK_PATH.read_text()

    if ALREADY_PATCHED_MARKER in text:
        print("ℹ️   Hook already patched — skipping.")
        return 0

    patched, count = re.subn(
        r"^INSTALL_PYTHON=.*$",
        DYNAMIC_BLOCK,
        text,
        flags=re.MULTILINE,
    )

    if count == 0:
        print(
            "⚠️   INSTALL_PYTHON line not found in hook — may already be patched or format changed.",
            file=sys.stderr,
        )
        return 0

    HOOK_PATH.write_text(patched)
    print("✅  Hook patched: .venv-darwin/ (macOS) or .venv-linux/ (Linux) resolved at runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
