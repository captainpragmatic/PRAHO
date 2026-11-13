#!/usr/bin/env python3
"""Decide whether a pull request needs the native deployment acceptance.

Reads changed file paths (one per line) from stdin and prints ``true`` or ``false``.

The native jobs feed the required ``integration-test`` check, so a wrong ``false`` would let a change
that breaks a native deploy merge untested. The rules therefore fail open:

- they list what cannot reach a native deploy, not what can; a path nobody listed runs it;
- no input (the diff could not be computed, or it was empty) prints ``true``.

Application code is inside: the native deploy migrates, collects static files and runs management
commands, and its cases assert views, templates and messages (and hard-code the latest migrations).
What is outside: prose, other layers' tests, other workflows and the CI-only scripts. Every push to
master runs the native jobs whatever changed.

integration.yml runs the BASE branch's copy of this file, so a pull request cannot change the rules
that judge it, and lists renames as both paths (``--no-renames``).

Usage:
    git diff --no-renames --name-only "$BASE"...HEAD | python3 scripts/ci_native_needed.py
"""

from __future__ import annotations

import re
import sys

OUTSIDE_NATIVE_DEPLOY: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"\.md$",
        r"^docs/",
        r"^LICENSE",
        r"^services/(platform|portal)/tests/",
        # Other layers' test directories; top-level files such as native_role_helpers.py stay inside.
        r"^tests/(?!deploy/)[^/]+/",
        r"^\.github/rulesets/",
        r"^\.github/workflows/(?!integration\.yml$)",
        # CI-only scripts: the release gate and the CI selectors never run on a deployed host.
        r"^scripts/(verify_release_candidate|ci_[a-z_]+_needed)\.py$",
    )
)


def native_needed(paths: list[str]) -> bool:
    """Return True unless every changed path is known not to reach a native deploy."""
    changed = [path.strip() for path in paths if path.strip()]
    if not changed:
        return True
    return not all(any(pattern.search(path) for pattern in OUTSIDE_NATIVE_DEPLOY) for path in changed)


def main() -> int:
    print("true" if native_needed(sys.stdin.read().splitlines()) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
