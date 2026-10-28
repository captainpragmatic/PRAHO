#!/usr/bin/env python3
"""Decide whether a pull request needs the Virtualmin lab.

Reads changed file paths (one per line) from stdin and prints ``true`` or ``false``.

The lab job is a required check, and a job skipped by its ``if:`` reports success, so a wrong
``false`` would let a breaking change merge untested. The rules therefore fail open: no input
(the diff could not be computed, or it was empty) prints ``true``, and so does any path the lab
code imports from or runs through. Narrow these rules only with evidence from real runs.

Usage:
    git diff --name-only "$BASE"...HEAD | python3 scripts/ci_lab_needed.py
"""

from __future__ import annotations

import re
import sys

# What the lab exercises: the provisioning and infrastructure apps, the node playbooks, the lab
# itself, the shared code and settings they import, the dependencies, and the lab's own wiring.
LAB_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        # The lab bootstrap creates currencies, customers and staff users, so their apps count too.
        r"^services/platform/apps/(provisioning|infrastructure|common|audit|settings|billing|customers|users)/",
        r"^services/platform/infrastructure/ansible/",
        r"^services/platform/config/",
        r"^deploy/virtualmin-lab/",
        r"^tests/virtualmin_lab/",
        r"^(Makefile|pyproject\.toml|uv\.lock)$",
        r"^\.github/workflows/virtualmin-lab\.yml$",
        r"^\.github/actions/virtualmin-lab-setup/",
        r"^scripts/ci_lab_needed\.py$",
    )
)


def lab_needed(paths: list[str]) -> bool:
    """Return True when any path can change what the lab tests, or when there is nothing to judge."""
    changed = [path.strip() for path in paths if path.strip()]
    if not changed:
        return True
    return any(pattern.search(path) for path in changed for pattern in LAB_PATH_PATTERNS)


def main() -> int:
    print("true" if lab_needed(sys.stdin.read().splitlines()) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
