#!/usr/bin/env python3
"""Decide whether a pull request needs the Virtualmin lab.

Reads changed file paths (one per line) from stdin and prints ``true`` or ``false``.

The lab job is a required check, and a job skipped by its ``if:`` reports success, so a wrong
``false`` would let a breaking change merge untested. The rules therefore fail open, twice over:

- they list what cannot reach the lab, not what can. The provisioning code imports half the
  platform (billing, customers, orders, tickets, domains, notifications, ui...), so a list of what
  reaches the lab goes stale with every new import; a path nobody listed runs the lab;
- no input (the diff could not be computed, or it was empty) prints ``true``.

virtualmin-lab-pr.yml runs the BASE branch's copy of this file, so a pull request cannot change the
rules that judge it, and lists renames as both paths (``--no-renames``).

Usage:
    git diff --no-renames --name-only "$BASE"...HEAD | python3 scripts/ci_lab_needed.py
"""

from __future__ import annotations

import re
import sys

# Paths that cannot change what the PR lab suites exercise: prose, the portal service (the lab
# drives Platform only), the test suites of other layers, and CI files other than the lab's own.
OUTSIDE_THE_LAB: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"\.md$",
        r"^docs/",
        r"^LICENSE",
        r"^services/portal/",
        r"^services/platform/tests/",
        r"^tests/(?!virtualmin_lab/)",
        r"^\.github/rulesets/",
        r"^\.github/workflows/(?!virtualmin-lab)",
    )
)


def lab_needed(paths: list[str]) -> bool:
    """Return True unless every changed path is known not to reach the lab."""
    changed = [path.strip() for path in paths if path.strip()]
    if not changed:
        return True
    return not all(any(pattern.search(path) for pattern in OUTSIDE_THE_LAB) for path in changed)


def main() -> int:
    print("true" if lab_needed(sys.stdin.read().splitlines()) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
