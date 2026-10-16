#!/usr/bin/env python3
"""List the platform test modules that only mean something on PostgreSQL.

A module is PostgreSQL-gated when it branches on ``connection.vendor`` being PostgreSQL or
SQLite, or skips itself with a message that names PostgreSQL. On SQLite those tests skip, so the default
test run proves nothing about them. CI feeds this list to the platform runner under
``config.settings.ci`` so a new gated module is picked up without anyone editing a workflow.

Prints one Django dotted label per line, sorted. Stdlib only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PLATFORM = Path(__file__).resolve().parents[1] / "services" / "platform"
TESTS = PLATFORM / "tests"

# `connection.vendor == "postgresql"`, `!=`, and the same through an alias or a variable.
VENDOR_GATE = re.compile(r"""vendor\s*(?:==|!=)\s*["']postgresql["']""")
# `connection.vendor == "sqlite"` or `!=`: the other branch, or the skipped test, is what runs on
# PostgreSQL, so it never runs at all unless a PostgreSQL step selects the module.
SQLITE_BRANCH = re.compile(r"""vendor\s*(?:==|!=)\s*["']sqlite["']""")
# `self.skipTest("... PostgreSQL ...")`, `@skipUnless(..., "Requires PostgreSQL ...")`.
SKIP_MESSAGE = re.compile(r"""skip\w*\([^)]*?["'][^"']*postgres""", re.IGNORECASE | re.DOTALL)


def is_gated(source: str) -> bool:
    """Whether a test module's source carries a PostgreSQL gate."""
    return bool(VENDOR_GATE.search(source) or SQLITE_BRANCH.search(source) or SKIP_MESSAGE.search(source))


def gated_modules(tests_dir: Path = TESTS) -> list[str]:
    """Dotted labels (relative to services/platform) of every gated test module."""
    return [
        ".".join(path.relative_to(tests_dir.parent).with_suffix("").parts)
        for path in sorted(tests_dir.rglob("test*.py"))
        if is_gated(path.read_text(encoding="utf-8"))
    ]


def main() -> int:
    labels = gated_modules()
    if not labels:
        print("no PostgreSQL-gated test modules found: the scan is broken", file=sys.stderr)
        return 1
    print("\n".join(labels))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
