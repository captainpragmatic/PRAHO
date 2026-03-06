#!/usr/bin/env python3
"""
Pre-commit hook: Block new direct usage of settings.SECRET_KEY in application code.

Allowed locations:
- config/settings/ (Django settings files legitimately need SECRET_KEY)
- Lines with '# noqa: SECRET_KEY' annotation

Exit code 0 = pass, 1 = violation found.
"""

from __future__ import annotations

import re
import sys

PATTERN = re.compile(r"settings\.SECRET_KEY")
# Paths that are allowed to reference SECRET_KEY
ALLOWED_PATH_PREFIXES = ("config/settings/",)
NOQA_MARKER = "# noqa: SECRET_KEY"


def check_files(file_paths: list[str]) -> list[str]:
    """Check files for SECRET_KEY usage. Returns list of violation messages."""
    violations: list[str] = []

    for path in file_paths:
        if not path.endswith(".py"):
            continue

        # Allow settings files
        if any(path.startswith(prefix) or f"/{prefix}" in path for prefix in ALLOWED_PATH_PREFIXES):
            continue

        try:
            with open(path) as f:
                for line_num, line in enumerate(f, 1):
                    if PATTERN.search(line) and NOQA_MARKER not in line:
                        violations.append(
                            f"{path}:{line_num}: Direct settings.SECRET_KEY usage found. "
                            f"Use apps.common.key_derivation.derive_key() or add {NOQA_MARKER}"
                        )
        except OSError:
            continue

    return violations


def main() -> int:
    files = sys.argv[1:]
    if not files:
        return 0

    violations = check_files(files)
    if violations:
        print("SECRET_KEY isolation violations found:")
        for v in violations:
            print(f"  {v}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
