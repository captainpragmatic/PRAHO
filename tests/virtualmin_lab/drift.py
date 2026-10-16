"""Compare a fresh contract recording with the committed fixtures and report every difference.

    python drift.py --fresh <dir> --committed <dir>

Both directories hold `<virtualmin version>/<program>.json`. Exit status 0: identical. 1: they differ
(the differences are printed as unified diffs per program and case). 2: nothing to compare.
Plain stdlib, so the lab runner can call it with no Django.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any


def _load(directory: Path) -> dict[str, dict[str, Any]]:
    return {path.name: json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))}


def _lines(value: Any) -> list[str]:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).splitlines()


def compare(fresh: Path, committed: Path) -> list[str]:
    """Human-readable differences between two recordings of one Virtualmin version; empty when identical."""
    report: list[str] = []
    before, after = _load(committed), _load(fresh)
    report.extend(f"{name}: committed, but the fresh run did not record it" for name in sorted(before.keys() - after.keys()))
    report.extend(f"{name}: recorded by the fresh run, not committed" for name in sorted(after.keys() - before.keys()))
    for name in sorted(before.keys() & after.keys()):
        old_cases, new_cases = before[name]["cases"], after[name]["cases"]
        report.extend(
            f"{name} [{case}]: committed, but the fresh run did not record it"
            for case in sorted(old_cases.keys() - new_cases.keys())
        )
        report.extend(
            f"{name} [{case}]: recorded by the fresh run, not committed"
            for case in sorted(new_cases.keys() - old_cases.keys())
        )
        for case in sorted(old_cases.keys() & new_cases.keys()):
            if old_cases[case] != new_cases[case]:
                diff = difflib.unified_diff(
                    _lines(old_cases[case]), _lines(new_cases[case]), "committed", "fresh", lineterm="", n=2
                )
                report.append(f"{name} [{case}] differs:\n" + "\n".join(diff))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh", type=Path, required=True)
    parser.add_argument("--committed", type=Path, required=True)
    args = parser.parse_args(argv)

    versions = sorted(path.name for path in args.fresh.iterdir() if path.is_dir()) if args.fresh.is_dir() else []
    if not versions:
        print(f"drift: no fresh recording under {args.fresh}", file=sys.stderr)
        return 2
    status = 0
    for version in versions:
        committed = args.committed / version
        if not committed.is_dir():
            print(f"drift: Virtualmin {version} has no committed recording under {args.committed}")
            status = 1
            continue
        report = compare(args.fresh / version, committed)
        if report:
            status = 1
            print(f"drift: Virtualmin {version} differs from the committed recording:")
            print("\n\n".join(report))
        else:
            print(f"drift: Virtualmin {version} matches the committed recording")
    return status


if __name__ == "__main__":
    sys.exit(main())
