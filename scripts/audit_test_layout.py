"""Audit test layout consistency and duplication hotspots.

Usage:
  python3 scripts/audit_test_layout.py
  python3 scripts/audit_test_layout.py --json
  python3 scripts/audit_test_layout.py --strict
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALLOWLIST_PATH = PROJECT_ROOT / "scripts" / "test_layout_allowlist.json"
TEST_ROOTS = [
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "services" / "platform" / "tests",
    PROJECT_ROOT / "services" / "portal" / "tests",
]

SUSPICIOUS_NAME_RE = re.compile(
    r"(todo|fix|misc|coverage|remaining|round\d*|basic|focused|additional|codex)",
    re.IGNORECASE,
)


@dataclass
class BranchInventory:
    local: list[str]
    remote: list[str]


@dataclass
class TestLocation:
    file: str
    test_name: str
    start_line: int
    end_line: int
    symbol_kind: str  # function | method


@dataclass
class DuplicateNameGroup:
    name: str
    allowed: bool
    locations: list[TestLocation]


@dataclass
class DuplicateBodyGroup:
    signature: str
    allowed: bool
    locations: list[TestLocation]


def run_git_lines(args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def collect_branch_inventory() -> BranchInventory:
    local = run_git_lines(["for-each-ref", "--format=%(refname:short)", "refs/heads"])
    remote = run_git_lines(["for-each-ref", "--format=%(refname:short)", "refs/remotes"])
    return BranchInventory(local=local, remote=remote)


def iter_test_files() -> list[Path]:
    files: list[Path] = []
    for root in TEST_ROOTS:
        if root.exists():
            files.extend(sorted(root.rglob("test_*.py")))
    return files


def read_ast(path: Path) -> tuple[ast.Module | None, str]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None, ""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None, content
    return tree, content


def normalize_source(source: str) -> str:
    normalized_lines: list[str] = []
    for raw in source.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        normalized_lines.append(re.sub(r"\s+", " ", line))
    return "\n".join(normalized_lines)


def load_allowlist(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _name_allowed(name: str, allowlist: dict[str, Any]) -> bool:
    explicit = set(allowlist.get("allowed_duplicate_names", []))
    if name in explicit:
        return True

    patterns = allowlist.get("allowed_duplicate_name_patterns", [])
    return any(re.search(pattern, name) for pattern in patterns)


def _to_relative(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def scan_test_nodes(file: Path, source: str, tree: ast.Module) -> list[tuple[str, str, TestLocation, str]]:
    """Return (unique_name, short_name, location, normalized_source)."""
    locations: list[tuple[str, str, TestLocation, str]] = []
    lines = source.splitlines()

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            start = node.lineno
            end = node.end_lineno or node.lineno
            segment = "\n".join(lines[start - 1 : end])
            normalized = normalize_source(segment)
            location = TestLocation(
                file=_to_relative(file),
                test_name=node.name,
                start_line=start,
                end_line=end,
                symbol_kind="function",
            )
            locations.append((node.name, node.name, location, normalized))
            continue

        if isinstance(node, ast.ClassDef):
            for method in node.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not method.name.startswith("test_"):
                    continue
                qualified = f"{node.name}.{method.name}"
                start = method.lineno
                end = method.end_lineno or method.lineno
                segment = "\n".join(lines[start - 1 : end])
                normalized = normalize_source(segment)
                location = TestLocation(
                    file=_to_relative(file),
                    test_name=qualified,
                    start_line=start,
                    end_line=end,
                    symbol_kind="method",
                )
                locations.append((qualified, method.name, location, normalized))

    return locations


def scan(allowlist_path: Path) -> dict[str, Any]:
    allowlist = load_allowlist(allowlist_path)

    suspicious_files: list[str] = []
    duplicate_name_index: dict[str, list[TestLocation]] = {}
    duplicate_body_index: dict[str, list[TestLocation]] = {}

    test_files = iter_test_files()
    for file in test_files:
        if SUSPICIOUS_NAME_RE.search(file.name):
            suspicious_files.append(_to_relative(file))

        tree, source = read_ast(file)
        if tree is None:
            continue

        for unique_name, _short_name, loc, normalized in scan_test_nodes(file, source, tree):
            duplicate_name_index.setdefault(unique_name, []).append(loc)

            if normalized:
                signature = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                duplicate_body_index.setdefault(signature, []).append(loc)

    duplicate_name_groups: list[DuplicateNameGroup] = []
    for name, locations in sorted(duplicate_name_index.items()):
        if len(locations) < 2:
            continue
        duplicate_name_groups.append(
            DuplicateNameGroup(
                name=name,
                allowed=_name_allowed(name, allowlist),
                locations=locations,
            )
        )

    duplicate_body_groups: list[DuplicateBodyGroup] = []
    for signature, locations in sorted(duplicate_body_index.items()):
        if len(locations) < 2:
            continue
        files = {loc.file for loc in locations}
        if len(files) < 2:
            continue
        names = {loc.test_name for loc in locations}
        allowed = bool(names) and all(_name_allowed(name, allowlist) for name in names)
        duplicate_body_groups.append(DuplicateBodyGroup(signature=signature, allowed=allowed, locations=locations))

    summary = {
        "test_files_scanned": len(test_files),
        "suspiciously_named_files": len(suspicious_files),
        "duplicate_test_names": len(duplicate_name_groups),
        "duplicate_test_names_unapproved": sum(not group.allowed for group in duplicate_name_groups),
        "duplicate_test_bodies": len(duplicate_body_groups),
        "duplicate_test_bodies_unapproved": sum(not group.allowed for group in duplicate_body_groups),
    }

    return {
        "allowlist_path": _to_relative(allowlist_path) if allowlist_path.exists() else str(allowlist_path),
        "branch_inventory": asdict(collect_branch_inventory()),
        "summary": summary,
        "suspicious_filenames": sorted(suspicious_files),
        "duplicate_test_names": [asdict(group) for group in duplicate_name_groups],
        "duplicate_test_bodies": [asdict(group) for group in duplicate_body_groups],
    }


def print_report(result: dict[str, Any]) -> None:
    branches = result["branch_inventory"]
    summary = result["summary"]

    print("# Branch inventory")
    print(f"Local branches ({len(branches['local'])}): {', '.join(branches['local']) or 'none'}")
    print(f"Remote refs ({len(branches['remote'])}): {', '.join(branches['remote']) or 'none'}")

    print("\n# Summary")
    print(f"Test files scanned: {summary['test_files_scanned']}")
    print(f"Suspicious filenames: {summary['suspiciously_named_files']}")
    print(
        "Duplicate test names: "
        f"{summary['duplicate_test_names']} "
        f"({summary['duplicate_test_names_unapproved']} unapproved)"
    )
    print(
        "Duplicate test bodies: "
        f"{summary['duplicate_test_bodies']} "
        f"({summary['duplicate_test_bodies_unapproved']} unapproved)"
    )
    print(f"Allowlist: {result['allowlist_path']}")

    print("\n# Suspicious filename candidates")
    suspicious = result["suspicious_filenames"]
    if suspicious:
        for filename in suspicious:
            print(f"- {filename}")
    else:
        print("- none")

    print("\n# Duplicate test names")
    if not result["duplicate_test_names"]:
        print("- none")
    for group in result["duplicate_test_names"]:
        status = "allowed" if group["allowed"] else "unapproved"
        print(f"- {group['name']} ({status})")
        for loc in group["locations"]:
            print(f"  - {loc['file']}:{loc['start_line']}")

    print("\n# Exact duplicate test bodies")
    if not result["duplicate_test_bodies"]:
        print("- none")
    for group in result["duplicate_test_bodies"]:
        status = "allowed" if group["allowed"] else "unapproved"
        print(f"- {group['signature']} ({status})")
        for loc in group["locations"]:
            print(f"  - {loc['file']}:{loc['start_line']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit test layout and duplication hotspots")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST_PATH,
        help="Path to duplicate-name allowlist JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when suspicious names or unapproved duplicates are present",
    )
    args = parser.parse_args()

    result = scan(args.allowlist)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    if args.strict:
        summary = result["summary"]
        if (
            summary["suspiciously_named_files"] > 0
            or summary["duplicate_test_names_unapproved"] > 0
            or summary["duplicate_test_bodies_unapproved"] > 0
        ):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
