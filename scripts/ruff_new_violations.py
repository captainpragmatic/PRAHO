"""
Fail only on newly introduced Ruff violations.

This script compares Ruff diagnostics for the current tree against a baseline
git ref (default: HEAD). Existing debt is tolerated; new violations fail.

Typical usage:
  .venv/bin/python scripts/ruff_new_violations.py --staged
  .venv/bin/python scripts/ruff_new_violations.py --baseline-ref <base_sha>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
DEFAULT_RUFF = REPO_ROOT / ".venv" / "bin" / "ruff"


@dataclass(frozen=True)
class ViolationFingerprint:
    rel_path: str
    code: str
    message: str
    line_text: str


@dataclass(frozen=True)
class Violation:
    rel_path: str
    row: int
    col: int
    code: str
    message: str
    line_text: str


def run_git(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def resolve_ruff_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    if DEFAULT_RUFF.exists():
        return str(DEFAULT_RUFF)
    return "ruff"


def normalize_path(path_value: str) -> str:
    raw_path = Path(path_value)
    if raw_path.is_absolute():
        try:
            return raw_path.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return raw_path.as_posix()
    return raw_path.as_posix().lstrip("./")


def collect_python_candidates(
    *,
    explicit_paths: list[str],
    staged: bool,
    since: str | None,
    baseline_ref: str,
    path_prefixes: list[str],
) -> list[str]:
    if explicit_paths:
        raw_files = [normalize_path(p) for p in explicit_paths]
    elif staged:
        raw_files = run_git(["diff", "--cached", "--name-only"]).stdout.splitlines()
    elif since:
        raw_files = run_git(["diff", "--name-only", since]).stdout.splitlines()
    else:
        # Triple-dot gives the range from merge-base(baseline_ref, HEAD) -> HEAD.
        raw_files = run_git(["diff", "--name-only", f"{baseline_ref}...HEAD"]).stdout.splitlines()

    prefixes = [p.rstrip("/").lstrip("./") for p in path_prefixes if p.strip()]

    result: list[str] = []
    seen: set[str] = set()
    for raw in raw_files:
        normalized = normalize_path(raw)
        if not normalized.endswith(".py"):
            continue
        if prefixes and not any(normalized.startswith(prefix + "/") or normalized == prefix for prefix in prefixes):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    return sorted(result)


def read_line_from_file(path: Path, line_number: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return ""
    if line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()


def run_ruff_json(
    *,
    files: list[Path],
    root_for_rel: Path,
    ruff_bin: str,
) -> list[Violation]:
    if not files:
        return []

    cmd = [
        ruff_bin,
        "check",
        "--output-format",
        "json",
        "--config",
        str(PYPROJECT_PATH),
        *[str(path) for path in files],
    ]
    proc = subprocess.run(
        cmd,
        cwd=root_for_rel,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"ruff execution failed with code {proc.returncode}")

    payload = proc.stdout.strip()
    if not payload:
        return []

    try:
        diagnostics = json.loads(payload)
    except json.JSONDecodeError as exc:
        print(payload)
        raise RuntimeError("Could not parse Ruff JSON output") from exc

    issues: list[Violation] = []
    for item in diagnostics:
        filename = Path(item["filename"])
        try:
            rel_path = filename.resolve().relative_to(root_for_rel.resolve()).as_posix()
        except ValueError:
            rel_path = filename.as_posix()

        location = item.get("location", {})
        row = int(location.get("row", 0))
        col = int(location.get("column", 0))
        code = str(item.get("code", "UNKNOWN"))
        message = str(item.get("message", "")).strip()
        line_text = read_line_from_file(root_for_rel / rel_path, row)

        issues.append(
            Violation(
                rel_path=rel_path,
                row=row,
                col=col,
                code=code,
                message=message,
                line_text=line_text,
            )
        )

    return issues


def build_baseline_tree(*, files: list[str], baseline_ref: str, baseline_root: Path) -> list[Path]:
    baseline_files: list[Path] = []
    for rel in files:
        show = run_git(["show", f"{baseline_ref}:{rel}"], check=False)
        if show.returncode != 0:
            # File may be newly added or absent at baseline ref.
            continue
        dst = baseline_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(show.stdout, encoding="utf-8")
        baseline_files.append(dst)
    return baseline_files


def to_fingerprint(issue: Violation) -> ViolationFingerprint:
    return ViolationFingerprint(
        rel_path=issue.rel_path,
        code=issue.code,
        message=issue.message,
        line_text=issue.line_text,
    )


def print_new_violations(new_violations: list[Violation], max_report: int) -> None:
    print(f"❌ Found {len(new_violations)} new Ruff violation(s):")
    for issue in new_violations[:max_report]:
        print(f"{issue.rel_path}:{issue.row}:{issue.col}: {issue.code} {issue.message}")
        if issue.line_text:
            print(f"  > {issue.line_text}")
    if len(new_violations) > max_report:
        remaining = len(new_violations) - max_report
        print(f"... and {remaining} more new violation(s).")


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail only on newly introduced Ruff violations")
    parser.add_argument("paths", nargs="*", help="Optional explicit file paths (e.g. from pre-commit)")
    parser.add_argument("--staged", action="store_true", help="Use staged files from git index")
    parser.add_argument("--since", default=None, help="Use files changed since this git ref/range")
    parser.add_argument("--baseline-ref", default="HEAD", help="Baseline git ref used for existing-debt comparison")
    parser.add_argument(
        "--path-prefix",
        action="append",
        default=[],
        help="Optional path prefix filter (repeatable), e.g. --path-prefix services/platform",
    )
    parser.add_argument("--ruff-bin", default=None, help="Optional Ruff binary path")
    parser.add_argument("--max-report", type=int, default=200, help="Maximum new violations to print")
    args = parser.parse_args()

    ruff_bin = resolve_ruff_binary(args.ruff_bin)
    candidates = collect_python_candidates(
        explicit_paths=args.paths,
        staged=args.staged,
        since=args.since,
        baseline_ref=args.baseline_ref,
        path_prefixes=args.path_prefix,
    )
    if not candidates:
        print("✅ No Python files to check for new Ruff violations.")
        return 0

    current_files = [REPO_ROOT / rel for rel in candidates if (REPO_ROOT / rel).exists()]
    current_violations = run_ruff_json(files=current_files, root_for_rel=REPO_ROOT, ruff_bin=ruff_bin)

    with tempfile.TemporaryDirectory(prefix="ruff-baseline-") as temp_dir:
        baseline_root = Path(temp_dir)
        baseline_files = build_baseline_tree(
            files=candidates, baseline_ref=args.baseline_ref, baseline_root=baseline_root
        )
        baseline_violations = run_ruff_json(files=baseline_files, root_for_rel=baseline_root, ruff_bin=ruff_bin)

        baseline_fingerprints = {to_fingerprint(issue) for issue in baseline_violations}
    new_violations = [issue for issue in current_violations if to_fingerprint(issue) not in baseline_fingerprints]

    if not new_violations:
        print("✅ No new Ruff violations introduced.")
        return 0

    print_new_violations(new_violations, max_report=args.max_report)
    return 1


if __name__ == "__main__":
    sys.exit(main())
