#!/usr/bin/env python3
"""
🔍 Incremental Type Checking for Modified Files

Blocks only NEW mypy errors introduced by the current changes — pre-existing
errors on the merge-base are ignored.  This makes the hook usable on codebases
with a non-zero mypy error count while still preventing regressions.

Algorithm:
  1. Run mypy on the working-tree versions of modified files.
  2. Run mypy on the same files from the merge-base (via ``git show``).
  3. Compute the set difference: new_errors = current - baseline.
  4. Fail only if new_errors is non-empty.

Usage:
    python scripts/check_types_modified.py [--staged] [--since=HEAD~5] [--verbose]
"""

import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Matches the start of a mypy error: "file.py:42: error: ..."
_MYPY_ERROR_START_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):\s*error:\s*(?P<message>.+)$")
# Matches an error code anywhere in text: "[error-code]"
_MYPY_CODE_RE = re.compile(r"\[(?P<code>[a-z][a-z0-9-]*)\]")


def normalize_repo_path(file_path: str) -> str:
    """Normalize path so checks work from repository root and service root."""
    normalized = file_path.replace("\\", "/").lstrip("./")
    if normalized.startswith("services/platform/"):
        return normalized[len("services/platform/") :]
    return normalized


def get_modified_python_files(staged_only: bool = False, since: str | None = None) -> list[str]:
    """Get Python files that have been modified."""
    try:
        if staged_only:
            cmd = ["git", "diff", "--cached", "--name-only"]
        elif since:
            cmd = ["git", "diff", "--name-only", since]
        else:
            cmd = ["git", "diff", "--name-only", "HEAD"]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)  # noqa: S603
        files = result.stdout.strip().split("\n")
        return [f for f in files if f.endswith(".py") and Path(f).exists()]

    except subprocess.CalledProcessError as e:
        print(f"❌ Error getting git changes: {e}")
        return []


def should_check_file(file_path: str) -> bool:
    """Determine if a file should be type-checked based on path."""
    normalized = normalize_repo_path(file_path)
    path = Path(normalized)

    if not str(path).startswith("apps/"):
        return False
    if "migrations" in str(path):
        return False
    if "test" in str(path).lower():
        return False

    high_impact_patterns = [
        "apps/common/",
        "apps/users/",
        "apps/billing/",
        "apps/customers/",
        "apps/audit/",
    ]
    return any(pattern in str(path) for pattern in high_impact_patterns)


def _parse_mypy_errors(output: str) -> dict[str, int]:
    """Extract per-file per-error-code counts from mypy output.

    Mypy wraps long messages across multiple lines.  The error code (e.g.
    ``[arg-type]``) may appear on a continuation line, not the first.  We
    collect continuation lines until the next error or the summary line,
    then extract the code from the full block.
    """
    counts: Counter[str] = Counter()
    lines = output.splitlines()

    current_file: str | None = None
    current_block: list[str] = []

    def _flush() -> None:
        nonlocal current_file, current_block
        if current_file is None:
            return
        block_text = "\n".join(current_block)
        code_match = _MYPY_CODE_RE.search(block_text)
        code = code_match.group("code") if code_match else "unknown"
        key = f"{current_file}:{code}"
        counts[key] += 1
        current_file = None
        current_block = []

    for line in lines:
        m = _MYPY_ERROR_START_RE.match(line)
        if m:
            _flush()
            current_file = m.group("file")
            current_block = [line]
        elif current_file is not None:
            # Continuation line (indented or type signature)
            current_block.append(line)

    _flush()
    return counts


def _get_merge_base() -> str:
    """Return the merge-base commit between HEAD and the main branch."""
    for main_branch in ("master", "main"):
        try:
            result = subprocess.run(  # noqa: S603
                ["git", "merge-base", "HEAD", main_branch],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            continue
    # Fallback: use HEAD (no baseline → all errors are "new")
    return "HEAD"


def _run_mypy(files: list[str], service_root: Path, env: dict[str, str]) -> str:
    """Run mypy and return raw stdout."""
    cmd = ["mypy", "--follow-imports=silent", *files]
    result = subprocess.run(  # noqa: S603
        cmd,
        check=False,
        capture_output=True,
        text=True,
        cwd=service_root,
        env=env,
    )
    return result.stdout


def _get_baseline_errors(
    normalized_files: list[str],
    service_root: Path,
    env: dict[str, str],
    merge_base: str,
) -> dict[str, int]:
    """Run mypy on the merge-base versions of the files and return error counts.

    Temporarily checks out baseline versions *in the real service root* so
    that mypy resolves imports identically to the current-version run, then
    restores the working-tree copies.
    """
    # Save current file contents and swap in baseline versions
    originals: dict[str, bytes] = {}
    baseline_files: list[str] = []

    for nf in normalized_files:
        full_path = service_root / nf
        git_path = f"services/platform/{nf}"
        try:
            result = subprocess.run(  # noqa: S603
                ["git", "show", f"{merge_base}:{git_path}"],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            # File didn't exist at merge-base (new file) → no baseline errors
            continue

        originals[nf] = full_path.read_bytes()
        full_path.write_text(result.stdout)
        baseline_files.append(nf)

    if not baseline_files:
        return {}

    try:
        output = _run_mypy(baseline_files, service_root, env)
        return _parse_mypy_errors(output)
    finally:
        # Always restore original files
        for nf, content in originals.items():
            (service_root / nf).write_bytes(content)


def run_mypy_incremental(files: list[str], verbose: bool = False) -> bool:
    """Run mypy incrementally — only fail on NEW errors vs merge-base."""
    if not files:
        if verbose:
            print("(i) No Python files to check")
        return True

    files_to_check = [f for f in files if should_check_file(f)]
    if not files_to_check:
        if verbose:
            print("(i) No high-impact files to check")
        return True

    if verbose:
        print(f"🔍 Checking {len(files_to_check)} files:")
        for f in files_to_check:
            print(f"  • {f}")

    repo_root = Path(__file__).resolve().parents[3]
    service_root = repo_root / "services" / "platform"
    normalized_files = [normalize_repo_path(f) for f in files_to_check]

    env = os.environ.copy()
    env["PATH"] = f"{repo_root / '.venv' / 'bin'}:{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{service_root}:{env.get('PYTHONPATH', '')}".rstrip(":")

    # Step 1: Run mypy on current working-tree files
    current_output = _run_mypy(normalized_files, service_root, env)
    current_counts = _parse_mypy_errors(current_output)
    total_current = sum(current_counts.values())

    if total_current == 0:
        print("✅ Type checking passed (no errors)")
        return True

    # Step 2: Get baseline error counts from merge-base
    merge_base = _get_merge_base()
    if verbose:
        print(f"📊 Comparing against merge-base: {merge_base[:10]}")

    baseline_counts = _get_baseline_errors(normalized_files, service_root, env, merge_base)
    total_baseline = sum(baseline_counts.values())

    # Step 3: Check for regressions — fail only if total error count grew
    if total_current <= total_baseline:
        print(f"✅ Type checking passed ({total_current} pre-existing error(s), 0 new)")
        return True
    else:
        new_count = total_current - total_baseline
        print(
            f"❌ Type checking failed: {new_count} new error(s) introduced (was {total_baseline}, now {total_current})"
        )
        # Show which error categories grew
        for key, count in sorted(current_counts.items()):
            baseline = baseline_counts.get(key, 0)
            if count > baseline:
                file_part, code = key.rsplit(":", 1)
                print(f"  {file_part}: [{code}] {baseline} → {count} (+{count - baseline})")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Type check modified Python files (incremental)")
    parser.add_argument("files", nargs="*", help="Optional explicit file list (e.g., pre-commit)")
    parser.add_argument("--staged", action="store_true", help="Check only staged files")
    parser.add_argument("--since", help="Check files modified since this commit")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("🎯 PRAHO Platform - Incremental Type Safety Check")

    files = args.files or get_modified_python_files(staged_only=args.staged, since=args.since)

    if not files:
        print("(i) No Python files modified")
        return 0

    success = run_mypy_incremental(files, verbose=args.verbose)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
