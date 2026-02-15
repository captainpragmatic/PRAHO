#!/usr/bin/env python3
"""
🔍 Type Checking Script for Phase 2 Gradual Typing

This script checks type safety for recently modified files based on git changes.
Used for pre-commit hooks and CI/CD to ensure type safety in modified code.

Usage:
    python scripts/check_types_modified.py [--staged] [--since=HEAD~5] [--verbose]
"""

import argparse
import subprocess
import sys
from pathlib import Path


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
            # Get staged files
            cmd = ["git", "diff", "--cached", "--name-only"]
        elif since:
            # Get files modified since commit
            cmd = ["git", "diff", "--name-only", since]
        else:
            # Get files modified since last commit
            cmd = ["git", "diff", "--name-only", "HEAD"]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)  # noqa: S603
        files = result.stdout.strip().split("\n")

        # Filter for Python files
        python_files = [f for f in files if f.endswith(".py") and Path(f).exists()]
        return python_files

    except subprocess.CalledProcessError as e:
        print(f"❌ Error getting git changes: {e}")
        return []


def should_check_file(file_path: str) -> bool:
    """Determine if a file should be type-checked based on path."""
    normalized = normalize_repo_path(file_path)
    path = Path(normalized)

    # Skip non-app files
    if not str(path).startswith("apps/"):
        return False

    # Skip migrations
    if "migrations" in str(path):
        return False

    # Skip test files (handled separately)
    if "test" in str(path).lower():
        return False

    # Focus on high-impact modules
    high_impact_patterns = [
        "apps/common/",
        "apps/users/",
        "apps/billing/",
        "apps/customers/",
        "apps/audit/",
    ]

    return any(pattern in str(path) for pattern in high_impact_patterns)


def run_mypy_on_files(files: list[str], verbose: bool = False) -> bool:
    """Run mypy on the given files."""
    if not files:
        if verbose:
            print("i  No Python files to check")
        return True

    # Filter files based on impact
    files_to_check = [f for f in files if should_check_file(f)]

    if not files_to_check:
        if verbose:
            print("i  No high-impact files to check")
        return True

    if verbose:
        print(f"🔍 Checking {len(files_to_check)} files:")
        for f in files_to_check:
            print(f"  • {f}")

    # Run mypy
    cmd = ["mypy", *files_to_check]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # noqa: S603

    if result.returncode == 0:
        print("✅ Type checking passed")
        if verbose and result.stdout.strip():
            print(result.stdout)
        return True
    else:
        print("❌ Type checking failed")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Type check modified Python files")
    parser.add_argument("files", nargs="*", help="Optional explicit file list (e.g., pre-commit)")
    parser.add_argument("--staged", action="store_true", help="Check only staged files")
    parser.add_argument("--since", help="Check files modified since this commit")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("🎯 PRAHO Platform - Type Safety Check")

    # Use explicit file list when provided (e.g., direct hook invocation), otherwise detect from git.
    files = args.files or get_modified_python_files(staged_only=args.staged, since=args.since)

    if not files:
        print("i  No Python files modified")
        return 0

    # Run type checking
    success = run_mypy_on_files(files, verbose=args.verbose)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
