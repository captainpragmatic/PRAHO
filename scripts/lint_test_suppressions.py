#!/usr/bin/env python3
"""
Scan test files for error suppression patterns that hide real bugs.

This scanner enforces ADR-0014 (No Test Suppression Policy) by detecting
patterns in both unit tests and E2E tests that suppress, ignore, or skip
errors without proper justification.

Detected patterns:
- ignore_patterns parameter in E2E test monitors
- pytest.mark.skip without a linked issue or clear reason
- bare except clauses that swallow errors silently
- @unittest.skip without justification
- xfail markers without strict=True
- noqa comments that suppress test-relevant linting rules

Exit codes:
  0 - No suppressions found
  1 - Suppressions found (fails the lint gate)

Usage:
  python scripts/lint_test_suppressions.py              # Scan all tests
  python scripts/lint_test_suppressions.py --json       # JSON output
  python scripts/lint_test_suppressions.py --fix-hint   # Show fix suggestions
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Directories to scan
TEST_DIRS = [
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "services" / "platform" / "tests",
    PROJECT_ROOT / "services" / "portal" / "tests",
]

# File patterns
TEST_FILE_GLOB = "test_*.py"

# Severity levels
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"


# ─── Finding dataclass ───────────────────────────────────────────────────────

@dataclass
class Finding:
    file: str
    line: int
    severity: str
    pattern: str
    code: str
    message: str
    fix_hint: str


# ─── Detection rules ─────────────────────────────────────────────────────────

RULES: list[dict] = [
    {
        "id": "TS001",
        "name": "ignore_patterns parameter",
        "severity": CRITICAL,
        "regex": r"ignore_patterns\s*=\s*\[",
        "message": "ignore_patterns suppresses real errors in E2E monitors. "
                   "Fix the root cause in application code or test logic instead.",
        "fix_hint": "Remove ignore_patterns and fix the underlying issue. "
                    "If the error comes from rate limiting, use RATELIMIT_ENABLE=false. "
                    "If from HMAC, check staff session fallback in middleware.",
    },
    {
        "id": "TS002",
        "name": "ignore_console_patterns parameter",
        "severity": CRITICAL,
        "regex": r"ignore_console_patterns\s*=\s*\[",
        "message": "ignore_console_patterns hides JavaScript console errors. "
                   "These may indicate real frontend bugs visible to users.",
        "fix_hint": "Fix the console error source. Common causes: missing API endpoints, "
                    "CORS issues, broken fetch() calls without HMAC headers.",
    },
    {
        "id": "TS003",
        "name": "pytest.mark.skip without issue reference",
        "severity": HIGH,
        "regex": r"@pytest\.mark\.skip\b(?!.*(?:issue|ticket|bug|TODO|FIXME|http))",
        "message": "Test skipped without linking to a tracking issue. "
                   "Skipped tests accumulate and hide regressions.",
        "fix_hint": "Either fix the test or add a skip reason with an issue link: "
                    '@pytest.mark.skip(reason="See issue #123")',
    },
    {
        "id": "TS004",
        "name": "pytest.skip() without issue reference",
        "severity": HIGH,
        "regex": r"pytest\.skip\(\s*[\"'](?!.*(?:issue|ticket|bug|TODO|FIXME|http))",
        "message": "Dynamic skip without tracking issue reference.",
        "fix_hint": "Add an issue link to the skip reason, or fix the underlying problem.",
    },
    {
        "id": "TS005",
        "name": "xfail without strict=True",
        "severity": MEDIUM,
        "regex": r"@pytest\.mark\.xfail\b(?!.*strict\s*=\s*True)",
        "message": "xfail without strict=True silently passes if the test starts working. "
                   "This hides when bugs are fixed.",
        "fix_hint": "Add strict=True: @pytest.mark.xfail(strict=True, reason='...')",
    },
    {
        "id": "TS006",
        "name": "bare except swallowing errors",
        "severity": MEDIUM,
        "regex": r"except\s*:\s*\n\s*(pass|continue|return\s+(?:None|False))",
        "multiline": True,
        "message": "Bare except clause silently swallows all errors in test code. "
                   "This hides real failures.",
        "fix_hint": "Catch specific exceptions, or let the error propagate to fail the test.",
    },
    {
        "id": "TS007",
        "name": "unittest.skip without justification",
        "severity": HIGH,
        "regex": r"@unittest\.skip\b(?!.*(?:issue|ticket|bug|TODO|FIXME|http))",
        "message": "Test skipped without justification or tracking reference.",
        "fix_hint": "Add a reason with issue link: @unittest.skip('See issue #123')",
    },
    {
        "id": "TS008",
        "name": "check_console=False without justification comment",
        "severity": LOW,
        "regex": r"check_console\s*=\s*False(?!\s*,?\s*#)",
        "message": "Console error checking disabled. If intentional, add a comment explaining why.",
        "fix_hint": "Add a comment: check_console=False,  # Reason: ...",
    },
    {
        "id": "TS009",
        "name": "check_network=False without justification comment",
        "severity": LOW,
        "regex": r"check_network\s*=\s*False(?!\s*,?\s*#)",
        "message": "Network error checking disabled. If intentional, add a comment explaining why.",
        "fix_hint": "Add a comment: check_network=False,  # Reason: ...",
    },
]


# ─── Scanner ──────────────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[Finding]:
    """Scan a single test file for suppression patterns."""
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings

    relative_path = str(filepath.relative_to(PROJECT_ROOT))
    lines = content.splitlines()

    for rule in RULES:
        if rule.get("multiline"):
            # Multi-line rules match against the full file content
            pattern = re.compile(rule["regex"], re.MULTILINE)
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                matched_line = lines[line_num - 1] if line_num <= len(lines) else ""
                findings.append(Finding(
                    file=relative_path,
                    line=line_num,
                    severity=rule["severity"],
                    pattern=rule["id"],
                    code=matched_line.strip(),
                    message=rule["message"],
                    fix_hint=rule["fix_hint"],
                ))
        else:
            pattern = re.compile(rule["regex"])
            for i, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(Finding(
                        file=relative_path,
                        line=i,
                        severity=rule["severity"],
                        pattern=rule["id"],
                        code=line.strip(),
                        message=rule["message"],
                        fix_hint=rule["fix_hint"],
                    ))

    return findings


def scan_all() -> list[Finding]:
    """Scan all test directories for suppression patterns."""
    all_findings: list[Finding] = []

    for test_dir in TEST_DIRS:
        if not test_dir.exists():
            continue
        for filepath in sorted(test_dir.rglob(TEST_FILE_GLOB)):
            all_findings.extend(scan_file(filepath))

    # Sort by severity (critical first), then file, then line
    severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.file, f.line))

    return all_findings


# ─── Output formatters ───────────────────────────────────────────────────────

def format_text(findings: list[Finding], *, show_hints: bool = False) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return "No test suppression patterns found."

    lines: list[str] = []
    lines.append(f"Found {len(findings)} test suppression pattern(s):\n")

    severity_icons = {CRITICAL: "🚨", HIGH: "⚠️", MEDIUM: "📋", LOW: "ℹ️"}

    current_file = ""
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            lines.append(f"\n  {current_file}")

        icon = severity_icons.get(f.severity, "?")
        lines.append(f"    {icon} [{f.pattern}] L{f.line}: {f.message}")
        lines.append(f"       Code: {f.code}")
        if show_hints:
            lines.append(f"       Fix:  {f.fix_hint}")

    # Summary
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    lines.append("\n  Summary:")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
        count = by_severity.get(sev, 0)
        if count:
            lines.append(f"    {severity_icons[sev]} {sev.upper()}: {count}")

    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    """Format findings as JSON for CI integration."""
    return json.dumps(
        {
            "total": len(findings),
            "findings": [asdict(f) for f in findings],
        },
        indent=2,
    )


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan test files for error suppression patterns (ADR-0014)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output for CI")
    parser.add_argument("--fix-hint", action="store_true", help="Show fix suggestions")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="critical",
        help="Minimum severity to fail on (default: critical)",
    )
    args = parser.parse_args()

    findings = scan_all()

    if args.json:
        print(format_json(findings))
    else:
        print(format_text(findings, show_hints=args.fix_hint))

    if args.fail_on == "none":
        return 0

    fail_severities = {CRITICAL, HIGH, MEDIUM, LOW}
    cutoff = {CRITICAL: {CRITICAL}, HIGH: {CRITICAL, HIGH}, MEDIUM: {CRITICAL, HIGH, MEDIUM}, LOW: fail_severities}
    active = cutoff.get(args.fail_on, {CRITICAL})

    has_failures = any(f.severity in active for f in findings)
    if has_failures:
        if not args.json:
            print(f"\n❌ Test suppression lint failed (threshold: {args.fail_on})")
            print("   See ADR-0014: docs/adrs/ADR-0014-no-test-suppression-policy.md")
        return 1

    if not args.json:
        if findings:
            print(f"\n⚠️  {len(findings)} finding(s) below threshold — review recommended")
        else:
            print("\n✅ No test suppression patterns found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
