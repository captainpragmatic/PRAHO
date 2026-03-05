"""
Audit portal templates for dark mode completeness.

Checks all templates use Tailwind's dark-aware tokens (slate-700, slate-800, etc.)
rather than hardcoded light-only colors, and that components support both modes.

Checks:
  DM001  Hardcoded light-only background (bg-white, bg-gray-50/100) without dark: variant
  DM002  Hardcoded light-only text color (text-black, text-gray-900) without dark: variant
  DM003  Hardcoded light-only border (border-gray-200/300) without dark: variant
  DM004  Inline style with color/background (bypasses dark mode system)
  DM005  Non-token color class (uses numbered gray- instead of slate- palette)

Exit codes:
    0 — no violations
    1 — violations found

Usage:
    python scripts/audit_dark_mode.py
    python scripts/audit_dark_mode.py --verbose
    python scripts/audit_dark_mode.py services/portal/templates/billing/
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ===============================================================================
# CONFIGURATION
# ===============================================================================

# ⚠️ Assumes script is exactly one level deep from repo root (scripts/)
REPO_ROOT = Path(__file__).resolve().parents[1]

PORTAL_TEMPLATES = REPO_ROOT / "services" / "portal" / "templates"
PLATFORM_TEMPLATES = REPO_ROOT / "services" / "platform" / "templates"

# Severity levels
SEVERITY_BLOCKER = "blocker"  # Definitely broken in dark mode
SEVERITY_WARNING = "warning"  # Likely broken or inconsistent

# ===============================================================================
# VIOLATION MODEL
# ===============================================================================


@dataclass
class DarkModeViolation:
    """Single dark mode violation."""

    code: str
    severity: str
    file: Path
    line: int
    message: str
    match_text: str  # The offending class/style

    def __str__(self) -> str:
        rel = self.file.relative_to(REPO_ROOT) if self.file.is_relative_to(REPO_ROOT) else self.file
        return f"{rel}:{self.line}: [{self.code}] ({self.severity}) {self.message} → `{self.match_text}`"


# ===============================================================================
# CHECK PATTERNS
# ===============================================================================

# Light-only background classes that need dark: variants
# Note: Tailwind class names are case-sensitive, so re.IGNORECASE is intentionally omitted.
LIGHT_BG_CLASSES = re.compile(r"""\b(bg-(?:white|gray-(?:50|100|200)))\b""")

# Light-only text colors
LIGHT_TEXT_CLASSES = re.compile(r"""\b(text-(?:black|gray-(?:800|900)))\b""")

# Light-only border colors
LIGHT_BORDER_CLASSES = re.compile(r"""\b(border-(?:gray-(?:100|200|300)))\b""")

# Inline styles with color or background
INLINE_COLOR_STYLE = re.compile(
    r"""style\s*=\s*["'][^"']*(?:color|background(?:-color)?)\s*:""",
    re.IGNORECASE,
)

# Non-token gray classes (should use slate- not gray-)
# Note: same case-sensitive justification as above.
NON_TOKEN_GRAY = re.compile(r"""\b((?:bg|text|border|ring|divide)-gray-\d+)\b""")

# Django template comment
DJANGO_COMMENT = re.compile(r"\{#.*#\}")

# Skip these template dirs (error pages, emails, etc.)
SKIP_PATTERNS = {
    "email",
    "admin",
}


def _should_skip(path: Path) -> bool:
    """Check if file should be skipped (emails, admin, etc.)."""
    return any(part in SKIP_PATTERNS for part in path.parts)


def _strip_comments(line: str) -> str:
    """Remove Django template comments and single-line HTML comments.

    ⚠️ KNOWN LIMITATION: Multi-line HTML comments (<!-- spanning multiple lines -->)
    are not stripped because this function works line-by-line. Content inside
    a multi-line comment may still produce false positives.
    """
    line = DJANGO_COMMENT.sub("", line)
    return re.sub(r"<!--.*?-->", "", line)


def _has_dark_variant_nearby(lines: list[str], line_idx: int, cls: str) -> bool:
    """Check if there's a dark: variant for this class nearby (within ±1 line, 3-line window).

    This handles multi-line class attributes where the dark: variant may
    be on an adjacent line.
    """
    # ⚡ PERFORMANCE: O(1) - checks constant number of lines
    prefix = cls.split("-", maxsplit=1)[0]  # bg, text, border
    dark_pattern = f"dark:{prefix}-"

    start = max(0, line_idx - 1)
    end = min(len(lines), line_idx + 2)
    window = " ".join(lines[start:end])
    return dark_pattern in window


def check_file(path: Path, *, verbose: bool = False) -> list[DarkModeViolation]:
    """Run all dark mode checks on a single template file.

    Returns:
        List of violations found.
    """
    violations: list[DarkModeViolation] = []

    if _should_skip(path):
        return violations

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return violations

    lines = content.splitlines()

    for i, raw_line in enumerate(lines, 1):
        line = _strip_comments(raw_line)
        if not line.strip():
            continue

        # Track classes flagged by DM001-DM003 so DM005 doesn't double-count them.
        already_flagged_classes: set[str] = set()

        # ── DM001: Light-only backgrounds ───────────────────────────────
        for match in LIGHT_BG_CLASSES.finditer(line):
            cls = match.group(1)
            if not _has_dark_variant_nearby(lines, i - 1, cls):
                violations.append(
                    DarkModeViolation(
                        code="DM001",
                        severity=SEVERITY_BLOCKER,
                        file=path,
                        line=i,
                        message="Light-only background without dark: variant",
                        match_text=cls,
                    )
                )
                already_flagged_classes.add(cls)

        # ── DM002: Light-only text colors ───────────────────────────────
        for match in LIGHT_TEXT_CLASSES.finditer(line):
            cls = match.group(1)
            if not _has_dark_variant_nearby(lines, i - 1, cls):
                violations.append(
                    DarkModeViolation(
                        code="DM002",
                        severity=SEVERITY_BLOCKER,
                        file=path,
                        line=i,
                        message="Light-only text color without dark: variant",
                        match_text=cls,
                    )
                )
                already_flagged_classes.add(cls)

        # ── DM003: Light-only borders ───────────────────────────────────
        for match in LIGHT_BORDER_CLASSES.finditer(line):
            cls = match.group(1)
            if not _has_dark_variant_nearby(lines, i - 1, cls):
                violations.append(
                    DarkModeViolation(
                        code="DM003",
                        severity=SEVERITY_WARNING,
                        file=path,
                        line=i,
                        message="Light-only border without dark: variant",
                        match_text=cls,
                    )
                )
                already_flagged_classes.add(cls)

        # ── DM004: Inline color styles ──────────────────────────────────
        violations.extend(
            DarkModeViolation(
                code="DM004",
                severity=SEVERITY_BLOCKER,
                file=path,
                line=i,
                message="Inline style with color/background bypasses dark mode",
                match_text=match.group(0)[:60],
            )
            for match in INLINE_COLOR_STYLE.finditer(line)
        )

        # ── DM005: Non-token gray palette ───────────────────────────────
        for match in NON_TOKEN_GRAY.finditer(line):
            cls = match.group(1)
            # Skip if already flagged by DM001-DM003 (avoids double-counting)
            # or if a dark: counterpart is present nearby (class is already migrated).
            if cls in already_flagged_classes:
                continue
            if _has_dark_variant_nearby(lines, i - 1, cls):
                continue
            violations.append(
                DarkModeViolation(
                    code="DM005",
                    severity=SEVERITY_WARNING,
                    file=path,
                    line=i,
                    message="Non-token 'gray-' class — use 'slate-' palette instead",
                    match_text=cls,
                )
            )

    return violations


# ===============================================================================
# FILE DISCOVERY
# ===============================================================================


def discover_templates(paths: list[str] | None = None) -> list[Path]:
    """Find all HTML templates to audit.

    Args:
        paths: Optional specific paths. If None, audits both services.

    Returns:
        Sorted list of template file paths.
    """
    if paths:
        result: list[Path] = []
        for p_str in paths:
            p = Path(p_str)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if p.is_file() and p.suffix == ".html":
                result.append(p)
            elif p.is_dir():
                result.extend(sorted(p.rglob("*.html")))
        return sorted(set(result))

    templates: list[Path] = []
    for tmpl_dir in [PORTAL_TEMPLATES, PLATFORM_TEMPLATES]:
        if tmpl_dir.exists():
            templates.extend(tmpl_dir.rglob("*.html"))
    return sorted(set(templates))


# ===============================================================================
# REPORTING
# ===============================================================================


def print_report(violations: list[DarkModeViolation], *, verbose: bool = False) -> None:
    """Print a summary of dark mode violations."""
    if not violations:
        print("✅ [DarkMode] All templates use dark-aware classes")
        return

    by_severity: dict[str, list[DarkModeViolation]] = {}
    for v in violations:
        by_severity.setdefault(v.severity, []).append(v)

    by_code: dict[str, int] = {}
    for v in violations:
        by_code[v.code] = by_code.get(v.code, 0) + 1

    blocker_count = len(by_severity.get(SEVERITY_BLOCKER, []))
    warning_count = len(by_severity.get(SEVERITY_WARNING, []))

    print("\n🌙 [DarkMode] Dark Mode Completeness Audit")
    print(f"{'─' * 60}")
    print(f"  🔥 Blockers: {blocker_count}")
    print(f"  ⚠️  Warnings: {warning_count}")
    print(f"  Total:       {len(violations)}")
    print()

    print("📊 Violations by rule:")
    for code in sorted(by_code.keys()):
        print(f"  {code}: {by_code[code]}")
    print()

    if verbose:
        for severity in [SEVERITY_BLOCKER, SEVERITY_WARNING]:
            items = by_severity.get(severity, [])
            if items:
                label = {"blocker": "🔥 BLOCKERS", "warning": "⚠️  WARNINGS"}[severity]
                print(f"\n{label} ({len(items)}):")
                print(f"{'─' * 60}")
                for v in items:
                    print(f"  {v}")

    # Per-file summary
    by_file: dict[Path, int] = {}
    for v in violations:
        by_file[v.file] = by_file.get(v.file, 0) + 1

    print(f"\n📁 Files with violations ({len(by_file)}):")
    # ⚡ PERFORMANCE: O(N log N) sort, N = unique files
    for f in sorted(by_file.keys(), key=lambda p: by_file[p], reverse=True):
        rel = f.relative_to(REPO_ROOT) if f.is_relative_to(REPO_ROOT) else f
        print(f"  {by_file[f]:3d}  {rel}")


# ===============================================================================
# MAIN
# ===============================================================================


def main() -> int:
    """Run the dark mode audit.

    Returns:
        Exit code: 0 if no blockers, 1 otherwise.
    """
    parser = argparse.ArgumentParser(description="Audit templates for dark mode completeness")
    parser.add_argument("paths", nargs="*", help="Specific files or directories to audit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all violations with details")
    parser.add_argument(
        "--fail-on",
        default="blocker",
        help="Comma-separated severities that cause non-zero exit (default: blocker)",
    )
    args = parser.parse_args()

    templates = discover_templates(args.paths or None)
    if not templates:
        print("⚠️  [DarkMode] No templates found to audit")
        return 0

    all_violations: list[DarkModeViolation] = []
    for template in templates:
        all_violations.extend(check_file(template, verbose=args.verbose))

    print_report(all_violations, verbose=args.verbose)

    fail_severities = {s.strip() for s in args.fail_on.split(",")}
    failing = [v for v in all_violations if v.severity in fail_severities]

    if failing:
        print(f"\n🚨 {len(failing)} violation(s) at fail-on severity — exiting 1")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
