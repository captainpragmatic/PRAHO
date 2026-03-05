"""
Audit portal templates for WCAG AA accessibility violations.

Static checks (no browser required):
  A11Y001  <img> without alt attribute
  A11Y002  <a> without discernible text (empty link or icon-only without aria-label)
  A11Y003  <input>/<select>/<textarea> without associated <label> or aria-label
  A11Y004  Missing lang attribute on <html>
  A11Y005  <button> without discernible text (icon-only without aria-label)
  A11Y006  Click handler on non-interactive element without role/tabindex
  A11Y007  Autofocus used on non-first input (UX anti-pattern)
  A11Y008  <table> without <caption> or aria-label
  A11Y009  Positive tabindex (should use 0 or -1)
  A11Y010  aria-hidden="true" on focusable element

Exit codes:
    0 — no violations
    1 — violations found

Usage:
    python scripts/audit_accessibility.py
    python scripts/audit_accessibility.py --verbose
    python scripts/audit_accessibility.py services/portal/templates/billing/
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
SEVERITY_CRITICAL = "critical"  # Must fix for WCAG AA
SEVERITY_SERIOUS = "serious"  # Should fix for WCAG AA
SEVERITY_MINOR = "minor"  # Nice-to-have

# ===============================================================================
# VIOLATION MODEL
# ===============================================================================


@dataclass
class A11yViolation:
    """Single accessibility violation."""

    code: str
    severity: str
    file: Path
    line: int
    message: str

    def __str__(self) -> str:
        rel = self.file.relative_to(REPO_ROOT) if self.file.is_relative_to(REPO_ROOT) else self.file
        return f"{rel}:{self.line}: [{self.code}] ({self.severity}) {self.message}"


# ===============================================================================
# CHECK RULES
# ===============================================================================

# Patterns to detect raw HTML elements (not inside Django template comments)
IMG_NO_ALT = re.compile(r"<img\b(?![^>]*\balt\s*=)[^>]*>", re.IGNORECASE)
EMPTY_LINK = re.compile(r"<a\b[^>]*>\s*</a>", re.IGNORECASE)
ICON_ONLY_LINK = re.compile(
    r"<a\b(?![^>]*\baria-label)[^>]*>\s*(?:<(?:i|svg|span)\b[^>]*(?:class=\"[^\"]*icon[^\"]*\")[^>]*/?>)\s*</a>",
    re.IGNORECASE,
)
ICON_ONLY_BUTTON = re.compile(
    r"<button\b(?![^>]*\baria-label)[^>]*>\s*(?:<(?:i|svg|span)\b[^>]*(?:class=\"[^\"]*icon[^\"]*\")[^>]*/?>)\s*</button>",
    re.IGNORECASE,
)
INPUT_NO_LABEL = re.compile(
    r"<(?:input|select|textarea)\b(?![^>]*(?:\baria-label|\baria-labelledby|\bid\s*=))[^>]*>",
    re.IGNORECASE,
)
POSITIVE_TABINDEX = re.compile(r"tabindex\s*=\s*[\"']([1-9]\d*)[\"']", re.IGNORECASE)
ONCLICK_NON_INTERACTIVE = re.compile(
    r"<(?:div|span|p|li|td)\b[^>]*(?:onclick|@click|x-on:click)[^>]*>",
    re.IGNORECASE,
)
ARIA_HIDDEN_FOCUSABLE = re.compile(
    r"<(?:a|button|input|select|textarea)\b[^>]*aria-hidden\s*=\s*[\"']true[\"'][^>]*>",
    re.IGNORECASE,
)
TABLE_NO_CAPTION = re.compile(
    r"<table\b(?![^>]*\baria-label)[^>]*>",
    re.IGNORECASE,
)

# A11Y004: <html> without lang attribute
HTML_MISSING_LANG = re.compile(r"<html\b(?![^>]*\blang\s*=)[^>]*>", re.IGNORECASE)

# A11Y007: autofocus on a form input (first is acceptable, subsequent are UX anti-patterns)
AUTOFOCUS_INPUT = re.compile(
    r"<(?:input|select|textarea)\b[^>]*\bautofocus\b[^>]*>",
    re.IGNORECASE,
)

# Template-aware patterns - skip lines that are Django comments
DJANGO_COMMENT = re.compile(r"\{#.*#\}")

# Lines to ignore: component templates handle their own a11y
COMPONENT_DIRS = {"components"}


def _is_component_template(path: Path) -> bool:
    """Check if a file is inside a components/ directory."""
    return any(part in COMPONENT_DIRS for part in path.parts)


def _strip_django_comments(line: str) -> str:
    """Remove Django template comments from a line."""
    return DJANGO_COMMENT.sub("", line)


def _strip_django_tags(line: str) -> str:
    """Remove Django template tags and variables for cleaner HTML analysis."""
    line = re.sub(r"\{%.*?%\}", "", line)
    return re.sub(r"\{\{.*?\}\}", "TEXT", line)


def check_file(path: Path, *, verbose: bool = False) -> list[A11yViolation]:
    """Run all accessibility checks on a single template file.

    Returns:
        List of violations found in the file.

    ⚠️  KNOWN LIMITATION: All checks are single-line regex only.
    Multi-line HTML tags (e.g. <img\n  alt="..."> spread across lines) may
    produce false negatives. Proper multi-line parsing would require an
    HTML parser rather than regex.
    """
    violations: list[A11yViolation] = []
    is_component = _is_component_template(path)

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return violations

    lines = content.splitlines()

    # ── A11Y004: <html> missing lang attribute ──────────────────────────
    # Only check the first 10 lines where <html> normally appears
    for i, raw_line in enumerate(lines[:10], 1):
        line = _strip_django_comments(raw_line)
        if HTML_MISSING_LANG.search(line):
            violations.append(
                A11yViolation(
                    code="A11Y004",
                    severity=SEVERITY_CRITICAL,
                    file=path,
                    line=i,
                    message="<html> element missing lang attribute",
                )
            )

    # ── A11Y001: <img> without alt ──────────────────────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        if IMG_NO_ALT.search(line):
            violations.append(
                A11yViolation(
                    code="A11Y001",
                    severity=SEVERITY_CRITICAL,
                    file=path,
                    line=i,
                    message="<img> missing alt attribute",
                )
            )

    # ── A11Y002: Empty links / icon-only links without aria-label ───────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        cleaned = _strip_django_tags(line)
        if EMPTY_LINK.search(cleaned):
            violations.append(
                A11yViolation(
                    code="A11Y002",
                    severity=SEVERITY_SERIOUS,
                    file=path,
                    line=i,
                    message="<a> with no discernible text content",
                )
            )
        elif ICON_ONLY_LINK.search(cleaned):
            violations.append(
                A11yViolation(
                    code="A11Y002",
                    severity=SEVERITY_SERIOUS,
                    file=path,
                    line=i,
                    message="Icon-only <a> missing aria-label",
                )
            )

    # ── A11Y003: Form inputs without labels ─────────────────────────────
    # Skip component templates (they define the components that add labels)
    if not is_component:
        for i, raw_line in enumerate(lines, 1):
            line = _strip_django_comments(raw_line)
            # Skip lines that use Django template component tags
            if re.search(r"\{%\s*(?:input_field|checkbox_field|select_field)", raw_line):
                continue
            if INPUT_NO_LABEL.search(line):
                violations.append(
                    A11yViolation(
                        code="A11Y003",
                        severity=SEVERITY_CRITICAL,
                        file=path,
                        line=i,
                        message="Form input missing label or aria-label",
                    )
                )

    # ── A11Y005: Icon-only buttons without aria-label ───────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        cleaned = _strip_django_tags(line)
        if ICON_ONLY_BUTTON.search(cleaned):
            violations.append(
                A11yViolation(
                    code="A11Y005",
                    severity=SEVERITY_SERIOUS,
                    file=path,
                    line=i,
                    message="Icon-only <button> missing aria-label",
                )
            )

    # ── A11Y006: Click handlers on non-interactive elements ─────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        if ONCLICK_NON_INTERACTIVE.search(line):
            # Check if it has role and tabindex
            if not re.search(r"\brole\s*=", line) or not re.search(r"\btabindex\s*=", line):
                violations.append(
                    A11yViolation(
                        code="A11Y006",
                        severity=SEVERITY_SERIOUS,
                        file=path,
                        line=i,
                        message="Click handler on non-interactive element without role/tabindex",
                    )
                )

    # ── A11Y007: Autofocus on non-first input ──────────────────────────
    # Autofocus on the very first input of a form is acceptable (good UX);
    # subsequent autofocus attributes compete and create confusion.
    if not is_component:
        autofocus_count = 0
        for i, raw_line in enumerate(lines, 1):
            line = _strip_django_comments(raw_line)
            if AUTOFOCUS_INPUT.search(line):
                autofocus_count += 1
                if autofocus_count > 1:
                    violations.append(
                        A11yViolation(
                            code="A11Y007",
                            severity=SEVERITY_SERIOUS,
                            file=path,
                            line=i,
                            message="autofocus on non-first input — only one autofocus per page is acceptable",
                        )
                    )

    # ── A11Y008: Tables without caption/aria-label ──────────────────────
    if not is_component:
        for i, raw_line in enumerate(lines, 1):
            line = _strip_django_comments(raw_line)
            if TABLE_NO_CAPTION.search(line):
                # Check if next few lines have a <caption> (widened to 5 lines
                # to handle blank lines between <table> and <caption>)
                following = "\n".join(lines[i : i + 5])
                if "<caption" not in following.lower():
                    violations.append(
                        A11yViolation(
                            code="A11Y008",
                            severity=SEVERITY_MINOR,
                            file=path,
                            line=i,
                            message="<table> missing <caption> or aria-label",
                        )
                    )

    # ── A11Y009: Positive tabindex ──────────────────────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        match = POSITIVE_TABINDEX.search(line)
        if match:
            violations.append(
                A11yViolation(
                    code="A11Y009",
                    severity=SEVERITY_SERIOUS,
                    file=path,
                    line=i,
                    message=f"Positive tabindex={match.group(1)} disrupts tab order (use 0 or -1)",
                )
            )

    # ── A11Y010: aria-hidden on focusable element ───────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        if ARIA_HIDDEN_FOCUSABLE.search(line):
            violations.append(
                A11yViolation(
                    code="A11Y010",
                    severity=SEVERITY_CRITICAL,
                    file=path,
                    line=i,
                    message="aria-hidden='true' on focusable element hides it from assistive tech",
                )
            )

    return violations


# ===============================================================================
# FILE DISCOVERY
# ===============================================================================


def discover_templates(paths: list[str] | None = None) -> list[Path]:
    """Find all HTML templates to audit.

    Args:
        paths: Optional specific paths to audit. If None, audits both services.

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


def print_report(violations: list[A11yViolation], *, verbose: bool = False) -> None:
    """Print a summary report of all violations found."""
    if not violations:
        print("✅ [A11Y] No accessibility violations found")
        return

    # Group by severity
    by_severity: dict[str, list[A11yViolation]] = {}
    for v in violations:
        by_severity.setdefault(v.severity, []).append(v)

    # Group by code
    by_code: dict[str, int] = {}
    for v in violations:
        by_code[v.code] = by_code.get(v.code, 0) + 1

    critical_count = len(by_severity.get(SEVERITY_CRITICAL, []))
    serious_count = len(by_severity.get(SEVERITY_SERIOUS, []))
    minor_count = len(by_severity.get(SEVERITY_MINOR, []))

    print("\n🔍 [A11Y] Accessibility Audit Results")
    print(f"{'─' * 60}")
    print(f"  🔥 Critical: {critical_count}")
    print(f"  ⚠️  Serious:  {serious_count}")
    print(f"  📝 Minor:    {minor_count}")
    print(f"  Total:       {len(violations)}")
    print()

    # Summary by rule
    print("📊 Violations by rule:")
    for code in sorted(by_code.keys()):
        print(f"  {code}: {by_code[code]}")
    print()

    if verbose:
        for severity in [SEVERITY_CRITICAL, SEVERITY_SERIOUS, SEVERITY_MINOR]:
            items = by_severity.get(severity, [])
            if items:
                label = {"critical": "🔥 CRITICAL", "serious": "⚠️  SERIOUS", "minor": "📝 MINOR"}[severity]
                print(f"\n{label} ({len(items)}):")
                print(f"{'─' * 60}")
                for v in items:
                    print(f"  {v}")


# ===============================================================================
# MAIN
# ===============================================================================


def main() -> int:
    """Run the accessibility audit.

    Returns:
        Exit code: 0 if no critical/serious violations, 1 otherwise.
    """
    parser = argparse.ArgumentParser(description="Audit templates for WCAG AA accessibility")
    parser.add_argument("paths", nargs="*", help="Specific files or directories to audit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all violations with details")
    parser.add_argument(
        "--fail-on",
        default="critical,serious",
        help="Comma-separated severities that cause non-zero exit (default: critical,serious)",
    )
    args = parser.parse_args()

    templates = discover_templates(args.paths or None)
    if not templates:
        print("⚠️  [A11Y] No templates found to audit")
        return 0

    all_violations: list[A11yViolation] = []
    for template in templates:
        all_violations.extend(check_file(template, verbose=args.verbose))

    print_report(all_violations, verbose=args.verbose)

    # Determine exit code based on --fail-on
    fail_severities = {s.strip() for s in args.fail_on.split(",")}
    failing = [v for v in all_violations if v.severity in fail_severities]

    if failing:
        print(f"\n🚨 {len(failing)} violation(s) at fail-on severity — exiting 1")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
