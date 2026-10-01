"""
Lint portal templates for design-system violations.

Checks:
  TMPL001  Raw <input> element in feature template (should use {% input_field %})
  TMPL002  Raw <button> element in feature template (should use {% button %})
  TMPL003  Raw <select> element in feature template (should use {% input_field type="select" %})
  TMPL004  Raw <textarea> element in feature template (should use {% input_field type="textarea" %})
  TMPL005  Raw semantic color class (bg-green-100, bg-red-100, etc.) — use {% badge %} instead
  TMPL006  Inline <style> block in a component template (only [x-cloak] 1-liners allowed)
  TMPL007  Inline <script> block in a component template (JS must live in static/)
  TMPL008  Emoji character in template (should use {% icon %} or remove)
  TMPL009  Raw <svg> in component template not allowlisted as complex visual

Exit codes:
    0 — no violations
    1 — violations found

Usage:
    python scripts/lint_template_components.py
    python scripts/lint_template_components.py --fail-on TMPL001,TMPL002
    python scripts/lint_template_components.py templates/billing/invoice_detail.html
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# ===============================================================================
# CONFIGURATION
# ===============================================================================

# ⚠️ Assumes script is exactly one level deep from repo root (scripts/)
REPO_ROOT = Path(__file__).resolve().parents[1]
PORTAL_TEMPLATES = REPO_ROOT / "services" / "portal" / "templates"
COMPONENT_DIR = PORTAL_TEMPLATES / "components"
COMPONENT_SVG_ALLOWLIST_FILE = REPO_ROOT / ".component-svg-allowlist"

# Severity levels
SEVERITY_BLOCKER = "blocker"
SEVERITY_WARNING = "warning"

# ===============================================================================
# VIOLATION MODEL
# ===============================================================================


@dataclass
class Violation:
    """A single template lint violation."""

    code: str
    severity: str
    file: Path
    line: int
    message: str
    snippet: str = ""
    exempted: bool = False
    reason: str = ""

    def __str__(self) -> str:
        rel = self.file.relative_to(REPO_ROOT)
        if self.exempted:
            indicator = "🔸"
        elif self.severity == SEVERITY_BLOCKER:
            indicator = "❌"
        else:
            indicator = "⚠️ "
        suffix = f" — EXEMPTED: {self.reason}" if self.exempted else ""
        return f"  {indicator} {rel}:{self.line} [{self.code}] {self.message}{suffix}"


# ===============================================================================
# DETECTION PATTERNS
# ===============================================================================

# TMPL001-004: Raw form elements in feature templates (not in components/)
# TMPL001: exclude both quoted (type='hidden') and unquoted (type=hidden) variants — valid HTML5
_RAW_INPUT_RE = re.compile(r"<input\b(?![^>]*type=(?:['\"]hidden['\"]|hidden\b))", re.IGNORECASE)
_RAW_BUTTON_RE = re.compile(r"<button\b", re.IGNORECASE)
_RAW_SELECT_RE = re.compile(r"<select\b", re.IGNORECASE)
_RAW_TEXTAREA_RE = re.compile(r"<textarea\b", re.IGNORECASE)

# TMPL001-004 exemption marker: a single-line {# tmpl-allow CODE: reason #} directly above the
# violating element. Per-line (not file-level like TMPL009's allowlist) because a single file can
# have both legitimate blockers to fix and legitimate exceptions on different lines - a file-level
# allowlist would exempt every future raw element in the file, not just the one it was written for.
_TMPL_ALLOW_RE = re.compile(r"\{#\s*tmpl-allow\s+(TMPL\d{3})\s*:\s*(.*?)\s*#\}")

# TMPL005: Raw semantic color classes used as status indicators
_SEMANTIC_COLOR_RE = re.compile(r"\b(bg|text)-(green|red|yellow|blue|orange|purple|pink)-\d{2,3}\b")
# Exclude these legitimate utility contexts (layout, not status)
_COLOR_CONTEXT_EXCLUDE = re.compile(
    r"(focus:|hover:|dark:|group-hover:|md:|lg:|xl:|from-|to-|via-|ring-|border-|placeholder-)",
    re.IGNORECASE,
)

# TMPL006: Inline <style> block — allow only single-line [x-cloak] rules
_STYLE_BLOCK_RE = re.compile(r"<style\b", re.IGNORECASE)
_XCLOAK_ONLY_RE = re.compile(r"<style[^>]*>\s*\[x-cloak\][^<]{0,60}</style>", re.IGNORECASE | re.DOTALL)

# TMPL007: Inline <script> block in component — Alpine x-data is allowed (on-element only)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b", re.IGNORECASE)

# TMPL008: Unicode emoji characters (ranges cover most common emoji blocks)
# Dingbats block (U+2700-U+27BF) is intentionally excluded because it contains
# commonly-used symbols like ✓ ✗ ★ ✉ that are NOT decorative emoji.
# ⚡ PERFORMANCE: pre-compiled pattern — O(1) reuse
_EMOJI_RE = re.compile(
    "["
    "\U0001f300-\U0001f9ff"  # Misc symbols, emoticons, transport, supplemental
    "\U00002600-\U000026ff"  # Misc symbols (weather, astro — exclude U+2700-U+27BF Dingbats)
    "\U0001fa00-\U0001faff"  # Chess pieces, shapes, etc.
    "\U0001f004-\U0001f0cf"  # Mahjong/playing card
    "\U0001f100-\U0001f1ff"  # Enclosed alphanumeric supplement
    "]+",
    re.UNICODE,
)

# TMPL009: Raw SVG in component templates must be allowlisted as complex visuals
_RAW_SVG_RE = re.compile(r"<svg\b", re.IGNORECASE)

# ===============================================================================
# FILE ROUTING
# ===============================================================================


def is_component_template(path: Path) -> bool:
    """True if the template lives under components/."""
    try:
        path.relative_to(COMPONENT_DIR)
        return True
    except ValueError:
        return False


def is_feature_template(path: Path) -> bool:
    """True if a template outside components/ (i.e., a feature template)."""
    try:
        path.relative_to(PORTAL_TEMPLATES)
        return not is_component_template(path)
    except ValueError:
        return False


@lru_cache(maxsize=1)
def load_component_svg_allowlist() -> set[str]:
    """
    Load allowlisted component template paths that can keep raw SVG.

    File format:
      services/portal/templates/components/button.html | loading spinner
    """
    if not COMPONENT_SVG_ALLOWLIST_FILE.exists():
        return set()

    allowed: set[str] = set()
    lines = COMPONENT_SVG_ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path_part = line.split("|", 1)[0].strip()
        if not path_part:
            continue
        allowed.add(path_part.replace("\\", "/"))
    return allowed


# ===============================================================================
# FILE SCANNER
# ===============================================================================


def _find_tmpl_allow_markers(lines: list[str], path: Path) -> tuple[dict[int, tuple[str, str]], list[Violation]]:
    """Scan every line for a `{# tmpl-allow CODE: reason #}` marker.

    Returns (markers, meta_violations): `markers` maps the marker's own 1-indexed line number to
    (code, reason), for lookup by the line directly below it. A marker with an empty reason is
    never added to `markers` (it exempts nothing) and instead produces a TMPL_ALLOW_NO_REASON
    blocker in `meta_violations` - require a reason rather than silently accepting a blank one.
    """
    markers: dict[int, tuple[str, str]] = {}
    meta_violations: list[Violation] = []
    for line_no, raw_line in enumerate(lines, start=1):
        match = _TMPL_ALLOW_RE.search(raw_line)
        if not match:
            continue
        code, reason = match.group(1), match.group(2).strip()
        if not reason:
            meta_violations.append(
                Violation(
                    "TMPL_ALLOW_NO_REASON",
                    SEVERITY_BLOCKER,
                    path,
                    line_no,
                    f"tmpl-allow marker for {code} has no reason — every exemption must say why",
                    snippet=raw_line.strip()[:120],
                )
            )
            continue
        markers[line_no] = (code, reason)
    return markers, meta_violations


def _exemption_for(
    markers: dict[int, tuple[str, str]], consumed: set[int], line_no: int, code: str
) -> tuple[bool, str]:
    """Check whether the line directly above `line_no` carries a marker for `code`."""
    marker = markers.get(line_no - 1)
    if marker is not None and marker[0] == code:
        consumed.add(line_no - 1)
        return True, marker[1]
    return False, ""


def scan_file(path: Path) -> list[Violation]:
    """Scan a single template file and return all violations found."""
    violations: list[Violation] = []
    path = path.resolve()
    is_component = is_component_template(path)
    is_feature = is_feature_template(path)
    relative_path = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    component_svg_allowlist = load_component_svg_allowlist()
    svg_allowed_in_component = relative_path in component_svg_allowlist

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return violations

    tmpl_allow_markers, tmpl_allow_meta_violations = _find_tmpl_allow_markers(lines, path) if is_feature else ({}, [])
    consumed_marker_lines: set[int] = set()

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        # ── Feature template checks (TMPL001-005, TMPL008) ─────────────────────
        if is_feature:
            if _RAW_INPUT_RE.search(raw_line):
                exempted, reason = _exemption_for(tmpl_allow_markers, consumed_marker_lines, line_no, "TMPL001")
                violations.append(
                    Violation(
                        "TMPL001",
                        SEVERITY_BLOCKER,
                        path,
                        line_no,
                        "Raw <input> element — use {% input_field %} component tag",
                        snippet=line[:120],
                        exempted=exempted,
                        reason=reason,
                    )
                )

            if _RAW_BUTTON_RE.search(raw_line):
                exempted, reason = _exemption_for(tmpl_allow_markers, consumed_marker_lines, line_no, "TMPL002")
                violations.append(
                    Violation(
                        "TMPL002",
                        SEVERITY_BLOCKER,
                        path,
                        line_no,
                        "Raw <button> element — use {% button %} component tag",
                        snippet=line[:120],
                        exempted=exempted,
                        reason=reason,
                    )
                )

            if _RAW_SELECT_RE.search(raw_line):
                exempted, reason = _exemption_for(tmpl_allow_markers, consumed_marker_lines, line_no, "TMPL003")
                violations.append(
                    Violation(
                        "TMPL003",
                        SEVERITY_BLOCKER,
                        path,
                        line_no,
                        'Raw <select> element — use {% input_field type="select" %} tag',
                        snippet=line[:120],
                        exempted=exempted,
                        reason=reason,
                    )
                )

            if _RAW_TEXTAREA_RE.search(raw_line):
                exempted, reason = _exemption_for(tmpl_allow_markers, consumed_marker_lines, line_no, "TMPL004")
                violations.append(
                    Violation(
                        "TMPL004",
                        SEVERITY_BLOCKER,
                        path,
                        line_no,
                        'Raw <textarea> element — use {% input_field type="textarea" %} tag',
                        snippet=line[:120],
                        exempted=exempted,
                        reason=reason,
                    )
                )

            # Check for hardcoded semantic color classes (status indicators)
            # Per-match check: only exclude if the context immediately BEFORE
            # this specific match contains a utility prefix (focus:, hover:, etc.).
            for color_match in _SEMANTIC_COLOR_RE.finditer(raw_line):
                match_start = color_match.start()
                pre_context = raw_line[max(0, match_start - 30) : match_start]
                if not _COLOR_CONTEXT_EXCLUDE.search(pre_context):
                    violations.append(
                        Violation(
                            "TMPL005",
                            SEVERITY_WARNING,
                            path,
                            line_no,
                            f"Raw semantic color class '{color_match.group()}' — use "
                            "{% badge variant=... %} or {% alert variant=... %} instead",
                            snippet=line[:120],
                        )
                    )

            # Check for emoji characters
            emoji_match = _EMOJI_RE.search(raw_line)
            if emoji_match:
                violations.append(
                    Violation(
                        "TMPL008",
                        SEVERITY_BLOCKER,
                        path,
                        line_no,
                        f"Emoji character '{emoji_match.group()}' in template — "
                        "use {% icon %} or remove (see design system §4.1)",
                        snippet=line[:120],
                    )
                )

        # ── Component template checks (TMPL006-007) ─────────────────────────────
        if is_component:
            if _STYLE_BLOCK_RE.search(raw_line):
                # Allow only single-line [x-cloak] style rules
                context_window = "\n".join(lines[max(0, line_no - 1) : line_no + 5])
                if not _XCLOAK_ONLY_RE.search(context_window):
                    violations.append(
                        Violation(
                            "TMPL006",
                            SEVERITY_WARNING,
                            path,
                            line_no,
                            "Inline <style> block in component — move to assets/css/input.css "
                            "(only [x-cloak] single-liners allowed)",
                            snippet=line[:120],
                        )
                    )

            if _SCRIPT_BLOCK_RE.search(raw_line):
                # Exception: <script type="application/json"> is non-executable data,
                # used for JSON-LD, HTMX config, etc. — safe inside components.
                if not re.search(
                    r'<script\b[^>]*type=["\']application/(?:json|ld\+json)["\']',
                    raw_line,
                    re.IGNORECASE,
                ):
                    violations.append(
                        Violation(
                            "TMPL007",
                            SEVERITY_WARNING,
                            path,
                            line_no,
                            "Inline <script> block in component — move to services/portal/static/js/ "
                            "(Alpine x-data on-element is allowed)",
                            snippet=line[:120],
                        )
                    )

            if _RAW_SVG_RE.search(raw_line) and not svg_allowed_in_component:
                violations.append(
                    Violation(
                        "TMPL009",
                        SEVERITY_WARNING,
                        path,
                        line_no,
                        "Raw <svg> in component — icon-like SVG must use {% icon %}; "
                        "only allowlisted complex visuals permitted",
                        snippet=line[:120],
                    )
                )

    for marker_line_no, (code, _reason) in tmpl_allow_markers.items():
        if marker_line_no not in consumed_marker_lines:
            violations.append(
                Violation(
                    "TMPL_ALLOW_STALE",
                    SEVERITY_BLOCKER,
                    path,
                    marker_line_no,
                    f"tmpl-allow marker for {code} has no matching violation on the next line — "
                    "remove the marker or restore the element it was written for",
                    snippet=lines[marker_line_no - 1].strip()[:120],
                )
            )
    violations.extend(tmpl_allow_meta_violations)

    return violations


# ===============================================================================
# MAIN
# ===============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint portal templates for design-system violations.")
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="Template files to scan. Defaults to all portal templates.",
    )
    parser.add_argument(
        "--fail-on",
        metavar="CODES",
        default="TMPL001,TMPL002,TMPL003,TMPL004,TMPL008,TMPL_ALLOW_STALE,TMPL_ALLOW_NO_REASON",
        help="Comma-separated violation codes that cause non-zero exit (default: blockers only).",
    )
    parser.add_argument("--list-violations", action="store_true", help="Print all violation codes and exit.")
    args = parser.parse_args()

    if args.list_violations:
        codes = [
            ("TMPL001", SEVERITY_BLOCKER, "Raw <input> in feature template"),
            ("TMPL002", SEVERITY_BLOCKER, "Raw <button> in feature template"),
            ("TMPL003", SEVERITY_BLOCKER, "Raw <select> in feature template"),
            ("TMPL004", SEVERITY_BLOCKER, "Raw <textarea> in feature template"),
            ("TMPL005", SEVERITY_WARNING, "Raw semantic color class in feature template"),
            ("TMPL006", SEVERITY_WARNING, "Inline <style> block in component template"),
            ("TMPL007", SEVERITY_WARNING, "Inline <script> block in component template"),
            ("TMPL008", SEVERITY_BLOCKER, "Emoji character in template"),
            ("TMPL009", SEVERITY_WARNING, "Raw <svg> in component template not allowlisted"),
            ("TMPL_ALLOW_STALE", SEVERITY_BLOCKER, "tmpl-allow marker with no matching violation below it"),
            ("TMPL_ALLOW_NO_REASON", SEVERITY_BLOCKER, "tmpl-allow marker with an empty reason"),
        ]
        for code, sev, desc in codes:
            print(f"  {code}  [{sev:7}]  {desc}")
        return 0

    fail_codes: set[str] = {c.strip().upper() for c in args.fail_on.split(",")}
    # Discard empty string produced by --fail-on "" to prevent always-pass sentinel bug.
    fail_codes.discard("")

    # ── Collect target files ─────────────────────────────────────────────────
    if args.files:
        # ⚡ PERFORMANCE: O(N) where N = number of explicitly provided files
        target_files = [f for f in args.files if f.suffix == ".html" and f.exists()]
    else:
        # ⚡ PERFORMANCE: O(T) where T = total template count (~200 in portal)
        target_files = sorted(PORTAL_TEMPLATES.rglob("*.html"))

    # ── Scan ─────────────────────────────────────────────────────────────────
    all_violations: list[Violation] = []
    for path in target_files:
        all_violations.extend(scan_file(path))

    if not all_violations:
        print("✅ [lint-templates] No design-system violations found.")
        return 0

    # ── Report ────────────────────────────────────────────────────────────────
    # ⚡ PERFORMANCE: O(V) where V = violation count
    by_code: dict[str, list[Violation]] = {}
    for v in all_violations:
        by_code.setdefault(v.code, []).append(v)

    print(f"🔍 [lint-templates] Found {len(all_violations)} violation(s):")
    print("━" * 60)

    for code in sorted(by_code):
        for v in by_code[code]:
            print(str(v))

    print("━" * 60)
    # A violation's SEVERITY is a fixed property of its rule (the table at the top of this file) -
    # it does not depend on what a caller happened to pass to --fail-on. `--fail-on` controls the
    # EXIT CODE only (which codes are allowed to fail this specific run); conflating the two meant
    # `lint-templates-strict` passing all nine codes reported 643 "blockers" - every TMPL005
    # warning reclassified by the act of asking for it to also fail the build.
    #
    # An exempted violation (a documented tmpl-allow exception) is reported above like any other -
    # explicit, not silent - but never counts toward blocker/warning/fail totals: that is the whole
    # point of the marker. `has_fail`/`fail_count` check `not v.exempted` per violation rather than
    # per code, because one code (e.g. TMPL002) can have both exempted and non-exempted instances
    # in the same run.
    blocker_count = sum(1 for v in all_violations if v.severity == SEVERITY_BLOCKER and not v.exempted)
    warn_count = sum(1 for v in all_violations if v.severity == SEVERITY_WARNING and not v.exempted)
    exempted_count = sum(1 for v in all_violations if v.exempted)
    has_fail = any(v.code in fail_codes and not v.exempted for v in all_violations)
    fail_count = sum(1 for v in all_violations if v.code in fail_codes and not v.exempted)
    exempted_suffix = f"  |  {exempted_count} exempted" if exempted_count else ""
    print(f"📊 {blocker_count} blocker(s)  |  {warn_count} warning(s){exempted_suffix}")

    if has_fail:
        print(f"\n❌ Non-zero exit: {fail_count} violation(s) matching --fail-on codes found.")
        print("   Fix the violations above or update design-system docs if intentional.")
        return 1

    if warn_count or blocker_count:
        print(f"\n⚠️  {blocker_count + warn_count} violation(s) found, none matching --fail-on codes — exit 0.")
    else:
        print("\n✅ No violations found — exit 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
