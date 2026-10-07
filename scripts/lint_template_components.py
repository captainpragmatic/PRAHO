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
  TMPL010  Malformed tmpl-allow marker (warning)

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
from gettext import gettext
from html.parser import HTMLParser
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

# TMPL001-005: one {# tmpl-allow CODE: reason #} marker may exempt one matching finding.
# A standalone marker targets the immediately following line; an inline marker targets its own.
# Exemptions remain local and explicit, and unused markers are reported as stale.
#
# Reasons may contain punctuation, including "#", but never the Django comment terminator.
# A tempered match stops at the first "#}", so two markers cannot merge into one reason.
_TMPL_ALLOW_RE = re.compile(r"\{#\s*tmpl-allow\s+(TMPL\d{3})\s*:\s*((?:(?!#\}).)*?)\s*#\}")

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

# TMPL007: inline executable scripts and HTML event handlers in components.
# External scripts and non-executable JSON data are allowed; Alpine directives remain allowed.
_DJANGO_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_DJANGO_CONTROL_FLOW_RE = re.compile(r"\{%\s*(?:if|elif|else|endif|for|empty|endfor)\b.*?%\}", re.DOTALL)

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


class _ComponentScriptParser(HTMLParser):
    """Locate inline execution without treating external script imports as inline code."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.lines: set[int] = set()
        self.script_line: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line_no = self.getpos()[0]
        if any(value is not None and re.fullmatch(r"on[a-z]+", name) for name, value in attrs):
            self.lines.add(line_no)
        if tag != "script":
            return
        attributes = {name: value or "" for name, value in attrs}
        script_type = attributes.get("type", "").strip().lower()
        if script_type in {"application/json", "application/ld+json"}:
            self.script_line = None
            return
        self.script_line = line_no
        if not attributes.get("src", "").strip():
            self.lines.add(line_no)

    def handle_data(self, data: str) -> None:
        if self.script_line is not None and data.strip():
            self.lines.add(self.script_line)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.script_line = None


def _find_tmpl_allow_markers(lines: list[str], path: Path) -> tuple[dict[int, tuple[str, str, int]], list[Violation]]:
    """Map each marker line to its code, reason and target line.

    Exactly one complete marker with a non-empty reason is allowed per line.
    Standalone markers target the next line; inline markers target their own line.
    """
    markers: dict[int, tuple[str, str, int]] = {}
    meta_violations: list[Violation] = []
    for line_no, raw_line in enumerate(lines, start=1):
        starts = list(re.finditer(r"\{#\s*tmpl-allow\b", raw_line))
        if not starts:
            continue
        matches = list(_TMPL_ALLOW_RE.finditer(raw_line))
        match = matches[0] if len(starts) == len(matches) == 1 else None
        if match is None or not match.group(2).strip():
            meta_violations.append(
                Violation(
                    "TMPL010",
                    SEVERITY_WARNING,
                    path,
                    line_no,
                    gettext(
                        "Malformed tmpl-allow marker — use one {# tmpl-allow CODE: reason #} "
                        "above or on the same line as the element"
                    ),
                    snippet=raw_line.strip()[:120],
                )
            )
        # Retain blocker diagnostics for recognised markers with missing reasons or duplicates.
        if not matches:
            continue
        if match is None:
            meta_violations.append(
                Violation(
                    "TMPL_ALLOW_NO_REASON",
                    SEVERITY_BLOCKER,
                    path,
                    line_no,
                    gettext("Use only one tmpl-allow marker per line — split markers across separate lines"),
                    snippet=raw_line.strip()[:120],
                )
            )
            continue
        code, reason = match.group(1), match.group(2).strip()
        if not reason:
            meta_violations.append(
                Violation(
                    "TMPL_ALLOW_NO_REASON",
                    SEVERITY_BLOCKER,
                    path,
                    line_no,
                    gettext("tmpl-allow marker for %(code)s has no reason — every exemption must say why")
                    % {"code": code},
                    snippet=raw_line.strip()[:120],
                )
            )
            continue
        target_line = line_no + int(raw_line.strip() == match.group())
        markers[line_no] = (code, reason, target_line)
    return markers, meta_violations


def _exemption_for(
    markers: dict[int, tuple[str, str, int]], consumed: set[int], line_no: int, code: str
) -> tuple[bool, str]:
    """Consume at most one matching allowance targeting this line."""
    for marker_line in (line_no, line_no - 1):
        marker = markers.get(marker_line)
        if marker is not None and marker_line not in consumed and marker[0] == code and marker[2] == line_no:
            consumed.add(marker_line)
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

    tmpl_allow_markers, tmpl_allow_meta_violations = _find_tmpl_allow_markers(lines, path)
    if not is_feature:
        tmpl_allow_markers = {}
        tmpl_allow_meta_violations = [v for v in tmpl_allow_meta_violations if v.code == "TMPL010"]
    consumed_marker_lines: set[int] = set()
    component_script_lines: set[int] = set()
    if is_component:
        script_parser = _ComponentScriptParser()
        markup = _DJANGO_COMMENT_RE.sub(lambda match: "\n" * match.group().count("\n"), "\n".join(lines))
        # Control-flow tags may touch an attribute name; separate them before HTML parsing.
        # Keep every newline so findings still refer to the original template.
        markup = _DJANGO_CONTROL_FLOW_RE.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), markup)
        script_parser.feed(markup)
        script_parser.close()
        component_script_lines = script_parser.lines

    for line_no, raw_line in enumerate(lines, start=1):
        # Marker reasons are prose; retain real elements sharing their line.
        raw_line = _DJANGO_COMMENT_RE.sub("", raw_line)
        line = raw_line.strip()

        # ── Feature template checks (TMPL001-005, TMPL008) ─────────────────────
        if is_feature and line:
            # Enumerate every element and consume at most one marker per finding.
            # Both marker placements may target this line, but neither marker can be reused.
            # Additional elements remain separate, un-exempted findings.
            for _match in _RAW_INPUT_RE.finditer(raw_line):
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

            for _match in _RAW_BUTTON_RE.finditer(raw_line):
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

            for _match in _RAW_SELECT_RE.finditer(raw_line):
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

            for _match in _RAW_TEXTAREA_RE.finditer(raw_line):
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
                    exempted, reason = _exemption_for(tmpl_allow_markers, consumed_marker_lines, line_no, "TMPL005")
                    violations.append(
                        Violation(
                            "TMPL005",
                            SEVERITY_WARNING,
                            path,
                            line_no,
                            f"Raw semantic color class '{color_match.group()}' — use "
                            "{% badge variant=... %} or {% alert variant=... %} instead",
                            snippet=line[:120],
                            exempted=exempted,
                            reason=reason,
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

            if line_no in component_script_lines:
                violations.append(
                    Violation(
                        "TMPL007",
                        SEVERITY_WARNING,
                        path,
                        line_no,
                        gettext(
                            "Inline script or event handler in component — move JavaScript to static/ "
                            "(Alpine x-data on-element is allowed)"
                        ),
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

    for marker_line_no, (code, _reason, _target_line) in tmpl_allow_markers.items():
        if marker_line_no not in consumed_marker_lines:
            violations.append(
                Violation(
                    "TMPL_ALLOW_STALE",
                    SEVERITY_BLOCKER,
                    path,
                    marker_line_no,
                    gettext(
                        "tmpl-allow marker for %(code)s has no matching violation on its target line — "
                        "remove the marker or restore the element it was written for"
                    )
                    % {"code": code},
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
            ("TMPL010", SEVERITY_WARNING, gettext("Malformed tmpl-allow marker")),
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
    elif exempted_count:
        print(f"\n✅ Only exempted violations found ({exempted_count}) — exit 0.")
    else:
        print("\n✅ No violations found — exit 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
