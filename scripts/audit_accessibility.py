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
  A11Y011  Malformed a11y-allow marker (warning)

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
import ast
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from gettext import gettext
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

from django.template import defaultfilters
from django.template.base import Lexer, Token, TokenType
from django.utils.html import conditional_escape
from django.utils.safestring import SafeString

# ===============================================================================
# CONFIGURATION
# ===============================================================================

# ⚠️ Assumes script is exactly one level deep from repo root (scripts/)
REPO_ROOT = Path(__file__).resolve().parents[1]

PORTAL_TEMPLATES = REPO_ROOT / "services" / "portal" / "templates"
PLATFORM_TEMPLATES = REPO_ROOT / "services" / "platform" / "templates"
SHARED_TEMPLATES = REPO_ROOT / "shared" / "ui" / "templates"

# Severity levels
SEVERITY_CRITICAL = "critical"  # Must fix for WCAG AA
SEVERITY_SERIOUS = "serious"  # Should fix for WCAG AA
SEVERITY_MINOR = "minor"  # Nice-to-have
SEVERITY_WARNING = "warning"  # Invalid exemption syntax; does not fail the default gate

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
COMPONENT_FIELDS = {"input_field", "checkbox_field", "select_field", "textarea_field", "filter_select"}
COMPONENT_ARGUMENT = re.compile(r"""(?:[^\s'"]+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+""")
QUOTED_LITERAL = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
TRANSLATED_LITERAL = rf"(?:_|gettext)\({QUOTED_LITERAL}\)"
COMPONENT_FILTER = re.compile(rf"\|(?P<name>\w+)(?::(?P<argument>{QUOTED_LITERAL}|{TRANSLATED_LITERAL}|[\w.+-]+))?")
COMPONENT_FILTER_EXPRESSION = re.compile(
    rf"(?P<literal>{QUOTED_LITERAL}|{TRANSLATED_LITERAL})(?P<filters>(?:{COMPONENT_FILTER.pattern})*)"
)
# Case changes retain characters; escaping retains text; safe changes only HTML safety.
# striptags can erase text, so check the resulting value after the complete chain.
COMPONENT_NAME_FILTERS: dict[str, Callable[[str], str]] = {
    "capfirst": defaultfilters.capfirst,
    "title": defaultfilters.title,
    "lower": defaultfilters.lower,
    "upper": defaultfilters.upper,
    "escape": defaultfilters.escape_filter,
    "force_escape": defaultfilters.force_escape,
    "safe": defaultfilters.safe,
    "striptags": defaultfilters.striptags,
}
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

# Preserve line numbers when stripping comments or multi-line template tags.
DJANGO_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)
A11Y_ALLOW = re.compile(r"\{#\s*a11y-allow\s+(A11Y\d{3})\s*:\s*((?:(?!#\}).)*?)\s*#\}")

# Lines to ignore: component templates handle their own a11y
COMPONENT_DIRS = {"components"}


def _is_component_template(path: Path) -> bool:
    """Check if a file is inside a components/ directory."""
    return any(part in COMPONENT_DIRS for part in path.parts)


def _strip_django_comments(line: str) -> str:
    """Remove Django comments without shifting subsequent line numbers."""
    return DJANGO_COMMENT.sub(lambda match: "\n" * match.group().count("\n"), line)


def _strip_django_tags(line: str, *, preserve_variables: bool = False) -> str:
    """Keep literal translations and non-empty variables as discernible text."""

    def replace_tag(match: re.Match[str]) -> str:
        tag = match.group()
        translation = re.match(r"""\{%\s*(?:trans|translate)\s+(?:"([^"]*)"|'([^']*)')""", tag)
        text = (translation.group(1) or translation.group(2) or "") if translation else ""
        if translation:
            options = COMPONENT_ARGUMENT.findall(tag[translation.end() : -2])
            if any(option == "as" for option in options[:-1]):
                text = ""
        return text + "\n" * tag.count("\n")

    line = re.sub(r"\{%.*?%\}", replace_tag, line, flags=re.DOTALL)
    if preserve_variables:
        return line
    return re.sub(
        r"\{\{(.*?)\}\}",
        lambda match: ("TEXT" if match.group(1).strip() else "") + "\n" * match.group().count("\n"),
        line,
        flags=re.DOTALL,
    )


@dataclass
class _FormLabel:
    target: str
    text: str = ""


class _FormLabelParser(HTMLParser):
    """Associate controls with explicit or wrapping labels, including multi-line markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.labels: list[_FormLabel] = []
        self.label_stack: list[_FormLabel] = []
        self.controls: list[tuple[int, dict[str, str], _FormLabel | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "label":
            label = _FormLabel(attributes.get("for", "").strip())
            self.labels.append(label)
            self.label_stack.append(label)
        elif tag in {"input", "select", "textarea"}:
            if tag == "input" and attributes.get("type", "").strip().lower() == "hidden":
                return
            wrapping_label = self.label_stack[-1] if self.label_stack else None
            self.controls.append((self.getpos()[0], attributes, wrapping_label))

    def handle_endtag(self, tag: str) -> None:
        if tag == "label" and self.label_stack:
            self.label_stack.pop()

    def handle_data(self, data: str) -> None:
        for label in self.label_stack:
            label.text += _strip_django_tags(data)


def _component_literal_text(value: str) -> str | None:
    """Read literal text, retaining Django's safe-string semantics."""
    translation = re.fullmatch(r"(?:_|gettext)\((.*)\)", value, flags=re.DOTALL)
    if translation:
        value = translation.group(1)
    try:
        text: object = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return None
    # Django treats quoted filter-expression constants as safe strings.
    return SafeString(text) if isinstance(text, str) else None


def _template_tokens(source: str) -> Iterator[Token]:
    """Use Django's lexer and omit content discarded by comment blocks."""
    in_comment = False
    for token in Lexer(source).tokenize():
        if in_comment:
            if token.token_type == TokenType.BLOCK and token.contents == "endcomment":
                in_comment = False
            continue
        if token.token_type == TokenType.COMMENT:
            continue
        if token.token_type == TokenType.BLOCK and token.contents.split()[:1] == ["comment"]:
            in_comment = True
            continue
        # The lexer already emits verbatim content as TEXT, including named blocks.
        yield token


def _form_label_source(tokens: list[Token]) -> str:
    """Prepare HTML for label checks without reparsing template delimiters in text."""
    parts: list[str] = []
    line_no = 1
    for token in tokens:
        parts.append("\n" * (token.lineno - line_no))
        if token.token_type == TokenType.TEXT:
            text = token.contents
        elif token.token_type == TokenType.VAR:
            text = "{{" + token.contents + "}}"
        else:
            text = _strip_django_tags("{% " + token.contents + " %}", preserve_variables=True)
        parts.append(text)
        line_no = token.lineno + text.count("\n")
    return "".join(parts)


def _component_fields_with_autoescape(tokens: list[Token]) -> Iterator[tuple[Token, bool]]:
    """Pair executable component tokens with their active autoescape state."""
    states = [True]
    for token in tokens:
        if token.token_type != TokenType.BLOCK:
            continue
        bits = token.contents.split()
        if len(bits) == 2 and bits[0] == "autoescape" and bits[1] in {"on", "off"}:
            states.append(bits[1] == "on")
        elif bits == ["endautoescape"]:
            if len(states) > 1:
                states.pop()
        elif bits and bits[0] in COMPONENT_FIELDS:
            yield token, states[-1]


def _component_argument_has_text(value: str, *, is_attribute: bool = False, autoescape: bool = True) -> bool:
    """Verify literal accessible text; keep the existing acceptance of variables."""
    expression = COMPONENT_FILTER_EXPRESSION.fullmatch(value)
    if expression is None:
        return not value.startswith(('"', "'")) and value.strip() not in {"", "None", "False"}
    text = _component_literal_text(expression.group("literal"))
    if text is None:
        return False
    for filter_match in COMPONENT_FILTER.finditer(expression.group("filters")):
        name = filter_match.group("name")
        argument = filter_match.group("argument")
        if name == "default":
            # A literal nonblank fallback can fill an empty value, but not whitespace.
            fallback = _component_literal_text(argument) if argument is not None else None
            if fallback is None or not fallback.strip():
                return False
            text = text or fallback
        else:
            transform = COMPONENT_NAME_FILTERS.get(name)
            if transform is None or argument is not None:
                # Unknown/erasing filters cannot prove a literal accessible name.
                return False
            text = transform(text)
    # Match the invocation's autoescape state when a filter removes string safety.
    if autoescape:
        text = conditional_escape(text)
    # Strip markup before decoding: escaped tags are accessible literal text.
    if not is_attribute:
        text = defaultfilters.striptags(text)
    return bool(unescape(text).strip())


def _check_form_labels(content: str, path: Path) -> list[A11yViolation]:
    """Check raw controls and component invocations rather than trusting id= alone."""
    tokens = list(_template_tokens(content))
    parser = _FormLabelParser()
    parser.feed(_form_label_source(tokens))
    parser.close()
    labelled_ids = {label.target for label in parser.labels if label.target and label.text.strip()}
    violations: list[A11yViolation] = []
    for line_no, attributes, wrapping_label in parser.controls:
        has_aria = bool(attributes.get("aria-label", "").strip() or attributes.get("aria-labelledby", "").strip())
        has_explicit_label = attributes.get("id", "").strip() in labelled_ids
        has_wrapping_label = wrapping_label is not None and bool(wrapping_label.text.strip())
        if not (has_aria or has_explicit_label or has_wrapping_label):
            violations.append(
                A11yViolation(
                    "A11Y003",
                    SEVERITY_CRITICAL,
                    path,
                    line_no,
                    gettext("Form input missing label or aria-label"),
                )
            )

    for token, autoescape in _component_fields_with_autoescape(tokens):
        bits = token.contents.split(maxsplit=1)
        component = bits[0]
        arguments: dict[str, str] = {}
        for argument in COMPONENT_ARGUMENT.findall(bits[1] if len(bits) > 1 else ""):
            key, separator, value = argument.partition("=")
            if separator:
                arguments[key] = value
        if component == "input_field" and arguments.get("input_type") in {'"hidden"', "'hidden'"}:
            continue
        label_keys = {"label", "aria_label"} if component == "input_field" else {"label"}
        has_label = any(
            _component_argument_has_text(arguments[key], is_attribute=key == "aria_label", autoescape=autoescape)
            for key in label_keys
            if key in arguments
        )
        if not has_label:
            violations.append(
                A11yViolation(
                    "A11Y003",
                    SEVERITY_CRITICAL,
                    path,
                    token.lineno,
                    gettext("Form component missing non-empty label or aria_label argument"),
                )
            )
    return violations


def _apply_a11y_allow(lines: list[str], path: Path, violations: list[A11yViolation]) -> list[A11yViolation]:
    """One standalone marker exempts the first matching finding on the next line."""
    markers: dict[int, str] = {}
    warnings: list[A11yViolation] = []
    for line_no, raw_line in enumerate(lines, 1):
        if not re.search(r"\{#\s*a11y-allow\b", raw_line):
            continue
        match = A11Y_ALLOW.fullmatch(raw_line.strip())
        if match is None or not match.group(2).strip():
            warnings.append(
                A11yViolation(
                    "A11Y011",
                    SEVERITY_WARNING,
                    path,
                    line_no,
                    gettext("Malformed a11y-allow marker — use {# a11y-allow CODE: reason #} on its own line"),
                )
            )
        else:
            markers[line_no + 1] = match.group(1)

    findings: list[A11yViolation] = []
    for violation in violations:
        if markers.get(violation.line) == violation.code:
            del markers[violation.line]
        else:
            findings.append(violation)
    return findings + warnings


def check_file(path: Path, *, verbose: bool = False) -> list[A11yViolation]:
    """Run all accessibility checks on a single template file.

    Returns:
        List of violations found in the file.

    ⚠️  KNOWN LIMITATION: Checks other than form labelling remain single-line regexes.
    Multi-line HTML tags may produce false negatives in those checks.
    Form labelling uses an HTML parser and Django's template lexer.
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
        violations.extend(
            A11yViolation(
                code="A11Y004",
                severity=SEVERITY_CRITICAL,
                file=path,
                line=i,
                message=gettext("<html> element missing lang attribute"),
            )
            for _match in HTML_MISSING_LANG.finditer(line)
        )

    # ── A11Y001: <img> without alt ──────────────────────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        violations.extend(
            A11yViolation(
                code="A11Y001",
                severity=SEVERITY_CRITICAL,
                file=path,
                line=i,
                message=gettext("<img> missing alt attribute"),
            )
            for _match in IMG_NO_ALT.finditer(line)
        )

    # ── A11Y002: Empty links / icon-only links without aria-label ───────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        cleaned = _strip_django_tags(line)
        matches = [
            (match.start(), message)
            for pattern, message in (
                (EMPTY_LINK, gettext("<a> with no discernible text content")),
                (ICON_ONLY_LINK, gettext("Icon-only <a> missing aria-label")),
            )
            for match in pattern.finditer(cleaned)
        ]
        for _position, message in sorted(matches):
            violations.append(
                A11yViolation(
                    code="A11Y002",
                    severity=SEVERITY_SERIOUS,
                    file=path,
                    line=i,
                    message=message,
                )
            )

    # ── A11Y003: Form inputs and component invocations without labels ──
    # Component definitions are checked through rendered representative controls in tests.
    if not is_component:
        violations.extend(_check_form_labels(content, path))

    # ── A11Y005: Icon-only buttons without aria-label ───────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        cleaned = _strip_django_tags(line)
        violations.extend(
            A11yViolation(
                code="A11Y005",
                severity=SEVERITY_SERIOUS,
                file=path,
                line=i,
                message=gettext("Icon-only <button> missing aria-label"),
            )
            for _match in ICON_ONLY_BUTTON.finditer(cleaned)
        )

    # ── A11Y006: Click handlers on non-interactive elements ─────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        for match in ONCLICK_NON_INTERACTIVE.finditer(line):
            # Role and tabindex must belong to this element.
            element = match.group()
            if not re.search(r"\brole\s*=", element) or not re.search(r"\btabindex\s*=", element):
                violations.append(
                    A11yViolation(
                        code="A11Y006",
                        severity=SEVERITY_SERIOUS,
                        file=path,
                        line=i,
                        message=gettext("Click handler on non-interactive element without role/tabindex"),
                    )
                )

    # ── A11Y007: Autofocus on non-first input ──────────────────────────
    # Autofocus on the very first input of a form is acceptable (good UX);
    # subsequent autofocus attributes compete and create confusion.
    if not is_component:
        autofocus_count = 0
        for i, raw_line in enumerate(lines, 1):
            line = _strip_django_comments(raw_line)
            for _match in AUTOFOCUS_INPUT.finditer(line):
                autofocus_count += 1
                if autofocus_count > 1:
                    violations.append(
                        A11yViolation(
                            code="A11Y007",
                            severity=SEVERITY_SERIOUS,
                            file=path,
                            line=i,
                            message=gettext("autofocus on non-first input — only one autofocus per page is acceptable"),
                        )
                    )

    # ── A11Y008: Tables without caption/aria-label ──────────────────────
    if not is_component:
        for i, raw_line in enumerate(lines, 1):
            line = _strip_django_comments(raw_line)
            for match in TABLE_NO_CAPTION.finditer(line):
                # Keep the five-line lookahead, bounded by this table's body.
                following = (
                    line[match.end() :] + "\n" + "\n".join(_strip_django_comments(raw) for raw in lines[i : i + 5])
                )
                body = re.split(r"</?table\b", following, maxsplit=1, flags=re.IGNORECASE)[0]
                if "<caption" not in body.lower():
                    violations.append(
                        A11yViolation(
                            code="A11Y008",
                            severity=SEVERITY_MINOR,
                            file=path,
                            line=i,
                            message=gettext("<table> missing <caption> or aria-label"),
                        )
                    )

    # ── A11Y009: Positive tabindex ──────────────────────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        violations.extend(
            A11yViolation(
                code="A11Y009",
                severity=SEVERITY_SERIOUS,
                file=path,
                line=i,
                message=gettext("Positive tabindex={value} disrupts tab order (use 0 or -1)").format(
                    value=match.group(1)
                ),
            )
            for match in POSITIVE_TABINDEX.finditer(line)
        )

    # ── A11Y010: aria-hidden on focusable element ───────────────────────
    for i, raw_line in enumerate(lines, 1):
        line = _strip_django_comments(raw_line)
        violations.extend(
            A11yViolation(
                code="A11Y010",
                severity=SEVERITY_CRITICAL,
                file=path,
                line=i,
                message=gettext("aria-hidden='true' on focusable element hides it from assistive tech"),
            )
            for _match in ARIA_HIDDEN_FOCUSABLE.finditer(line)
        )

    return _apply_a11y_allow(lines, path, violations)


# ===============================================================================
# FILE DISCOVERY
# ===============================================================================


def discover_templates(paths: list[str] | None = None) -> list[Path]:
    """Find all HTML templates to audit.

    Args:
        paths: Optional specific paths to audit. If None, audits both services and shared UI.

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
    for tmpl_dir in [PORTAL_TEMPLATES, PLATFORM_TEMPLATES, SHARED_TEMPLATES]:
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
    warning_count = len(by_severity.get(SEVERITY_WARNING, []))

    print("\n🔍 [A11Y] Accessibility Audit Results")
    print(f"{'─' * 60}")
    print(f"  🔥 Critical: {critical_count}")
    print(f"  ⚠️  Serious:  {serious_count}")
    print(f"  📝 Minor:    {minor_count}")
    print(gettext("  ⚠️  Warnings: {count}").format(count=warning_count))
    print(f"  Total:       {len(violations)}")
    print()

    # Summary by rule
    print("📊 Violations by rule:")
    for code in sorted(by_code.keys()):
        print(f"  {code}: {by_code[code]}")
    print()

    if verbose:
        for severity in [SEVERITY_CRITICAL, SEVERITY_SERIOUS, SEVERITY_MINOR, SEVERITY_WARNING]:
            items = by_severity.get(severity, [])
            if items:
                label = {
                    "critical": "🔥 CRITICAL",
                    "serious": "⚠️  SERIOUS",
                    "minor": "📝 MINOR",
                    "warning": gettext("⚠️  WARNING"),
                }[severity]
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
