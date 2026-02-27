"""
Scan Python and template files for hardcoded strings missing i18n wrappers.

Finds:
- ValidationError("str") without _() wrapper (I18N001)
- messages.success/error/warning/info(request, "str") without _() (I18N002)
- Model field help_text="str" without _() (I18N003)
- Model field verbose_name="str" without _() (I18N004)
- Choices tuple label ("code", "Label") without _() (I18N005)
- Form field label="str" without _() (I18N006)
- Admin short_description = "str" without _() (I18N007)
- Template hardcoded strings in buttons, alerts, headings (I18N008-I18N010)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

# Gettext wrapper function names that indicate proper i18n
I18N_WRAPPER_NAMES = {"_", "gettext", "gettext_lazy", "ngettext", "ngettext_lazy", "pgettext", "pgettext_lazy"}

# Keyword args that require i18n wrapping
I18N_KEYWORD_ARGS = {"help_text", "verbose_name", "verbose_name_plural", "label"}

# Keyword arg -> issue code mapping
KEYWORD_ISSUE_CODES = {
    "help_text": ("I18N003", "high"),
    "verbose_name": ("I18N004", "high"),
    "verbose_name_plural": ("I18N004", "high"),
    "label": ("I18N006", "critical"),
}

# Django messages methods
MESSAGES_METHODS = {"success", "error", "warning", "info"}

# Regex for strings that are technical/non-translatable
TECHNICAL_STRING_RE = re.compile(
    r"^("
    r"[0-9\s\.\,\-\+\*\/\%\#\@\!\?\;\:\'\"\(\)\[\]\{\}]*$"  # numbers/punctuation only
    r"|.$"  # single character
    r"|https?://\S+"  # URLs
    r"|/[\w/\.\-]+"  # file paths
    r"|[\w\.\-]+@[\w\.\-]+"  # emails
    r"|[\w\-]+\.[\w\-]+\.\w+"  # dotted identifiers (e.g., app.module.Class)
    r"|[A-Z_][A-Z0-9_]*$"  # UPPER_SNAKE constants
    r"|[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff]+"  # emoji-only
    r")",
    re.UNICODE,
)

# Template regex patterns
TEMPLATE_HEADING_RE = re.compile(
    r"<(th|h[1-6])(?:\s[^>]*)?>(?!\s*\{%\s*trans)"  # opening tag not followed by {% trans
    r"\s*([^<{]+?)\s*"  # content (no tags or template vars)
    r"</(th|h[1-6])>",
    re.IGNORECASE,
)
TEMPLATE_BUTTON_RE = re.compile(
    r'\{%\s*button\s+"([^"]+)"\s*%\}',
)
TEMPLATE_ALERT_RE = re.compile(
    r"""alert\(\s*['"]([^'"]+)['"]\s*\)""",
)


@dataclass(frozen=True)
class Issue:
    file: str
    line: int
    col: int
    severity: str
    code: str
    message: str
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def severity_at_least(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER[value] <= SEVERITY_ORDER[minimum]


def _is_string_constant(node: ast.expr) -> bool:
    """Check if an AST node is a plain string constant."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_i18n_wrapped(node: ast.expr) -> bool:
    """Check if a node is wrapped in a gettext call like _("...")."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in I18N_WRAPPER_NAMES
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in I18N_WRAPPER_NAMES
    return False


def _is_technical_string(value: str) -> bool:
    """Return True if the string looks like a non-translatable technical identifier."""
    if not value or not value.strip():
        return True
    return bool(TECHNICAL_STRING_RE.match(value.strip()))


def _get_string_value(node: ast.expr) -> str | None:
    """Extract string value from a Constant node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class I18nCoverageVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.issues: list[Issue] = []

    def visit_Call(self, node: ast.Call) -> Any:
        self._check_validation_error(node)
        self._check_messages_call(node)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> Any:
        if node.arg in I18N_KEYWORD_ARGS:
            self._check_keyword_arg(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._check_short_description(node)
        self._check_choices_tuple(node)
        self.generic_visit(node)

    def _check_validation_error(self, node: ast.Call) -> None:
        """I18N001: ValidationError("str") without _() wrapper."""
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name != "ValidationError":
            return
        if not node.args:
            return
        first_arg = node.args[0]
        if _is_i18n_wrapped(first_arg):
            return
        if not _is_string_constant(first_arg):
            return
        value = _get_string_value(first_arg)
        if value and _is_technical_string(value):
            return
        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="critical",
            code="I18N001",
            message=f'ValidationError("{value}") missing i18n wrapper — use _("...").',
        )

    def _check_messages_call(self, node: ast.Call) -> None:
        """I18N002: messages.success/error/warning/info(request, "str") without _()."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in MESSAGES_METHODS:
            return
        # Check it's called on messages (or something ending in messages)
        if isinstance(func.value, ast.Name) and func.value.id != "messages":
            return
        if len(node.args) < 2:
            return
        second_arg = node.args[1]
        if _is_i18n_wrapped(second_arg):
            return
        if not _is_string_constant(second_arg):
            return
        value = _get_string_value(second_arg)
        if value and _is_technical_string(value):
            return
        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="critical",
            code="I18N002",
            message=f'messages.{func.attr}() string "{value}" missing i18n wrapper.',
        )

    def _check_keyword_arg(self, node: ast.keyword) -> None:
        """I18N003/I18N004/I18N006: keyword args without _() wrapper."""
        assert node.arg is not None
        if _is_i18n_wrapped(node.value):
            return
        if not _is_string_constant(node.value):
            return
        value = _get_string_value(node.value)
        if value and _is_technical_string(value):
            return
        code, severity = KEYWORD_ISSUE_CODES[node.arg]
        self._add_issue(
            line=node.value.lineno if hasattr(node.value, "lineno") else 0,
            col=node.value.col_offset if hasattr(node.value, "col_offset") else 0,
            severity=severity,
            code=code,
            message=f'{node.arg}="{value}" missing i18n wrapper — use _("...").',
        )

    def _check_short_description(self, node: ast.Assign) -> None:
        """I18N007: short_description = "str" without _()."""
        if not node.targets:
            return
        target = node.targets[0]
        attr_name = None
        if isinstance(target, ast.Attribute):
            attr_name = target.attr
        elif isinstance(target, ast.Name):
            attr_name = target.id
        if attr_name != "short_description":
            return
        if _is_i18n_wrapped(node.value):
            return
        if not _is_string_constant(node.value):
            return
        value = _get_string_value(node.value)
        if value and _is_technical_string(value):
            return
        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="medium",
            code="I18N007",
            message=f'short_description = "{value}" missing i18n wrapper.',
        )

    def _check_choices_tuple(self, node: ast.Assign) -> None:
        """I18N005: choices tuple label without _()."""
        # Look for patterns like CHOICES = [("key", "Label"), ...]
        value = node.value
        items: list[ast.expr] = []
        if isinstance(value, (ast.List, ast.Tuple)):
            items = value.elts
        else:
            return

        for item in items:
            if not isinstance(item, ast.Tuple):
                continue
            if len(item.elts) < 2:
                continue
            label_node = item.elts[1]
            if _is_i18n_wrapped(label_node):
                continue
            if not _is_string_constant(label_node):
                continue
            label_value = _get_string_value(label_node)
            if label_value and _is_technical_string(label_value):
                continue
            self._add_issue(
                line=label_node.lineno if hasattr(label_node, "lineno") else item.lineno,
                col=label_node.col_offset if hasattr(label_node, "col_offset") else item.col_offset,
                severity="high",
                code="I18N005",
                message=f'Choices label "{label_value}" missing i18n wrapper — use _("...").',
            )

    def _add_issue(self, line: int, col: int, severity: str, code: str, message: str) -> None:
        snippet = ""
        if 1 <= line <= len(self.source_lines):
            snippet = self.source_lines[line - 1].rstrip()
        self.issues.append(
            Issue(
                file=self.file_path.as_posix(),
                line=line,
                col=col,
                severity=severity,
                code=code,
                message=message,
                snippet=snippet,
            )
        )


def scan_python_file(file_path: Path) -> tuple[list[Issue], str | None]:
    """Scan a single Python file for i18n coverage issues."""
    try:
        text = file_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [], f"read-error:{exc}"

    source_lines = text.splitlines()

    try:
        tree = ast.parse(text, filename=str(file_path))
    except SyntaxError as exc:
        issue = Issue(
            file=file_path.as_posix(),
            line=exc.lineno or 1,
            col=exc.offset or 0,
            severity="medium",
            code="parse-error",
            message=f"Failed to parse file: {exc.msg}",
            snippet=(exc.text or "").rstrip(),
        )
        return [issue], None

    visitor = I18nCoverageVisitor(file_path=file_path, source_lines=source_lines)
    visitor.visit(tree)

    return visitor.issues, None


def scan_template_file(file_path: Path) -> tuple[list[Issue], str | None]:
    """Scan a single template file for hardcoded strings."""
    try:
        text = file_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [], f"read-error:{exc}"

    source_lines = text.splitlines()
    issues: list[Issue] = []

    for lineno, line in enumerate(source_lines, start=1):
        # I18N008: {% button "hardcoded" %}
        for match in TEMPLATE_BUTTON_RE.finditer(line):
            value = match.group(1)
            if not _is_technical_string(value):
                # Check if line already has {% trans %} wrapping nearby
                if "{% trans" not in line:
                    issues.append(
                        Issue(
                            file=file_path.as_posix(),
                            line=lineno,
                            col=match.start(),
                            severity="low",
                            code="I18N008",
                            message=f'Button text "{value}" not wrapped in {{% trans %}}.',
                            snippet=line.rstrip(),
                        )
                    )

        # I18N009: alert('hardcoded string')
        for match in TEMPLATE_ALERT_RE.finditer(line):
            value = match.group(1)
            if not _is_technical_string(value):
                issues.append(
                    Issue(
                        file=file_path.as_posix(),
                        line=lineno,
                        col=match.start(),
                        severity="low",
                        code="I18N009",
                        message=f'JS alert("{value}") not wrapped in {{% trans %}}.',
                        snippet=line.rstrip(),
                    )
                )

        # I18N010: <th>Hardcoded</th> or <h1-h6>Hardcoded</h1-h6>
        for match in TEMPLATE_HEADING_RE.finditer(line):
            tag = match.group(1).lower()
            content = match.group(2).strip()
            closing_tag = match.group(3).lower()
            if tag != closing_tag:
                continue
            if not content or _is_technical_string(content):
                continue
            # Skip if content is only template variables {{ ... }}
            if re.match(r"^[\s\{%\}]+$", content):
                continue
            issues.append(
                Issue(
                    file=file_path.as_posix(),
                    line=lineno,
                    col=match.start(),
                    severity="low",
                    code="I18N010",
                    message=f'<{tag}> text "{content}" not wrapped in {{% trans %}}.',
                    snippet=line.rstrip(),
                )
            )

    return issues, None


def iter_files(root_paths: list[Path], extension: str, exclude_dir_names: set[str]) -> list[Path]:
    """Walk directories collecting files with the given extension."""
    files: list[Path] = []
    for root in root_paths:
        if not root.exists():
            continue
        if root.is_file():
            if root.name.endswith(extension):
                files.append(root)
            continue
        for current_root, dirs, filenames in os.walk(root):
            dirs[:] = [d for d in dirs if d not in exclude_dir_names and not d.startswith(".")]
            for filename in filenames:
                if not filename.endswith(extension):
                    continue
                files.append(Path(current_root) / filename)
    return files


def is_test_file(file_path: str) -> bool:
    """Check if a file is inside a tests directory."""
    return "/tests/" in file_path or file_path.endswith("/tests.py")


def load_allowlist(path: Path) -> set[str]:
    """Load allowlist entries as 'filepath:CODE' strings."""
    entries: set[str] = set()
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.add(line)
    return entries


def sort_issues(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (SEVERITY_ORDER[i.severity], i.file, i.line, i.col))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan Python and template files for hardcoded strings missing i18n wrappers.",
    )
    parser.add_argument(
        "roots",
        nargs="*",
        default=[],
        help=(
            "Root directories to scan (default: services/platform/apps, services/portal/apps "
            "for Python; services/platform/templates, services/portal/templates for templates)"
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to include (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="high",
        help="Exit code 1 if any issue at this severity or above (default: high)",
    )
    parser.add_argument(
        "--max-issues",
        type=int,
        default=300,
        help="Maximum number of issues to print in text mode (default: 300).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON.",
    )
    parser.add_argument(
        "--allowlist",
        type=str,
        default=None,
        help="Path to allowlist file (one 'filepath:I18N00X' per line).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    exclude_dir_names = {
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
        "staticfiles",
        "migrations",
        "htmlcov",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }

    # Determine roots
    if args.roots:
        python_roots: list[Path] = []
        template_roots: list[Path] = []
        for r in args.roots:
            p = Path(r)
            if p.is_file():
                if r.endswith(".py"):
                    python_roots.append(p)
                elif r.endswith(".html"):
                    template_roots.append(p)
            else:
                python_roots.append(p)
                template_roots.append(p)
    else:
        python_roots = [Path("services/platform/apps"), Path("services/portal/apps")]
        template_roots = [Path("services/platform/templates"), Path("services/portal/templates")]

    # Load allowlist
    allowlist: set[str] = set()
    if args.allowlist:
        allowlist = load_allowlist(Path(args.allowlist))

    # Scan Python files (skip test files)
    python_files = iter_files(python_roots, ".py", exclude_dir_names)
    python_files = [f for f in python_files if not is_test_file(f.as_posix())]

    # Scan template files
    template_files = iter_files(template_roots, ".html", exclude_dir_names)

    if args.roots and not python_files and not template_files:
        print(f"⚠️  Warning: no matching .py or .html files found in: {args.roots}", file=sys.stderr)

    all_issues: list[Issue] = []
    scan_errors: list[str] = []

    for file_path in python_files:
        issues, scan_error = scan_python_file(file_path)
        all_issues.extend(issues)
        if scan_error:
            scan_errors.append(f"{file_path.as_posix()}:{scan_error}")

    for file_path in template_files:
        issues, scan_error = scan_template_file(file_path)
        all_issues.extend(issues)
        if scan_error:
            scan_errors.append(f"{file_path.as_posix()}:{scan_error}")

    # Apply allowlist
    if allowlist:
        all_issues = [i for i in all_issues if f"{i.file}:{i.code}" not in allowlist]

    # Filter by min-severity
    all_issues = [i for i in all_issues if severity_at_least(i.severity, args.min_severity)]

    issues = sort_issues(all_issues)

    severity_counts = Counter(issue.severity for issue in issues)
    code_counts = Counter(issue.code for issue in issues)
    by_file: dict[str, int] = defaultdict(int)
    for issue in issues:
        by_file[issue.file] += 1

    total_files = len(python_files) + len(template_files)

    # Determine exit code based on --fail-on
    has_failure = False
    if args.fail_on != "none":
        has_failure = any(severity_at_least(i.severity, args.fail_on) for i in issues)

    if args.json:
        payload = {
            "summary": {
                "roots": {
                    "python": [p.as_posix() for p in python_roots],
                    "templates": [p.as_posix() for p in template_roots],
                },
                "files_scanned": total_files,
                "issues_found": len(issues),
                "severity_counts": dict(severity_counts),
                "issue_type_counts": dict(code_counts),
                "scan_errors": scan_errors,
                "top_files": sorted(by_file.items(), key=lambda item: item[1], reverse=True)[:20],
            },
            "issues": [issue.to_dict() for issue in issues],
        }
        print(json.dumps(payload, indent=2))
        return 1 if has_failure else 0

    print("i18n Coverage Lint")
    print(f"Python roots: {', '.join(p.as_posix() for p in python_roots)}")
    print(f"Template roots: {', '.join(p.as_posix() for p in template_roots)}")
    print(f"Files scanned: {total_files} ({len(python_files)} Python, {len(template_files)} templates)")
    print(f"Issues found (severity>={args.min_severity}): {len(issues)}")
    if allowlist:
        print(f"Allowlist entries: {len(allowlist)}")
    if scan_errors:
        print(f"File read errors: {len(scan_errors)}")

    if issues:
        print("\nSeverity counts:")
        for severity in ["critical", "high", "medium", "low"]:
            if severity in severity_counts:
                print(f"  {severity:8} {severity_counts[severity]}")

        print("\nIssue type counts:")
        for code, count in code_counts.most_common():
            print(f"  {code:25} {count}")

        print("\nTop files:")
        for file_name, count in sorted(by_file.items(), key=lambda item: item[1], reverse=True)[:20]:
            print(f"  {count:4}  {file_name}")

        print("\nFindings:")
        for issue in issues[: args.max_issues]:
            print(
                f"[{issue.severity.upper():8}] {issue.code:25} "
                f"{issue.file}:{issue.line}:{issue.col} - {issue.message}"
            )
            if issue.snippet:
                print(f"    {issue.snippet.strip()}")

        if len(issues) > args.max_issues:
            hidden = len(issues) - args.max_issues
            print(f"\n... truncated {hidden} additional findings (increase --max-issues).")
    else:
        print("No findings at selected severity.")

    return 1 if has_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
