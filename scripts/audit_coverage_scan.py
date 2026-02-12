#!/usr/bin/env python3
"""
Scan Python code for audit coverage gaps and anti-patterns.

Finds:
- Placeholder audit functions (empty stubs that bypass real auditing)
- Commented-out audit decorators
- Deprecated audit API usage (`log_event_legacy`)
- Direct `AuditEvent.objects.create()` calls outside `apps/audit/`
- Service files in critical domains missing audit imports
- Placeholder financial validation functions (empty stubs)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
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

PLACEHOLDER_AUDIT_FUNCTIONS = {"log_security_event"}

PLACEHOLDER_VALIDATION_FUNCTIONS = {
    "validate_financial_amount",
    "validate_financial_json",
    "validate_financial_text_field",
}

# Canonical implementation files - these are the real implementations, not placeholders
CANONICAL_AUDIT_FILES = {
    "apps/audit/",
    "apps/common/validators.py",
}

CANONICAL_VALIDATION_FILES = {
    "apps/billing/validators.py",
    "apps/common/validators.py",
}

# Critical app directories that must have audit coverage in service files
CRITICAL_APP_DIRS = {"billing", "orders", "users", "customers"}

COMMENTED_DECORATOR_RE = re.compile(r"^\s*#\s*@audit_service_call\(")


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


def _is_in_canonical_path(file_path: Path, canonical_paths: set[str]) -> bool:
    posix = file_path.as_posix()
    return any(canon in posix for canon in canonical_paths)


def _is_placeholder_body(body: list[ast.stmt]) -> bool:
    """Check if a function body is a placeholder (empty stub).

    Detects: pass, Ellipsis (...), docstring-only, and bodies that only
    contain logger.info/warning/debug calls (the original GAP 1 pattern).
    """
    if not body:
        return True

    # Filter out docstrings (first statement being a string constant)
    stmts = body
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]

    if not stmts:
        # Docstring-only function
        return True

    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
            continue
        if _is_logger_call(stmt):
            continue
        # Found a real statement
        return False

    return True


def _is_logger_call(stmt: ast.stmt) -> bool:
    """Check if a statement is a logger.info/warning/debug/etc. call."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    func = stmt.value.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in {"logger", "logging"}:
            return func.attr in {"debug", "info", "warning", "error", "exception", "critical"}
    return False


class AuditCoverageVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.issues: list[Issue] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._check_placeholder_audit(node)
        self._check_placeholder_validation(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> Any:
        self._check_deprecated_audit_api(node)
        self._check_direct_audit_model(node)
        self.generic_visit(node)

    def _check_placeholder_audit(self, node: ast.FunctionDef) -> None:
        if node.name not in PLACEHOLDER_AUDIT_FUNCTIONS:
            return
        if _is_in_canonical_path(self.file_path, CANONICAL_AUDIT_FILES):
            return
        if _is_placeholder_body(node.body):
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity="critical",
                code="placeholder-audit",
                message=f"Placeholder audit function `{node.name}()` has empty/stub body — auditing is bypassed.",
            )

    def _check_placeholder_validation(self, node: ast.FunctionDef) -> None:
        if node.name not in PLACEHOLDER_VALIDATION_FUNCTIONS:
            return
        if _is_in_canonical_path(self.file_path, CANONICAL_VALIDATION_FILES):
            return
        if _is_placeholder_body(node.body):
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity="high",
                code="placeholder-validation",
                message=f"Placeholder validation function `{node.name}()` has empty/stub body — validation is bypassed.",
            )

    def _check_deprecated_audit_api(self, node: ast.Call) -> None:
        if _is_in_canonical_path(self.file_path, {"apps/audit/"}):
            return
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr == "log_event_legacy":
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity="medium",
                code="deprecated-audit-api",
                message="`log_event_legacy()` is deprecated — use `log_security_event()` from `apps.audit.services`.",
            )

    def _check_direct_audit_model(self, node: ast.Call) -> None:
        if _is_in_canonical_path(self.file_path, {"apps/audit/"}):
            return
        # Detect AuditEvent.objects.create() — chained attribute access
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "create":
            return
        # Check for *.objects.create where * ends with AuditEvent
        objects_node = func.value
        if not isinstance(objects_node, ast.Attribute) or objects_node.attr != "objects":
            return
        model_node = objects_node.value
        if isinstance(model_node, ast.Name) and model_node.id == "AuditEvent":
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity="medium",
                code="direct-audit-model",
                message="`AuditEvent.objects.create()` bypasses the audit service layer — use `apps.audit.services` instead.",
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


def scan_file_for_comments(file_path: Path, source_lines: list[str]) -> list[Issue]:
    """Regex-based scan for commented-out audit decorators."""
    issues: list[Issue] = []
    for lineno, line in enumerate(source_lines, start=1):
        if COMMENTED_DECORATOR_RE.search(line):
            issues.append(
                Issue(
                    file=file_path.as_posix(),
                    line=lineno,
                    col=0,
                    severity="high",
                    code="commented-audit-decorator",
                    message="Commented-out `@audit_service_call` decorator — audit coverage disabled.",
                    snippet=line.rstrip(),
                )
            )
    return issues


def check_service_audit_imports(file_path: Path, source: str) -> list[Issue]:
    """Check that service files in critical domains import audit functions."""
    posix = file_path.as_posix()
    filename = file_path.name

    # Only check service files
    if filename not in ("services.py",) and not filename.endswith("_service.py"):
        return []

    # Only check critical app directories
    is_critical = any(f"apps/{app_dir}/" in posix for app_dir in CRITICAL_APP_DIRS)
    if not is_critical:
        return []

    # Skip test files
    if "/tests/" in posix:
        return []

    # Check for audit-related imports or usage
    has_audit_import = "apps.audit" in source
    has_security_event = "log_security_event" in source

    if not has_audit_import and not has_security_event:
        return [
            Issue(
                file=posix,
                line=1,
                col=0,
                severity="low",
                code="service-no-audit",
                message=(
                    f"Service file `{filename}` in critical domain has no audit imports "
                    "— consider adding `log_security_event` for key operations."
                ),
                snippet="",
            )
        ]
    return []


def iter_python_files(root_paths: list[Path], exclude_dir_names: set[str]) -> list[Path]:
    files: list[Path] = []
    for root in root_paths:
        if not root.exists():
            continue
        for current_root, dirs, filenames in os.walk(root):
            dirs[:] = [d for d in dirs if d not in exclude_dir_names and not d.startswith(".")]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                files.append(Path(current_root) / filename)
    return files


def scan_file(file_path: Path) -> tuple[list[Issue], str | None]:
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

    issues: list[Issue] = []

    # AST-based checks
    visitor = AuditCoverageVisitor(file_path=file_path, source_lines=source_lines)
    visitor.visit(tree)
    issues.extend(visitor.issues)

    # Comment-based checks
    issues.extend(scan_file_for_comments(file_path, source_lines))

    # Service-level import checks
    issues.extend(check_service_audit_imports(file_path, text))

    return issues, None


def filter_issues(issues: list[Issue], min_severity: str, exclude_tests: bool) -> list[Issue]:
    filtered: list[Issue] = []
    for issue in issues:
        if exclude_tests and is_test_file(issue.file):
            continue
        if severity_at_least(issue.severity, min_severity):
            filtered.append(issue)
    return filtered


def is_test_file(file_path: str) -> bool:
    path = Path(file_path)
    parts = set(path.parts)
    return "tests" in parts


def sort_issues(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (SEVERITY_ORDER[i.severity], i.file, i.line, i.col))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan Python files for audit coverage gaps and anti-patterns.",
    )
    parser.add_argument(
        "roots",
        nargs="*",
        default=["services/platform/apps"],
        help="Root directories to scan (default: services/platform/apps)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to include (default: medium)",
    )
    parser.add_argument(
        "--exclude-tests",
        action="store_true",
        help="Exclude files under */tests/* from report output.",
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

    root_paths = [Path(root) for root in args.roots]
    files = iter_python_files(root_paths, exclude_dir_names)

    all_issues: list[Issue] = []
    scan_errors: list[str] = []
    for file_path in files:
        issues, scan_error = scan_file(file_path)
        all_issues.extend(issues)
        if scan_error:
            scan_errors.append(f"{file_path.as_posix()}:{scan_error}")

    issues = sort_issues(filter_issues(all_issues, args.min_severity, args.exclude_tests))

    severity_counts = Counter(issue.severity for issue in issues)
    code_counts = Counter(issue.code for issue in issues)
    by_file: dict[str, int] = defaultdict(int)
    for issue in issues:
        by_file[issue.file] += 1

    if args.json:
        payload = {
            "summary": {
                "roots": [p.as_posix() for p in root_paths],
                "files_scanned": len(files),
                "issues_found": len(issues),
                "severity_counts": dict(severity_counts),
                "issue_type_counts": dict(code_counts),
                "scan_errors": scan_errors,
                "top_files": sorted(by_file.items(), key=lambda item: item[1], reverse=True)[:20],
            },
            "issues": [issue.to_dict() for issue in issues],
        }
        print(json.dumps(payload, indent=2))
        return 1 if issues else 0

    print("Audit Coverage Scan")
    print(f"Roots: {', '.join(p.as_posix() for p in root_paths)}")
    print(f"Files scanned: {len(files)}")
    print(f"Issues found (severity>={args.min_severity}): {len(issues)}")
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

    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
