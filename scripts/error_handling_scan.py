#!/usr/bin/env python3
"""
Scan Python code for risky error-handling patterns.

Finds:
- Broad or bare exception handlers that suppress failures
- `contextlib.suppress(Exception)` usage
- Calls that intentionally silence failures (`fail_silently=True`, etc.)
- Potential process-terminating calls in application code (`sys.exit`, `os._exit`)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
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


def expr_to_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def is_true_constant(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return node.value is True
    return False


class ErrorHandlingVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.issues: list[Issue] = []
        self._stack: list[ast.AST] = []

    def visit(self, node: ast.AST) -> Any:
        self._stack.append(node)
        result = super().visit(node)
        self._stack.pop()
        return result

    def visit_Try(self, node: ast.Try) -> Any:
        for handler in node.handlers:
            self._analyze_except_handler(handler)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        self._analyze_with_items(node.items, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self._analyze_with_items(node.items, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._analyze_error_silencing_kwargs(node)
        self._analyze_exit_calls(node)
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> Any:
        if self._is_system_exit_raise(node):
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity=self._exit_severity(),
                code="process-exit",
                message="`raise SystemExit` can terminate the process if not guarded.",
            )
        self.generic_visit(node)

    def _analyze_except_handler(self, handler: ast.ExceptHandler) -> None:
        is_bare = handler.type is None
        is_broad = is_bare or self._is_broad_exception_type(handler.type)
        action = self._classify_handler_action(handler.body)
        has_raise = self._handler_has_raise(handler.body)
        exc_text = "bare except" if is_bare else expr_to_text(handler.type)

        if is_bare:
            severity = "critical" if action in {"pass", "return-none", "return-value", "continue", "break"} else "high"
            self._add_issue(
                line=handler.lineno,
                col=handler.col_offset,
                severity=severity,
                code="bare-except",
                message=f"Bare `except:` catches system exceptions and may hide failures (action: {action}).",
            )
            return

        if self._is_base_exception_type(handler.type):
            severity = "critical" if action in {"pass", "return-none", "return-value", "continue", "break"} else "high"
            self._add_issue(
                line=handler.lineno,
                col=handler.col_offset,
                severity=severity,
                code="baseexception-catch",
                message=f"`except {exc_text}:` catches process-level exceptions (action: {action}).",
            )
            return

        if action in {"pass", "continue", "break"}:
            self._add_issue(
                line=handler.lineno,
                col=handler.col_offset,
                severity="high" if is_broad else "medium",
                code="silent-except",
                message=f"`except {exc_text}: {action}` suppresses failure with no recovery.",
            )
            return

        if action in {"return-none", "return-value"} and not has_raise:
            self._add_issue(
                line=handler.lineno,
                col=handler.col_offset,
                severity="medium",
                code="fallback-except",
                message=f"`except {exc_text}` converts exception into fallback return ({action}).",
            )
            return

        if is_broad and not has_raise:
            self._add_issue(
                line=handler.lineno,
                col=handler.col_offset,
                severity="medium",
                code="broad-except",
                message=f"`except {exc_text}` is broad and does not re-raise.",
            )

    def _analyze_with_items(self, items: list[ast.withitem], line: int, col: int) -> None:
        for item in items:
            context_expr = item.context_expr
            if not isinstance(context_expr, ast.Call):
                continue

            callee = context_expr.func
            is_suppress = False
            if isinstance(callee, ast.Name) and callee.id == "suppress":
                is_suppress = True
            elif isinstance(callee, ast.Attribute) and callee.attr == "suppress":
                is_suppress = True

            if not is_suppress:
                continue

            if not context_expr.args:
                continue

            catches_broad = any(self._is_broad_exception_type(arg) for arg in context_expr.args)
            severity = "high" if catches_broad else "low"
            self._add_issue(
                line=line,
                col=col,
                severity=severity,
                code="contextlib-suppress",
                message=f"`suppress({', '.join(expr_to_text(a) for a in context_expr.args)})` hides exceptions.",
            )

    def _analyze_error_silencing_kwargs(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "fail_silently" and is_true_constant(keyword.value):
                self._add_issue(
                    line=node.lineno,
                    col=node.col_offset,
                    severity="medium",
                    code="fail-silently",
                    message="Call uses `fail_silently=True` and may hide operational failures.",
                )
            if keyword.arg == "ignore_errors" and is_true_constant(keyword.value):
                self._add_issue(
                    line=node.lineno,
                    col=node.col_offset,
                    severity="medium",
                    code="ignore-errors",
                    message="Call uses `ignore_errors=True` and may suppress failures.",
                )
            if keyword.arg == "return_exceptions" and is_true_constant(keyword.value):
                self._add_issue(
                    line=node.lineno,
                    col=node.col_offset,
                    severity="medium",
                    code="return-exceptions",
                    message="`return_exceptions=True` returns errors as values and can mask failures.",
                )

    def _analyze_exit_calls(self, node: ast.Call) -> None:
        call_kind: str | None = None
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "sys" and node.func.attr == "exit":
                call_kind = "sys.exit"
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "_exit":
                call_kind = "os._exit"

        if call_kind is None:
            return

        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity=self._exit_severity(),
            code="process-exit",
            message=f"`{call_kind}()` can terminate the process if executed in app runtime.",
        )

    def _handler_has_raise(self, body: list[ast.stmt]) -> bool:
        module = ast.Module(body=body, type_ignores=[])
        return any(isinstance(node, ast.Raise) for node in ast.walk(module))

    def _classify_handler_action(self, body: list[ast.stmt]) -> str:
        if not body:
            return "empty"

        if len(body) == 1:
            only = body[0]
            if isinstance(only, ast.Pass):
                return "pass"
            if isinstance(only, ast.Continue):
                return "continue"
            if isinstance(only, ast.Break):
                return "break"
            if isinstance(only, ast.Return):
                if only.value is None or (isinstance(only.value, ast.Constant) and only.value.value is None):
                    return "return-none"
                return "return-value"
            if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is Ellipsis:
                return "ellipsis"

        has_logging = any(self._is_logging_stmt(stmt) for stmt in body)
        has_raise = self._handler_has_raise(body)

        if has_logging and not has_raise:
            return "log-and-swallow"
        if has_raise:
            return "raises"
        return "custom"

    def _is_logging_stmt(self, stmt: ast.stmt) -> bool:
        if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
            return False
        call = stmt.value
        func = call.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id in {"logger", "logging"}:
                return func.attr in {"debug", "info", "warning", "error", "exception", "critical"}
        return False

    def _is_broad_exception_type(self, node: ast.AST | None) -> bool:
        if node is None:
            return True
        if isinstance(node, ast.Name):
            return node.id in {"Exception", "BaseException"}
        if isinstance(node, ast.Tuple):
            return any(self._is_broad_exception_type(elt) for elt in node.elts)
        if isinstance(node, ast.Attribute):
            return node.attr in {"Exception", "BaseException"}
        return False

    def _is_base_exception_type(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id == "BaseException"
        if isinstance(node, ast.Tuple):
            return any(self._is_base_exception_type(elt) for elt in node.elts)
        if isinstance(node, ast.Attribute):
            return node.attr == "BaseException"
        return False

    def _is_system_exit_raise(self, node: ast.Raise) -> bool:
        if node.exc is None:
            return False
        if isinstance(node.exc, ast.Name):
            return node.exc.id == "SystemExit"
        if isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name):
                return node.exc.func.id == "SystemExit"
        return False

    def _exit_severity(self) -> str:
        file_str = self.file_path.as_posix()
        if self._inside_main_guard() or "/scripts/" in file_str or "/management/commands/" in file_str:
            return "low"
        if "/tests/" in file_str:
            return "low"
        return "high"

    def _inside_main_guard(self) -> bool:
        for node in reversed(self._stack):
            if isinstance(node, ast.If) and self._is_main_guard_test(node.test):
                return True
        return False

    def _is_main_guard_test(self, test: ast.AST) -> bool:
        if not isinstance(test, ast.Compare):
            return False
        if not isinstance(test.left, ast.Name) or test.left.id != "__name__":
            return False
        if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
            return False
        if len(test.comparators) != 1:
            return False
        comparator = test.comparators[0]
        return isinstance(comparator, ast.Constant) and comparator.value == "__main__"

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

    visitor = ErrorHandlingVisitor(file_path=file_path, source_lines=text.splitlines())
    visitor.visit(tree)
    return visitor.issues, None


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
        description="Scan Python files for risky error suppression and crash-prone patterns.",
    )
    parser.add_argument(
        "roots",
        nargs="*",
        default=["services", "tests"],
        help="Root directories to scan (default: services tests)",
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

    print("Error Handling Risk Scan")
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
            print(f"  {code:20} {count}")

        print("\nTop files:")
        for file_name, count in sorted(by_file.items(), key=lambda item: item[1], reverse=True)[:20]:
            print(f"  {count:4}  {file_name}")

        print("\nFindings:")
        for issue in issues[: args.max_issues]:
            print(
                f"[{issue.severity.upper():8}] {issue.code:20} {issue.file}:{issue.line}:{issue.col} - {issue.message}"
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
