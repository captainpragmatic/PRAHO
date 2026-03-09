#!/usr/bin/env python3
"""
Scan Python code for recurring anti-patterns found during chaos-monkey reviews.

Detects:
- TODO/FIXME/HACK stubs with placeholder bodies (return True/pass/docstring-only)
- Magic numeric defaults in getattr() calls (> threshold)
- Always-true authentication/verification functions (security critical)
- .save() calls in service files without transaction.atomic() guards
- Signal handlers that call .save() on sender model without recursion guards
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

# ─── Severity ────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def severity_at_least(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER[value] <= SEVERITY_ORDER[minimum]


# ─── Issue dataclass ─────────────────────────────────────────────────────────


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


# ─── Rule constants ──────────────────────────────────────────────────────────

RULE_TODO_STUB = "todo-stub"
RULE_MAGIC_GETATTR = "magic-getattr-default"
RULE_ALWAYS_TRUE_AUTH = "always-true-auth"
RULE_SAVE_WITHOUT_ATOMIC = "save-without-atomic"
RULE_SIGNAL_SAVES_SENDER = "signal-saves-sender"

AUTH_FUNCTION_PREFIXES = ("verify_", "authenticate_", "check_permission", "validate_signature")

TODO_MARKERS = {"TODO:", "FIXME:", "HACK:"}

RECURSION_GUARD_PATTERNS = {"_processing", "_in_signal", "_guard", "_saving", "update_fields"}

MAGIC_GETATTR_THRESHOLD = 100


# ─── Path helpers ────────────────────────────────────────────────────────────


def is_test_file(file_path: str) -> bool:
    path = Path(file_path)
    parts = set(path.parts)
    return "tests" in parts


def is_service_file(path: Path) -> bool:
    """Match *service*.py and *services*.py files."""
    name = path.name.lower()
    return "service" in name


def is_exempt_path(path: Path, rule: str) -> bool:
    """Per-rule path exemptions."""
    parts_str = path.as_posix()
    # Migrations are always exempt
    if "/migrations/" in parts_str:
        return True
    # Rule-specific exemptions
    if rule == RULE_SAVE_WITHOUT_ATOMIC:
        # Only enforce in service files, skip admin/models/tests/management
        if not is_service_file(path):
            return True
        if any(seg in parts_str for seg in ("/admin", "/models", "/tests/", "/management/")):
            return True
    if rule == RULE_SIGNAL_SAVES_SENDER:
        if "/management/" in parts_str:
            return True
    return False


# ─── AST Visitor ─────────────────────────────────────────────────────────────


class CodeHealthVisitor(ast.NodeVisitor):
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

    # ── Function-level checks ────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._check_todo_stub(node)
        self._check_always_true_auth(node)
        self._check_signal_saves_sender(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._check_todo_stub(node)
        self._check_always_true_auth(node)
        self.generic_visit(node)

    # ── Call-level checks ────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> Any:
        self._check_magic_getattr(node)
        self._check_save_without_atomic(node)
        self.generic_visit(node)

    # ── Rule 1: todo-stub ────────────────────────────────────────────────

    def _check_todo_stub(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Flag functions with TODO/FIXME/HACK markers AND placeholder bodies."""
        if node.end_lineno is None:
            return

        # Read source lines for this function
        start = node.lineno - 1
        end = node.end_lineno
        func_lines = self.source_lines[start:end]
        func_text = "\n".join(func_lines)

        # Check for TODO markers in any comment or string
        has_marker = any(marker in func_text for marker in TODO_MARKERS)
        if not has_marker:
            return

        # Check if body is a placeholder
        if self._is_placeholder_body(node.body) or self._has_trivial_return(node.body):
            self._add_issue(
                line=node.lineno,
                col=node.col_offset,
                severity="high",
                code=RULE_TODO_STUB,
                message=f"Function `{node.name}` has TODO/FIXME marker with placeholder body — stub not implemented.",
            )

    def _is_placeholder_body(self, body: list[ast.stmt]) -> bool:
        """Check if function body is pass, docstring-only, or logger-only."""
        if not body:
            return True

        # Filter out docstrings
        stmts = body
        if (
            stmts
            and isinstance(stmts[0], ast.Expr)
            and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)
        ):
            stmts = stmts[1:]

        if not stmts:
            return True  # docstring-only

        # Single pass or ellipsis
        if len(stmts) == 1:
            only = stmts[0]
            if isinstance(only, ast.Pass):
                return True
            if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is Ellipsis:
                return True

        # All statements are logger calls
        return all(self._is_logger_call(stmt) for stmt in stmts)

    def _has_trivial_return(self, body: list[ast.stmt]) -> bool:
        """Check if body has only trivial return (True/False/None/{}) after optional docstring/logger."""
        # Filter out docstrings and logger calls
        meaningful = []
        for stmt in body:
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                continue  # docstring
            if self._is_logger_call(stmt):
                continue
            meaningful.append(stmt)

        if len(meaningful) != 1:
            return False

        only = meaningful[0]
        if not isinstance(only, ast.Return):
            return False

        # return True / return False / return None / return {}
        val = only.value
        if val is None:
            return True
        if isinstance(val, ast.Constant) and val.value in (True, False, None):
            return True
        return bool(isinstance(val, ast.Dict) and not val.keys)

    def _is_logger_call(self, stmt: ast.stmt) -> bool:
        """Check if statement is a logger.xxx() call."""
        if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
            return False
        func = stmt.value.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id in {"logger", "logging"}:
                return func.attr in {"debug", "info", "warning", "error", "exception", "critical"}
        return False

    # ── Rule 2: magic-getattr-default ────────────────────────────────────

    def _check_magic_getattr(self, node: ast.Call) -> None:
        """Flag getattr(obj, name, <large_numeric_default>)."""
        if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
            return
        if len(node.args) != 3:
            return

        default_arg = node.args[2]
        if not isinstance(default_arg, ast.Constant):
            return
        if not isinstance(default_arg.value, (int, float)):
            return
        if abs(default_arg.value) <= MAGIC_GETATTR_THRESHOLD:
            return

        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="medium",
            code=RULE_MAGIC_GETATTR,
            message=f"Magic numeric default {default_arg.value} in getattr() — extract to a named constant.",
        )

    # ── Rule 3: always-true-auth ─────────────────────────────────────────

    def _check_always_true_auth(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Flag auth/verify functions that unconditionally return True."""
        if not any(node.name.startswith(prefix) for prefix in AUTH_FUNCTION_PREFIXES):
            return

        # Strip docstring and logger calls from body
        meaningful = []
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                continue
            if self._is_logger_call(stmt):
                continue
            meaningful.append(stmt)

        # Must be exactly one Return(True) statement
        if len(meaningful) != 1:
            return
        only = meaningful[0]
        if not isinstance(only, ast.Return):
            return
        if not isinstance(only.value, ast.Constant) or only.value.value is not True:
            return

        # Ensure there's no branching logic at all in the full body
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.Try)):
                return

        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="critical",
            code=RULE_ALWAYS_TRUE_AUTH,
            message=(
                f"Auth function `{node.name}` unconditionally returns True — "
                "security bypass: verification/authentication is not implemented."
            ),
        )

    # ── Rule 4: save-without-atomic ──────────────────────────────────────

    def _check_save_without_atomic(self, node: ast.Call) -> None:
        """Flag .save() in service files outside transaction.atomic()."""
        if is_exempt_path(self.file_path, RULE_SAVE_WITHOUT_ATOMIC):
            return

        # Check it's a .save() call
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "save":
            return

        # Skip if save has update_fields kwarg (targeted save, lower risk)
        for kw in node.keywords:
            if kw.arg == "update_fields":
                return

        if self._is_inside_atomic():
            return

        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="medium",
            code=RULE_SAVE_WITHOUT_ATOMIC,
            message=(
                "Bare `.save()` in service without `transaction.atomic()` guard — "
                "consider adding atomicity or `update_fields`."
            ),
        )

    def _is_inside_atomic(self) -> bool:
        """Check if current position is inside a transaction.atomic() context."""
        for node in reversed(self._stack):
            # Check with/async with for transaction.atomic()
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    ctx = item.context_expr
                    if isinstance(ctx, ast.Call) and self._is_atomic_call(ctx):
                        return True
            # Check function decorators for @transaction.atomic
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for deco in node.decorator_list:
                    if self._is_atomic_ref(deco):
                        return True
        return False

    def _is_atomic_call(self, node: ast.Call) -> bool:
        """Check if a Call node is transaction.atomic()."""
        return self._is_atomic_ref(node.func)

    def _is_atomic_ref(self, node: ast.AST) -> bool:
        """Check if node references transaction.atomic."""
        if isinstance(node, ast.Attribute) and node.attr == "atomic":
            if isinstance(node.value, ast.Name) and node.value.id == "transaction":
                return True
        # Also match bare `atomic` import
        return isinstance(node, ast.Name) and node.id == "atomic"

    # ── Rule 5: signal-saves-sender ──────────────────────────────────────

    def _check_signal_saves_sender(self, node: ast.FunctionDef) -> None:
        """Flag post_save signal handlers that call .save() without recursion guard."""
        if is_exempt_path(self.file_path, RULE_SIGNAL_SAVES_SENDER):
            return

        # Check for @receiver(post_save, ...) decorator
        if not self._has_post_save_decorator(node):
            return

        # Check if body contains any .save() call
        has_save = False
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "save":
                has_save = True
                break

        if not has_save:
            return

        # Check for recursion guard patterns in source text
        if node.end_lineno is None:
            return
        start = node.lineno - 1
        end = node.end_lineno
        func_text = "\n".join(self.source_lines[start:end])

        for guard in RECURSION_GUARD_PATTERNS:
            if guard in func_text:
                return

        self._add_issue(
            line=node.lineno,
            col=node.col_offset,
            severity="medium",
            code=RULE_SIGNAL_SAVES_SENDER,
            message=(
                f"Signal handler `{node.name}` calls `.save()` inside post_save "
                "without recursion guard — risk of infinite loop."
            ),
        )

    def _has_post_save_decorator(self, node: ast.FunctionDef) -> bool:
        """Check if function is decorated with @receiver(post_save, ...)."""
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            # @receiver(post_save, ...)
            is_receiver = (isinstance(func, ast.Name) and func.id == "receiver") or (
                isinstance(func, ast.Attribute) and func.attr == "receiver"
            )
            if not is_receiver:
                continue
            # Check first arg is post_save (not pre_delete, post_delete)
            if deco.args:
                first = deco.args[0]
                if isinstance(first, ast.Name) and first.id in ("pre_delete", "post_delete"):
                    continue
                if isinstance(first, ast.Name) and first.id == "post_save":
                    return True
                # Also match other save-related signals
                if isinstance(first, ast.Name) and first.id in ("pre_save",):
                    return True
            # Check sender kwarg
            for kw in deco.keywords:
                if kw.arg == "signal":
                    if isinstance(kw.value, ast.Name) and kw.value.id in ("pre_delete", "post_delete"):
                        break
            else:
                # If we got here with a receiver decorator, assume it might be post_save
                if deco.args:
                    return True
        return False

    # ── Shared helpers ───────────────────────────────────────────────────

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


# ─── File scanning ───────────────────────────────────────────────────────────


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

    visitor = CodeHealthVisitor(file_path=file_path, source_lines=text.splitlines())
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


def sort_issues(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (SEVERITY_ORDER[i.severity], i.file, i.line, i.col))


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan Python files for recurring code health anti-patterns.",
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
        "--allowlist",
        metavar="FILE",
        help="Path to allowlist file. Lines starting with '#' are comments. "
        "Each non-blank line is a '<file>:<line>:<code>' pattern to suppress.",
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

    # Load allowlist entries: each line is "<file_fragment>:<line>:<code>" or a comment
    allowlist: set[str] = set()
    if args.allowlist:
        allowlist_path = Path(args.allowlist)
        if allowlist_path.exists():
            for raw in allowlist_path.read_text().splitlines():
                entry = raw.strip()
                if entry and not entry.startswith("#"):
                    allowlist.add(entry)

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

    # Apply allowlist suppressions
    if allowlist:

        def _is_allowed(issue: Issue) -> bool:
            key = f"{issue.file}:{issue.line}:{issue.code}"
            return any(key.endswith(entry) or entry in key for entry in allowlist)

        issues = [i for i in issues if not _is_allowed(i)]

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

    print("Code Health Scan")
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
