"""
FSM guardrail lint script for PRAHO Platform.

Detects bypass patterns that circumvent django-fsm-2 FSMField(protected=True).
Part of the defense-in-depth strategy from ADR-0034.

Uses a hybrid approach:
- AST analysis on model files to auto-detect which classes use FSMField
- App-level scoping for service/view files (cannot resolve cross-file instance types)
- Inline `# fsm-bypass:` comments for one-off suppressions

Checks:
1. No direct .status = in app code (must use @transition methods)
2. No QuerySet.update(status=) bypassing model methods
3. No bulk_update with status fields
4. No __dict__['status'] outside test helpers
5. No side effects (HTTP/email) inside @transition methods

Exit codes:
  0 - No violations found
  1 - Violations found (fails the lint gate)

Usage:
  python scripts/lint_fsm_guardrails.py              # Scan all apps
  python scripts/lint_fsm_guardrails.py --json        # JSON output
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# FSM-protected status field names across all models
FSM_STATUS_FIELDS = frozenset({"status", "provisioning_status"})

# Apps that contain FSM-protected models.
# Only files under these app directories are scanned for checks 1-3.
# New apps with FSM models must be added here.
FSM_APPS = frozenset(
    {
        "apps/orders",
        "apps/billing",
        "apps/provisioning",
        "apps/domains",
        "apps/tickets",
    }
)

# Non-model files within FSM apps that exclusively touch non-FSM models.
# Model files are auto-detected via AST (no manual exclusion needed).
# This list is only for service/view/task files that work with non-FSM models
# like VirtualminTask, PaymentRetryAttempt, CollectionRun, UsageAggregation, etc.
NON_FSM_SERVICE_FILES = frozenset(
    {
        "billing/metering_service.py",
        "billing/stripe_metering.py",
        "billing/usage_invoice_service.py",
        "billing/tasks.py",
        "provisioning/virtualmin_service.py",
        "provisioning/virtualmin_views.py",
    }
)

# Paths that are allowed to use __dict__ bypass
ALLOWED_DICT_BYPASS_PATHS = frozenset(
    {
        "tests/helpers/fsm_helpers.py",
    }
)

# Paths that are allowed to have direct status assignments (test files)
TEST_PATH_PATTERNS = frozenset(
    {
        "/tests/",
    }
)

# Files where refresh_from_db override legitimately touches __dict__
REFRESH_OVERRIDE_PATTERN = re.compile(r"def refresh_from_db\(")

# Patterns for side effects inside transition methods
SIDE_EFFECT_PATTERNS = [
    (re.compile(r"\brequests\.(get|post|put|patch|delete)\b"), "HTTP request via requests"),
    (re.compile(r"\bsafe_request\b"), "HTTP request via safe_request"),
    (re.compile(r"\bsend_mail\b"), "Email send via send_mail"),
    (re.compile(r"\bEmailMessage\b"), "Email send via EmailMessage"),
    (re.compile(r"\bstripe\.\w+\.\w+\b"), "Stripe API call"),
]


@dataclass
class Violation:
    """A single FSM guardrail violation."""

    file: str
    line: int
    check: str
    message: str
    severity: str = "error"


@dataclass
class ScanResult:
    """Results from scanning the codebase."""

    violations: list[Violation] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0


# ---------------------------------------------------------------------------
# AST-based FSM model detection
# ---------------------------------------------------------------------------


class _FSMModelDetector(ast.NodeVisitor):
    """Detect which classes in a file declare FSMField on status fields.

    Visits class bodies looking for assignments like:
        status = FSMField(protected=True, ...)
        provisioning_status = FSMField(...)

    Builds a set of class names that are FSM-protected.
    """

    def __init__(self) -> None:
        self.fsm_classes: set[str] = set()
        # Map field_name -> set of class names that protect it via FSMField
        self.fsm_fields_by_class: dict[str, set[str]] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in ast.walk(node):
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id in FSM_STATUS_FIELDS:
                    if _is_fsm_field_call(item.value):
                        self.fsm_classes.add(node.name)
                        self.fsm_fields_by_class.setdefault(target.id, set()).add(node.name)
        self.generic_visit(node)


def _is_fsm_field_call(node: ast.expr) -> bool:
    """Check if an AST node is an FSMField(...) or FSMIntegerField(...) call."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in ("FSMField", "FSMIntegerField")
    if isinstance(func, ast.Attribute):
        return func.attr in ("FSMField", "FSMIntegerField")
    return False


def detect_fsm_classes(content: str) -> _FSMModelDetector:
    """Parse Python source and detect FSM-protected model classes."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _FSMModelDetector()
    detector = _FSMModelDetector()
    detector.visit(tree)
    return detector


# Cache of model files -> FSM class names, built per scan
_fsm_class_cache: dict[str, set[str]] = {}


def _build_fsm_class_cache(root: Path) -> None:
    """Scan all model files under root to build the FSM class cache."""
    _fsm_class_cache.clear()
    for py_file in root.rglob("*models*.py"):
        str_path = str(py_file)
        if any(skip in str_path for skip in ["/migrations/", "/__pycache__/", ".venv", "/tests/"]):
            continue
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        detector = detect_fsm_classes(content)
        if detector.fsm_classes:
            _fsm_class_cache[str_path] = detector.fsm_classes


def _is_model_file_with_fsm(path: str) -> bool | None:
    """Check if a model file contains FSM classes.

    Returns:
        True  — model file with FSM classes (should be checked)
        False — model file WITHOUT FSM classes (skip checks 1-3)
        None  — not a model file (use app-level scoping instead)
    """
    basename = Path(path).name
    if "model" not in basename:
        return None  # Not a model file — fall through to app-level scoping
    return path in _fsm_class_cache


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_test_file(path: str) -> bool:
    """Check if path is a test file."""
    return any(p in path for p in TEST_PATH_PATTERNS)


def _is_fsm_app_file(path: str) -> bool:
    """Check if path belongs to an app with FSM-protected models."""
    return any(app in path for app in FSM_APPS)


def _should_check_status_patterns(path: str) -> bool:
    """Determine if a file should be checked for status assignment patterns.

    Uses a two-tier strategy:
    1. Model files: AST-based detection (auto-detects FSMField in class bodies)
    2. Non-model files: app-level scoping (FSM_APPS whitelist)

    This eliminates the need for a manually-curated NON_FSM_STATUS_FILES list.
    """
    if _is_test_file(path):
        return False

    # Tier 1: Model files — use AST detection
    model_check = _is_model_file_with_fsm(path)
    if model_check is not None:
        return model_check

    # Tier 2: Non-model files — use app-level scoping + service exclusion
    if not _is_fsm_app_file(path):
        return False
    return not any(path.endswith(f) for f in NON_FSM_SERVICE_FILES)


def _is_in_transition_method(lines: list[str], line_idx: int) -> bool:
    """Check if the given line is inside an @transition-decorated method."""
    for i in range(line_idx - 1, max(line_idx - 20, -1), -1):
        stripped = lines[i].strip()
        if stripped.startswith("@transition("):
            return True
        if stripped.startswith("def ") and not stripped.startswith("@"):
            break
        if stripped.startswith("class "):
            break
    return False


def _has_fsm_bypass_comment(line: str) -> bool:
    """Check if line has an explicit fsm-bypass comment."""
    return "# fsm-bypass:" in line


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_direct_status_assignment(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 1: No direct .status = in app code (FSM-relevant files only)."""
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    for field_name in FSM_STATUS_FIELDS:
        pattern = re.compile(rf"\.{field_name}\s*=\s*[\"']")
        for i, line in enumerate(lines):
            if pattern.search(line) and not _has_fsm_bypass_comment(line):
                # Allow inside @transition methods (they set the field via descriptor)
                if _is_in_transition_method(lines, i):
                    continue
                # Allow in refresh_from_db overrides
                if REFRESH_OVERRIDE_PATTERN.search(repr(lines[max(0, i - 10) : i + 1])):
                    continue
                result.violations.append(
                    Violation(
                        file=str_path,
                        line=i + 1,
                        check="direct-assignment",
                        message=f"Direct .{field_name} = assignment. Use FSM transition method instead.",
                    )
                )


def check_queryset_update(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 2: No QuerySet.update(status=) bypassing model methods (FSM-relevant files only)."""
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    for field_name in FSM_STATUS_FIELDS:
        pattern = re.compile(rf"\.update\([^)]*{field_name}\s*=")
        for i, line in enumerate(lines):
            if pattern.search(line) and not _has_fsm_bypass_comment(line):
                result.violations.append(
                    Violation(
                        file=str_path,
                        line=i + 1,
                        check="queryset-update",
                        message=f"QuerySet.update({field_name}=) bypasses FSM. Use model transition methods.",
                    )
                )


def check_bulk_update(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 3: No bulk_update with status fields (FSM-relevant files only)."""
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    for field_name in FSM_STATUS_FIELDS:
        pattern = re.compile(rf"bulk_update.*[\"']{field_name}[\"']")
        for i, line in enumerate(lines):
            if pattern.search(line) and not _has_fsm_bypass_comment(line):
                result.violations.append(
                    Violation(
                        file=str_path,
                        line=i + 1,
                        check="bulk-update",
                        message=f"bulk_update with '{field_name}' bypasses FSM. Use individual transitions.",
                    )
                )


def check_dict_bypass(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 4: __dict__['status'] only in test helper."""
    str_path = str(path)

    # Allow in designated test helpers
    for allowed in ALLOWED_DICT_BYPASS_PATHS:
        if str_path.endswith(allowed):
            return

    for field_name in FSM_STATUS_FIELDS:
        pattern = re.compile(rf"__dict__\[[\"']{field_name}[\"']\]")
        for i, line in enumerate(lines):
            if pattern.search(line):
                # Allow in refresh_from_db overrides (they pop/restore for FSM compat)
                context = "\n".join(lines[max(0, i - 10) : i + 5])
                if "refresh_from_db" in context:
                    continue
                if not _has_fsm_bypass_comment(line):
                    result.violations.append(
                        Violation(
                            file=str_path,
                            line=i + 1,
                            check="dict-bypass",
                            message=f"__dict__['{field_name}'] bypass. Only allowed in tests/helpers/fsm_helpers.py.",
                        )
                    )


def check_side_effects_in_transition(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 5: No side effects (HTTP/email/Stripe) inside @transition methods."""
    str_path = str(path)
    if _is_test_file(str_path):
        return

    in_transition = False
    transition_indent = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Detect @transition decorator
        if stripped.startswith("@transition("):
            in_transition = True
            continue

        # Detect method def after @transition
        if in_transition and stripped.startswith("def "):
            transition_indent = len(line) - len(line.lstrip())
            continue

        # Exit transition method when indentation returns to class level
        if in_transition and stripped and not stripped.startswith("#"):
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= transition_indent and not line.strip().startswith(")"):
                in_transition = False
                continue

        # Check for side effects inside transition
        if in_transition and stripped:
            for pattern, description in SIDE_EFFECT_PATTERNS:
                if pattern.search(stripped) and not _has_fsm_bypass_comment(line):
                    result.violations.append(
                        Violation(
                            file=str_path,
                            line=i + 1,
                            check="transition-side-effect",
                            message=f"{description} inside @transition method. Move to post_transition signal.",
                            severity="warning",
                        )
                    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_file(path: Path, result: ScanResult) -> None:
    """Run all checks on a single file."""
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return

    lines = content.splitlines()

    check_direct_status_assignment(path, lines, result)
    check_queryset_update(path, lines, result)
    check_bulk_update(path, lines, result)
    check_dict_bypass(path, lines, result)
    check_side_effects_in_transition(path, lines, result)


def scan_directory(root: Path) -> ScanResult:
    """Scan all Python files under the given directory."""
    # Build the FSM class cache from model files before scanning
    _build_fsm_class_cache(root)

    result = ScanResult()

    for py_file in sorted(root.rglob("*.py")):
        # Skip migrations, __pycache__, .venv
        str_path = str(py_file)
        if any(skip in str_path for skip in ["/migrations/", "/__pycache__/", ".venv"]):
            continue
        scan_file(py_file, result)

    return result


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="FSM guardrail lint for PRAHO Platform")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detected FSM classes")
    parser.add_argument("paths", nargs="*", default=["services/platform/apps"], help="Paths to scan")
    args = parser.parse_args()

    all_results = ScanResult()
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            # Single file mode — build cache from parent directory
            _build_fsm_class_cache(path.parent)
            scan_file(path, all_results)
        elif path.is_dir():
            dir_result = scan_directory(path)
            all_results.violations.extend(dir_result.violations)

    if args.verbose:
        print("FSM classes detected via AST analysis:")
        for model_file, classes in sorted(_fsm_class_cache.items()):
            print(f"  {model_file}: {', '.join(sorted(classes))}")
        print()

    if args.json:
        data = [
            {"file": v.file, "line": v.line, "check": v.check, "message": v.message, "severity": v.severity}
            for v in all_results.violations
        ]
        print(json.dumps(data, indent=2))
    elif all_results.violations:
        print(f"FSM Guardrail Lint: {len(all_results.violations)} violation(s) found\n")
        for v in all_results.violations:
            icon = "🔥" if v.severity == "error" else "⚠️"
            print(f"  {icon} {v.file}:{v.line}: [{v.check}] {v.message}")
        print(f"\n❌ {len(all_results.violations)} FSM guardrail violation(s)")
    else:
        print("✅ No FSM guardrail violations found")

    return 1 if any(v.severity == "error" for v in all_results.violations) else 0


if __name__ == "__main__":
    sys.exit(main())
