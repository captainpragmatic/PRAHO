"""
FSM guardrail lint script for PRAHO Platform.

Detects bypass patterns that circumvent django-fsm-2 FSMField(protected=True).
Part of the defense-in-depth strategy from ADR-0034.

Uses a hybrid approach:
- AST analysis on model files to auto-detect which classes use FSMField
- App-level scoping for service/view files (cannot resolve cross-file instance types)
- Inline `# fsm-bypass:` comments for one-off suppressions

Checks:
1. No direct .status = in app code (must use @transition methods) — catches variable AND literal assignments
2. No QuerySet.update(status=) bypassing model methods
3. No bulk_update with status fields
4. No __dict__['status'] outside test helpers
5. No side effects (HTTP/email) inside @transition methods
6. No objects.create(status="non-default") bypassing FSM lifecycle
7. No datetime.now() in production code (use timezone.now())
8. FSM transition calls must be followed by .save() within 20 lines

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
        "apps/customers",
        "apps/promotions",
    }
)

# Non-model files within FSM apps that exclusively touch non-FSM models.
# Model files are auto-detected via AST (no manual exclusion needed).
# This list is only for service/view/task files that work with non-FSM models
# like VirtualminTask, PaymentRetryAttempt, CollectionRun, UsageAggregation, etc.
NON_FSM_SERVICE_FILES = frozenset(
    {
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
    """Check if the given line is inside an @transition-decorated method.

    Scans backwards from line_idx looking for the enclosing def, then
    continues scanning past it to find @transition among its decorators.
    Handles stacked decorators (e.g. @transition + @audit_log + def).
    """
    found_def = False
    for i in range(line_idx - 1, max(line_idx - 30, -1), -1):
        stripped = lines[i].strip()
        if stripped.startswith("@transition("):
            return True
        if stripped.startswith("class "):
            break
        if stripped.startswith("def "):
            # Found the enclosing def — keep scanning upward for its decorators
            found_def = True
            continue
        if found_def and not stripped.startswith("@") and stripped != "":
            # Hit a non-decorator, non-blank line above the def — stop
            break
    return False


def _has_fsm_bypass_comment(line: str) -> bool:
    """Check if line has an explicit fsm-bypass comment."""
    return "# fsm-bypass:" in line


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_direct_status_assignment(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 1: No direct .status = in app code (FSM-relevant files only).

    Catches both literal and variable assignments:
      .status = "active"        (literal)
      .status = new_status      (variable)
      .status = SomeEnum.VALUE  (enum)

    Excludes:
      .status == "active"       (comparison)
      .status += ...            (augmented — unlikely but safe)
      status = FSMField(...)    (field definition)
      status = models.CharField (non-FSM field definition)
    """
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    for field_name in FSM_STATUS_FIELDS:
        # Match .status = <anything> but NOT == (comparison) or FSMField/models.* (definition)
        pattern = re.compile(rf"\.{field_name}\s*=\s*(?!=)")
        # Exclusion patterns for field definitions (class-level, not instance assignment)
        definition_pattern = re.compile(rf"^\s+{field_name}\s*=\s*(FSMField|models\.)")
        for i, line in enumerate(lines):
            if not pattern.search(line) or _has_fsm_bypass_comment(line):
                continue
            # Skip field definitions (class body: `status = FSMField(...)`)
            if definition_pattern.search(line):
                continue
            # Allow inside @transition methods (they set the field via descriptor)
            if _is_in_transition_method(lines, i):
                continue
            # Allow in refresh_from_db overrides
            if REFRESH_OVERRIDE_PATTERN.search("\n".join(lines[max(0, i - 10) : i + 1])):
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
    """Check 2: No QuerySet.update(status=) bypassing model methods (FSM-relevant files only).

    Handles both single-line and multi-line .update() calls by joining
    continuation lines when an unclosed paren is detected.
    """
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    # Also detect setattr(obj, 'status', value) bypass pattern
    for field_name in FSM_STATUS_FIELDS:
        setattr_pattern = re.compile(rf"setattr\([^,]+,\s*[\"']{field_name}[\"']")
        for i, line in enumerate(lines):
            if setattr_pattern.search(line) and not _has_fsm_bypass_comment(line):
                result.violations.append(
                    Violation(
                        file=str_path,
                        line=i + 1,
                        check="setattr-bypass",
                        message=f"setattr(..., '{field_name}', ...) bypasses FSM. Use transition methods.",
                    )
                )

    for field_name in FSM_STATUS_FIELDS:
        pattern = re.compile(rf"\.update\([^)]*{field_name}\s*=")
        for i, line in enumerate(lines):
            # Single-line match
            if pattern.search(line) and not _has_fsm_bypass_comment(line):
                result.violations.append(
                    Violation(
                        file=str_path,
                        line=i + 1,
                        check="queryset-update",
                        message=f"QuerySet.update({field_name}=) bypasses FSM. Use model transition methods.",
                    )
                )
                continue
            # Multi-line: if line has .update( with unclosed paren, join next lines.
            # The `.update(` line may have a trailing comment (e.g. `# fsm-bypass:`),
            # so strip comments before checking for unclosed paren.
            code_part = line.split("#")[0].rstrip()
            if ".update(" in line and code_part.endswith(("(", ",")):
                if _has_fsm_bypass_comment(line):
                    continue
                joined = line
                for j in range(i + 1, min(i + 10, len(lines))):
                    joined += " " + lines[j].strip()
                    if ")" in lines[j]:
                        break
                if pattern.search(joined) and not _has_fsm_bypass_comment(joined):
                    result.violations.append(
                        Violation(
                            file=str_path,
                            line=i + 1,
                            check="queryset-update",
                            message=f"QuerySet.update({field_name}=) bypasses FSM (multi-line). Use transition methods.",
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


def check_create_with_status(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 6: No objects.create(status=...) bypassing FSM lifecycle.

    Django Model.__init__ accepts any status kwarg, completely bypassing FSM
    protected field guards. Invoices born as 'issued' skip the draft→issued
    transition and any side effects (locked_at, issued_at, audit logging).

    Catches:
      Invoice.objects.create(status="issued")
      Model.objects.get_or_create(..., defaults={"status": "active"})
      Model.objects.update_or_create(..., defaults={"status": "active"})

    Allows:
      - Default status values (status="draft", status="pending", status="prospect", etc.)
      - Test files (already excluded by _should_check_status_patterns)
    """
    str_path = str(path)
    if not _should_check_status_patterns(str_path):
        return

    # Default/initial statuses that are safe to use in create() (match model defaults)
    safe_initial_statuses = frozenset(
        {
            "draft",
            "pending",
            "prospect",
            "upcoming",
            "accumulating",
            "new",
            "open",
        }
    )

    for field_name in FSM_STATUS_FIELDS:
        # Match create/get_or_create/update_or_create with status kwarg
        create_pattern = re.compile(
            rf"\.(?:create|get_or_create|update_or_create)\([^)]*{field_name}\s*=\s*[\"'](\w+)[\"']"
        )
        # Match defaults dict with status
        defaults_pattern = re.compile(rf"defaults\s*=\s*\{{[^}}]*[\"']{field_name}[\"']\s*:\s*[\"'](\w+)[\"']")
        for i, line in enumerate(lines):
            if _has_fsm_bypass_comment(line):
                continue
            for pat in (create_pattern, defaults_pattern):
                match = pat.search(line)
                if match:
                    status_value = match.group(1)
                    if status_value not in safe_initial_statuses:
                        result.violations.append(
                            Violation(
                                file=str_path,
                                line=i + 1,
                                check="create-with-status",
                                message=(
                                    f'objects.create({field_name}="{status_value}") bypasses FSM lifecycle. '
                                    f"Create with default status, then call transition method."
                                ),
                                severity="warning",
                            )
                        )


def check_naive_datetime(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 7: No datetime.now() in production code — use timezone.now().

    Django requires timezone-aware datetimes. Using datetime.now() produces
    naive datetimes that cause subtle bugs in USE_TZ=True projects.
    """
    str_path = str(path)
    if _is_test_file(str_path):
        return

    pattern = re.compile(r"\bdatetime\.now\(\)")
    for i, line in enumerate(lines):
        if pattern.search(line) and not _has_fsm_bypass_comment(line):
            result.violations.append(
                Violation(
                    file=str_path,
                    line=i + 1,
                    check="naive-datetime",
                    message="datetime.now() produces naive datetime. Use django.utils.timezone.now() instead.",
                    severity="warning",
                )
            )


def check_transition_without_save(path: Path, lines: list[str], result: ScanResult) -> None:
    """Check 8: FSM transition calls should be followed by .save().

    django-fsm transitions mutate in-memory state but do NOT auto-save.
    Forgetting .save() means the database is never updated — silent data loss.

    Looks for patterns like:
        obj.activate()
        # ... no obj.save() within next 5 lines

    Only checks in FSM app files (not tests, not models).
    Uses only unambiguous transition names to minimize false positives.
    """
    str_path = str(path)
    if _is_test_file(str_path):
        return
    if not _is_fsm_app_file(str_path):
        return
    # Skip model files — transition methods are defined there, not called
    if "model" in Path(str_path).name:
        return
    # Skip admin files — admin.register() false positive
    if Path(str_path).name == "admin.py":
        return

    # Build set of known transition method names from all FSM models
    known_transitions = _get_known_transition_names()
    if not known_transitions:
        return

    transition_call_pattern = re.compile(rf"(\w+)\.({'|'.join(re.escape(t) for t in known_transitions)})\(")

    # Names that are obviously NOT model instances (classes, modules, services)
    non_instance_prefixes = frozenset(
        {
            "self",
            "cls",
            "admin",
            "executor",
            "gateway",
            "RefundService",
            "ServiceManagementService",
            "IdempotencyManager",
            "AuditService",
        }
    )

    for i, line in enumerate(lines):
        match = transition_call_pattern.search(line.strip())
        if not match or _has_fsm_bypass_comment(line):
            continue

        obj_name = match.group(1)
        method_name = match.group(2)

        # Skip non-instance callers (classes, modules, self.*)
        if obj_name in non_instance_prefixes:
            continue
        # Skip if caller is PascalCase (class name, not instance)
        if obj_name[0].isupper():
            continue

        # Check if .save() appears within the next 20 lines for the same object
        save_found = False
        for j in range(i + 1, min(i + 21, len(lines))):
            if f"{obj_name}.save(" in lines[j]:
                save_found = True
                break
            # Also accept return/raise (control flow exits before save needed here)
            stripped_next = lines[j].strip()
            if stripped_next.startswith(("return ", "raise ", "except ", "finally:")):
                save_found = True  # Different control flow — don't flag
                break

        if not save_found:
            result.violations.append(
                Violation(
                    file=str_path,
                    line=i + 1,
                    check="transition-no-save",
                    message=(
                        f"{obj_name}.{method_name}() — no .save() within 20 lines. FSM transitions don't auto-save."
                    ),
                    severity="warning",
                )
            )


def _get_known_transition_names() -> frozenset[str]:
    """Return all known FSM transition method names across the codebase.

    Built from AST cache. Falls back to a hardcoded set if cache is empty
    (e.g., when scanning a single file).
    """
    # Only UNAMBIGUOUS transition names — names that are unlikely to collide
    # with non-FSM methods (e.g., `register()` and `close()` are too common).
    # Kept in sync with @transition methods across models.
    known_transitions = frozenset(
        {
            # Order
            "confirm",
            "start_processing",
            "refund_order",
            "start_provisioning",
            "complete_provisioning",
            # Invoice
            "mark_as_paid",
            "mark_overdue",
            "refund_invoice",
            "mark_partially_refunded",
            # Payment
            "succeed",
            "fail_payment",
            "refund_payment",
            "partially_refund",
            "complete_refund",
            "dispute_payment",
            "cancel_payment",
            # Subscription
            "activate",
            "cancel_subscription",
            "mark_past_due",
            # Service
            "suspend",
            "terminate",
            "decommission",
            # Domain
            "transfer_in",
            "expire_domain",
            "delete_domain",
            # Ticket
            "start_work",
            "wait_on_customer",
            "reopen",
            # EFactura
            "mark_queued",
            "mark_submitted",
            "mark_processing",
            "mark_accepted",
            "mark_rejected",
            "mark_error",
            # BillingCycle
            "start_closing",
            "mark_invoiced",
            "finalize",
            # UsageAggregation
            "close_for_rating",
            # Customer
            "deactivate",
            "reactivate",
            "unsuspend",
            # Proforma
            "send_proforma",
            "accept_proforma",
            "reject_proforma",
            "expire_proforma",
            # Refund
            "process_refund",
            "complete_refund_processing",
            "reject_refund",
            # OrderItem
            "start_item_provisioning",
            "complete_item_provisioning",
            "fail_item_provisioning",
        }
    )
    return known_transitions


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
    check_create_with_status(path, lines, result)
    check_naive_datetime(path, lines, result)
    check_transition_without_save(path, lines, result)


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

    # Checks that should block commits (errors + critical warnings)
    blocking_checks = {
        "direct-assignment",
        "queryset-update",
        "bulk-update",
        "dict-bypass",
        "setattr-bypass",
        "create-with-status",
        "transition-no-save",
    }

    if args.json:
        data = [
            {"file": v.file, "line": v.line, "check": v.check, "message": v.message, "severity": v.severity}
            for v in all_results.violations
        ]
        print(json.dumps(data, indent=2))
    elif all_results.violations:
        errors = [v for v in all_results.violations if v.check in blocking_checks]
        warnings = [v for v in all_results.violations if v.check not in blocking_checks]
        print(f"FSM Guardrail Lint: {len(all_results.violations)} violation(s) found\n")
        for v in all_results.violations:
            icon = "🔥" if v.check in blocking_checks else "⚠️"
            print(f"  {icon} {v.file}:{v.line}: [{v.check}] {v.message}")
        if errors:
            print(f"\n❌ {len(errors)} blocking violation(s), {len(warnings)} warning(s)")
        else:
            print(f"\n⚠️ {len(warnings)} warning(s) (non-blocking)")
    else:
        print("✅ No FSM guardrail violations found")

    has_blocking = any(v.check in blocking_checks for v in all_results.violations)
    return 1 if has_blocking else 0


if __name__ == "__main__":
    sys.exit(main())
