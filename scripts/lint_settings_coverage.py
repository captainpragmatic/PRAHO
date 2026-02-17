"""
Lint settings coverage — detect orphan settings, unwired constants,
hardcoded candidates, and default-value drift.

Checks:
  1. Orphan Settings (medium)    — keys in DEFAULT_SETTINGS never used in app code or templates
  2. Unwired Constants (low)     — _DEFAULT_* constants not passed to a SettingsService call (AST)
  3. Hardcoded Candidates (info) — module-level MAX_*/DEFAULT_*/etc. in files without
                                   SettingsService imports (informational, won't fail CI)
  4. Default Drift (medium)      — inline fallback value in SettingsService.get_*() disagrees
                                   with the canonical DEFAULT_SETTINGS value (AST-based)

Exit codes:
  0 — clean (or no findings at the active severity)
  1 — findings at or above --fail-on severity

Usage:
  python scripts/lint_settings_coverage.py                       # default (--fail-on medium)
  python scripts/lint_settings_coverage.py --fail-on low         # stricter
  python scripts/lint_settings_coverage.py --json                # machine-readable
  python scripts/lint_settings_coverage.py --allowlist FILE      # custom allowlist
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

# ─── Configuration ────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APPS_DIR = PROJECT_ROOT / "services" / "platform" / "apps"
TEMPLATES_DIR = PROJECT_ROOT / "services" / "platform" / "templates"
SETTINGS_SERVICE_FILE = APPS_DIR / "settings" / "services.py"
SETUP_DEFAULTS_GLOB = "setup_default_settings.py"

DEFAULT_ALLOWLIST = PROJECT_ROOT / "scripts" / "settings_allowlist.txt"

SEVERITY_ORDER = {"medium": 0, "low": 1, "info": 2}

EXCLUDE_DIRS = {
    "__pycache__",
    "migrations",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "staticfiles",
    "htmlcov",
    "node_modules",
}

# Patterns that match module-level constants which could be settings candidates
CANDIDATE_PATTERNS = [
    re.compile(r"^(MAX_\w+)\s*="),
    re.compile(r"^(DEFAULT_\w+)\s*="),
    re.compile(r"^(\w+_THRESHOLD)\s*="),
    re.compile(r"^(\w+_LIMIT)\s*="),
    re.compile(r"^(\w+_TIMEOUT\w*)\s*="),
    re.compile(r"^(\w+_RATE_\w+)\s*="),
]

# SettingsService accessor method names
SETTINGS_GETTER_METHODS = {
    "get_setting",
    "get_integer_setting",
    "get_boolean_setting",
    "get_decimal_setting",
    "get_list_setting",
}

# _DEFAULT_* pattern for Check 2
DEFAULT_CONST_PATTERN = re.compile(r"^(_DEFAULT_\w+)\s*=")


# ─── Finding ──────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    check: str
    name: str
    message: str


# ─── Allowlist loading ────────────────────────────────────────────────────────


def load_allowlist(path: Path) -> tuple[set[str], set[str]]:
    """Load allowlisted entries from file (one per line, # comments).

    Returns:
        (constant_names, orphan_setting_keys) — two separate sets.
        Lines containing a dot (e.g. "billing.negative_balance_threshold")
        are treated as known-orphan setting keys; everything else as constants.
    """
    constants: set[str] = set()
    orphan_keys: set[str] = set()
    if not path.exists():
        return constants, orphan_keys
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Support "file:CONSTANT" or bare "CONSTANT" formats
        if ":" in line:
            line = line.split(":", 1)[1].strip()
        # Dot → setting key (orphan allowlist); no dot → constant name
        if "." in line:
            orphan_keys.add(line)
        else:
            constants.add(line)
    return constants, orphan_keys


# ─── AST-based DEFAULT_SETTINGS extraction ────────────────────────────────────


def extract_default_settings(services_file: Path) -> dict[str, Any]:
    """Parse DEFAULT_SETTINGS dict from services.py using AST.

    Returns dict mapping setting keys to their default values.
    """
    defaults: dict[str, Any] = {}
    if not services_file.exists():
        return defaults

    source = services_file.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(services_file))
    except SyntaxError:
        return defaults

    for node in ast.walk(tree):
        # Find: DEFAULT_SETTINGS: ClassVar[...] = { ... }
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue

        # Get the target name
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value_node = node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            value_node = node.value
        else:
            continue

        if target_name != "DEFAULT_SETTINGS" or not isinstance(value_node, ast.Dict):
            continue

        for key_node, val_node in zip(value_node.keys, value_node.values, strict=False):
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                defaults[key_node.value] = _ast_const_to_python(val_node)

    return defaults


def _ast_const_to_python(node: ast.expr) -> Any:
    """Convert an AST constant/literal node to a Python value."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_ast_const_to_python(elt) for elt in node.elts]
    if isinstance(node, ast.Dict):
        return {
            _ast_const_to_python(k): _ast_const_to_python(v)
            for k, v in zip(node.keys, node.values, strict=False)
            if k is not None
        }
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        val = _ast_const_to_python(node.operand)
        if isinstance(val, int | float):
            return -val
    return None  # Cannot resolve


# ─── File iteration ──────────────────────────────────────────────────────────


def iter_python_files(root: Path) -> list[Path]:
    """Walk root for .py files, skipping excluded dirs."""
    files: list[Path] = []
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for filename in filenames:
            if filename.endswith(".py"):
                files.append(Path(current_root) / filename)
    return sorted(files)


def iter_template_files(root: Path) -> list[Path]:
    """Walk root for .html template files."""
    files: list[Path] = []
    if not root.exists():
        return files
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in filenames:
            if filename.endswith(".html"):
                files.append(Path(current_root) / filename)
    return sorted(files)


# ─── AST visitor: extract SettingsService call-sites ─────────────────────────


@dataclass
class SettingsCallSite:
    """A SettingsService.get_*() call found in source code."""

    key: str  # the setting key string, e.g. "billing.efactura_batch_size"
    fallback_value: Any  # the default/fallback argument (Python value or sentinel)
    fallback_is_name: bool  # True if fallback is a variable name (can't compare numerically)
    fallback_name: str  # the variable name if fallback_is_name, else ""
    line: int
    file: str


_UNRESOLVED = object()  # sentinel for values we can't statically resolve


class SettingsCallVisitor(ast.NodeVisitor):
    """Walk an AST and collect all SettingsService.get_*_setting() call sites."""

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.calls: list[SettingsCallSite] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_settings_call(node)
        self.generic_visit(node)

    def _check_settings_call(self, node: ast.Call) -> None:
        # Match: SettingsService.get_*_setting("key", default)
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in SETTINGS_GETTER_METHODS:
            return
        # Check it's on SettingsService (could be cls or direct)
        if isinstance(func.value, ast.Name) and func.value.id not in ("SettingsService", "cls"):
            return

        # Extract the key argument (first positional or 'key' keyword)
        key_value: str | None = None
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            key_value = node.args[0].value
        else:
            for kw in node.keywords:
                if kw.arg == "key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    key_value = kw.value.value
                    break
        if not key_value:
            return

        # Extract the fallback/default argument (second positional or 'default' keyword)
        fallback_node: ast.expr | None = None
        if len(node.args) >= 2:
            fallback_node = node.args[1]
        else:
            for kw in node.keywords:
                if kw.arg == "default" and fallback_node is None:
                    fallback_node = kw.value
                    break

        fallback_value: Any = _UNRESOLVED
        fallback_is_name = False
        fallback_name = ""

        if fallback_node is not None:
            if isinstance(fallback_node, ast.Name):
                fallback_is_name = True
                fallback_name = fallback_node.id
            else:
                resolved = _ast_const_to_python(fallback_node)
                if resolved is not None:
                    fallback_value = resolved

        self.calls.append(
            SettingsCallSite(
                key=key_value,
                fallback_value=fallback_value,
                fallback_is_name=fallback_is_name,
                fallback_name=fallback_name,
                line=node.lineno,
                file=str(self.filepath.relative_to(PROJECT_ROOT)),
            )
        )


def collect_settings_calls(app_files: list[Path]) -> list[SettingsCallSite]:
    """Parse all Python files and return SettingsService call sites."""
    all_calls: list[SettingsCallSite] = []
    for filepath in app_files:
        try:
            source = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "SettingsService" not in source:
            continue
        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            continue
        visitor = SettingsCallVisitor(filepath)
        visitor.visit(tree)
        all_calls.extend(visitor.calls)
    return all_calls


# ─── Check 1: Orphan Settings ────────────────────────────────────────────────


def check_orphan_settings(
    defaults: dict[str, Any],
    app_files: list[Path],
    template_files: list[Path],
    services_file: Path,
    known_orphans: set[str],
    call_sites: list[SettingsCallSite],
) -> list[Finding]:
    """Find DEFAULT_SETTINGS keys never referenced in app code or templates."""
    findings: list[Finding] = []

    # Keys actually used in SettingsService calls
    used_keys = {c.key for c in call_sites}

    # Build corpus from non-infrastructure files for substring fallback
    skip_files = {services_file.resolve()}
    for f in app_files:
        if f.name == SETUP_DEFAULTS_GLOB:
            skip_files.add(f.resolve())

    corpus_parts: list[str] = []
    for f in app_files:
        if f.resolve() in skip_files:
            continue
        try:
            corpus_parts.append(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue

    # Also include template content (settings used in Django templates)
    for f in template_files:
        try:
            corpus_parts.append(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue

    corpus = "\n".join(corpus_parts)

    for key in sorted(defaults):
        if key in known_orphans:
            continue
        # Primary check: is this key in any SettingsService call?
        if key in used_keys:
            continue
        # Fallback: exact quoted-string search in corpus (catches template TODOs, comments, etc.)
        # Use quoted form to avoid substring matches like "billing.vat_rate" inside "billing.vat_rate_effective"
        if f'"{key}"' in corpus or f"'{key}'" in corpus:
            continue
        # Also check unquoted (template references like company.email_dpo)
        if key in corpus:
            continue
        findings.append(
            Finding(
                file=str(services_file.relative_to(PROJECT_ROOT)),
                line=0,
                severity="medium",
                check="orphan-setting",
                name=key,
                message=f'Setting "{key}" is defined in DEFAULT_SETTINGS but never referenced in app code or templates.',
            )
        )

    return findings


# ─── Check 2: Unwired Constants (AST-based) ──────────────────────────────────


def check_unwired_constants(
    app_files: list[Path],
    allowlist: set[str],
    call_sites: list[SettingsCallSite],
) -> list[Finding]:
    """Find _DEFAULT_* constants not passed to any SettingsService call in the same file."""
    findings: list[Finding] = []

    # Build per-file index of fallback variable names used in SettingsService calls
    fallback_names_by_file: dict[str, set[str]] = {}
    for call in call_sites:
        if call.fallback_is_name:
            fallback_names_by_file.setdefault(call.file, set()).add(call.fallback_name)

    for filepath in app_files:
        rel = filepath.relative_to(PROJECT_ROOT)
        rel_str = str(rel)

        # Skip test files and settings service itself
        if "/tests/" in rel_str:
            continue
        if filepath.name == "services.py" and "settings" in rel_str:
            continue

        try:
            content = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        lines = content.splitlines()
        file_fallback_names = fallback_names_by_file.get(rel_str, set())

        for i, line in enumerate(lines, start=1):
            match = DEFAULT_CONST_PATTERN.match(line)
            if not match:
                continue

            const_name = match.group(1)
            if const_name in allowlist:
                continue

            # AST-verified: is this constant name used as a fallback in a SettingsService call?
            if const_name in file_fallback_names:
                continue

            findings.append(
                Finding(
                    file=rel_str,
                    line=i,
                    severity="low",
                    check="unwired-constant",
                    name=const_name,
                    message=f"Constant {const_name} is not passed as a fallback to any SettingsService call in this file.",
                )
            )

    return findings


# ─── Check 3: Hardcoded Candidates ───────────────────────────────────────────


def check_hardcoded_candidates(app_files: list[Path], allowlist: set[str]) -> list[Finding]:
    """Find module-level constants that could be settings candidates."""
    findings: list[Finding] = []

    for filepath in app_files:
        rel = filepath.relative_to(PROJECT_ROOT)
        rel_str = str(rel)

        # Skip test files, migrations, and settings infrastructure
        if "/tests/" in rel_str or "/migrations/" in rel_str:
            continue
        if filepath.name == "services.py" and "settings" in rel_str:
            continue
        if filepath.name == SETUP_DEFAULTS_GLOB:
            continue

        try:
            content = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Skip files that already import SettingsService
        if "SettingsService" in content:
            continue

        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            for pattern in CANDIDATE_PATTERNS:
                match = pattern.match(line)
                if not match:
                    continue

                const_name = match.group(1)

                # Skip private _DEFAULT_* (handled by Check 2)
                if const_name.startswith("_DEFAULT_"):
                    continue

                if const_name in allowlist:
                    continue

                findings.append(
                    Finding(
                        file=rel_str,
                        line=i,
                        severity="info",
                        check="hardcoded-candidate",
                        name=const_name,
                        message=f"Constant {const_name} could be a SettingsService candidate.",
                    )
                )
                break  # One finding per line

    return findings


# ─── Check 4: Default Value Drift ────────────────────────────────────────────


def _normalize_for_comparison(value: Any) -> Any:
    """Normalize a value for drift comparison (handle int/float/str coercions)."""
    if isinstance(value, float) and value == int(value):
        return int(value)
    return value


def check_default_drift(
    defaults: dict[str, Any],
    call_sites: list[SettingsCallSite],
) -> list[Finding]:
    """Detect when an inline fallback disagrees with DEFAULT_SETTINGS.

    Example: DEFAULT_SETTINGS has "billing.efactura_batch_size": 100
    but a call site uses SettingsService.get_integer_setting("billing.efactura_batch_size", 50).
    The fallback values are inconsistent — a real bug class.
    """
    findings: list[Finding] = []

    for call in call_sites:
        # Skip calls where we couldn't resolve the fallback
        if call.fallback_is_name or call.fallback_value is _UNRESOLVED:
            continue
        # Skip keys not in DEFAULT_SETTINGS (custom/dynamic keys)
        if call.key not in defaults:
            continue

        canonical = defaults[call.key]
        inline = call.fallback_value

        # Normalize for comparison
        canonical_norm = _normalize_for_comparison(canonical)
        inline_norm = _normalize_for_comparison(inline)

        # String representation comparison for Decimal-like values
        if str(canonical_norm) == str(inline_norm):
            continue
        # Direct equality
        if canonical_norm == inline_norm:
            continue

        findings.append(
            Finding(
                file=call.file,
                line=call.line,
                severity="medium",
                check="default-drift",
                name=call.key,
                message=(
                    f"Inline fallback {inline!r} disagrees with DEFAULT_SETTINGS value {canonical!r} "
                    f'for key "{call.key}". Update one to match the other.'
                ),
            )
        )

    return findings


# ─── Output formatters ───────────────────────────────────────────────────────

SEVERITY_ICONS = {"medium": "📋", "low": "ℹ️", "info": "💡"}


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No settings coverage issues found."

    parts: list[str] = []
    parts.append(f"Found {len(findings)} settings coverage finding(s):\n")

    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check, []).append(f)

    for check_name, check_findings in by_check.items():
        parts.append(f"\n  [{check_name}] ({len(check_findings)} finding(s))")
        for f in check_findings:
            icon = SEVERITY_ICONS.get(f.severity, "?")
            loc = f"{f.file}:{f.line}" if f.line else f.file
            parts.append(f"    {icon} [{f.severity.upper()}] {loc} — {f.name}")
            parts.append(f"       {f.message}")

    # Summary
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    parts.append("\n  Summary:")
    for sev in ["medium", "low", "info"]:
        count = by_severity.get(sev, 0)
        if count:
            parts.append(f"    {SEVERITY_ICONS[sev]} {sev.upper()}: {count}")

    return "\n".join(parts)


def format_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "total": len(findings),
            "findings": [asdict(f) for f in findings],
        },
        indent=2,
    )


# ─── Main ────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lint settings coverage: orphans, unwired constants, hardcoded candidates, default drift.",
    )
    parser.add_argument("--json", action="store_true", help="JSON output for CI")
    parser.add_argument(
        "--fail-on",
        choices=["medium", "low", "info", "none"],
        default="medium",
        help="Minimum severity to fail on (default: medium)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
        help="Path to allowlist file (default: scripts/settings_allowlist.txt)",
    )
    args = parser.parse_args()

    # Load allowlist (constants for Check 2/3, orphan keys for Check 1)
    allowlist, known_orphans = load_allowlist(args.allowlist)

    # AST-parse DEFAULT_SETTINGS (keys + values)
    defaults = extract_default_settings(SETTINGS_SERVICE_FILE)
    if not defaults:
        print("WARNING: Could not extract DEFAULT_SETTINGS from services.py")
        return 1

    # Collect all Python files in apps/
    app_files = iter_python_files(APPS_DIR)

    # Collect all template files
    template_files = iter_template_files(TEMPLATES_DIR)

    # AST-parse all SettingsService call sites (used by Checks 1, 2, 4)
    call_sites = collect_settings_calls(app_files)

    # Run all four checks
    all_findings: list[Finding] = []
    all_findings.extend(
        check_orphan_settings(defaults, app_files, template_files, SETTINGS_SERVICE_FILE, known_orphans, call_sites)
    )
    all_findings.extend(check_unwired_constants(app_files, allowlist, call_sites))
    all_findings.extend(check_hardcoded_candidates(app_files, allowlist))
    all_findings.extend(check_default_drift(defaults, call_sites))

    # Sort by severity, then file, then line
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))

    # Output
    if args.json:
        print(format_json(all_findings))
    else:
        print(format_text(all_findings))

    # Exit code
    if args.fail_on == "none":
        return 0

    cutoff = {
        "medium": {"medium"},
        "low": {"medium", "low"},
        "info": {"medium", "low", "info"},
    }
    active = cutoff.get(args.fail_on, {"medium"})

    has_failures = any(f.severity in active for f in all_findings)
    if has_failures:
        if not args.json:
            print(f"\n❌ Settings coverage lint failed (threshold: {args.fail_on})")
        return 1

    if not args.json:
        if all_findings:
            print(f"\n⚠️  {len(all_findings)} finding(s) below threshold — review recommended")
        else:
            print("\n✅ No settings coverage issues found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
