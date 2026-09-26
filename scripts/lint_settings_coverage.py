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
  5. Untested Effect (medium)    — a key that was effect-tested no longer is. Checks 1-4 are all
                                   about wiring; this one asks whether anything asserts the
                                   setting's CONSEQUENCE. Ratchets against a recorded baseline.
  6. Inert Setting (medium)      — a key whose only reader is a function nothing calls. Editable
                                   in the UI, no effect anywhere. Check 1 passes on these because
                                   the key IS referenced — inside the dead getter.

Exit codes:
  0 — clean (or no findings at the active severity)
  1 — findings at or above --fail-on severity

Usage:
  python scripts/lint_settings_coverage.py                       # default (--fail-on medium)
  python scripts/lint_settings_coverage.py --fail-on low         # stricter
  python scripts/lint_settings_coverage.py --json                # machine-readable
  python scripts/lint_settings_coverage.py --allowlist FILE      # custom allowlist
  python scripts/lint_settings_coverage.py --effect-baseline F   # custom effect baseline
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path
from typing import Any

# ─── Configuration ────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APPS_DIR = PROJECT_ROOT / "services" / "platform" / "apps"
TEMPLATES_DIR = PROJECT_ROOT / "services" / "platform" / "templates"
SETTINGS_SERVICE_FILE = APPS_DIR / "settings" / "services.py"
CATALOG_FILE = APPS_DIR / "settings" / "catalog.py"

# Shared tokenize-based extraction (same module the consumer-contract test uses)
sys.path.insert(0, str(PROJECT_ROOT / "services" / "platform"))
from apps.settings.key_scan import extract_catalog_defaults, extract_string_literals

SETUP_DEFAULTS_GLOB = "setup_default_settings.py"

DEFAULT_ALLOWLIST = PROJECT_ROOT / "scripts" / "settings_allowlist.txt"
PLATFORM_TESTS_DIR = PROJECT_ROOT / "services" / "platform" / "tests"
DEFAULT_EFFECT_BASELINE = PROJECT_ROOT / "scripts" / "settings_effect_baseline.txt"
DEFAULT_INERT_BASELINE = PROJECT_ROOT / "scripts" / "settings_inert_baseline.txt"
PLATFORM_DIR = PROJECT_ROOT / "services" / "platform"

# The two SettingsService methods that actually persist a value; helpers forwarding to either
# count as writers too (see `_write_helper_names`).
_DIRECT_WRITERS = ("update_setting", "reset_setting_to_default")

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


def extract_catalog_keys(catalog_path: Path) -> set[str]:
    """Every `SettingDef(key=...)` in the catalog, by text rather than import.

    Deliberately no Django: this script runs in the lint phase, before any app is loaded.
    """
    return set(re.findall(r'key="([a-z0-9_.]+)"', catalog_path.read_text()))


def load_key_baseline(path: Path) -> set[str]:
    """One setting key per line, `#` comments ignored. Shared by checks 5 and 6."""
    if not path.exists():
        return set()
    return {
        line.strip() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")
    }


def load_allowlist(path: Path) -> tuple[set[str], set[str]]:
    """Load allowlisted entries from file (one per line, # comments).

    Supports category headers (lines starting with ``# @category``) for
    documentation, but all non-dotted entries are treated as constant names
    regardless of category.

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
    """Setting keys + defaults from the catalog (services.py DEFAULT_SETTINGS derives from it)."""
    del services_file  # signature kept for call-site compatibility
    return extract_catalog_defaults(CATALOG_FILE)


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


def module_literal_constants(tree: ast.Module) -> dict[str, Any]:
    """Module-level `NAME = <literal>` values in ONE file, following one level of aliasing.

    Check 2 tells you to move an inline fallback into a `_DEFAULT_*` constant; check 4 then
    stopped looking, because its fallback was a Name rather than a literal. The two checks
    worked against each other, and 118 of 260 call sites - 45% - were invisible to the drift
    check for following the convention the same script recommends.

    Only names assigned at module level in THIS file are resolved. An imported name, a class
    attribute or a computed expression stays unresolved and is counted as such: a drift list
    that silently drops what it could not resolve repeats the defect it exists to find.
    """
    literals: dict[str, Any] = {}
    aliases: dict[str, str] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(value, ast.Name):
                aliases[target.id] = value.id
            else:
                resolved = _ast_const_to_python(value)
                if resolved is not None:
                    literals[target.id] = resolved
    for name, source in aliases.items():
        if source in literals:
            literals[name] = literals[source]
    return literals


# ─── File iteration ──────────────────────────────────────────────────────────


def iter_python_files(root: Path) -> list[Path]:
    """Walk root for .py files, skipping excluded dirs."""
    files: list[Path] = []
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        files.extend(Path(current_root) / filename for filename in filenames if filename.endswith(".py"))
    return sorted(files)


def iter_template_files(root: Path) -> list[Path]:
    """Walk root for .html template files."""
    files: list[Path] = []
    if not root.exists():
        return files
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        files.extend(Path(current_root) / filename for filename in filenames if filename.endswith(".html"))
    return sorted(files)


# ─── AST visitor: extract SettingsService call-sites ─────────────────────────


@dataclass
class SettingsCallSite:
    """A SettingsService.get_*() call found in source code."""

    key: str  # the setting key string, e.g. "billing.efactura_batch_size"
    fallback_value: Any  # the default/fallback argument (Python value or sentinel)
    fallback_is_name: bool  # True if the fallback was written as a variable name
    fallback_name: str  # the variable name if fallback_is_name, else ""
    line: int
    file: str
    # A named fallback that `module_literal_constants` resolved to a literal in the same file.
    # Distinguishing this from a bare literal keeps the unresolved remainder countable.
    fallback_resolved_from_name: bool = False


_UNRESOLVED = object()  # sentinel for values we can't statically resolve


class SettingsCallVisitor(ast.NodeVisitor):
    """Walk an AST and collect all SettingsService.get_*_setting() call sites."""

    def __init__(self, filepath: Path, module_constants: dict[str, Any] | None = None) -> None:
        self.filepath = filepath
        self.calls: list[SettingsCallSite] = []
        self.module_constants = module_constants or {}

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
        resolved_from_name = False

        if fallback_node is not None:
            if isinstance(fallback_node, ast.Name):
                fallback_is_name = True
                fallback_name = fallback_node.id
                if fallback_name in self.module_constants:
                    fallback_value = self.module_constants[fallback_name]
                    resolved_from_name = True
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
                fallback_resolved_from_name=resolved_from_name,
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
        visitor = SettingsCallVisitor(filepath, module_literal_constants(tree))
        visitor.visit(tree)
        all_calls.extend(visitor.calls)
    return all_calls


# ─── Check 1: Orphan Settings ────────────────────────────────────────────────


def check_orphan_settings(  # noqa: PLR0913  # Aggregates all guardrail inputs
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
    settings_app_dir = (APPS_DIR / "settings").resolve()
    skip_files = {services_file.resolve()}
    for f in app_files:
        if f.name == SETUP_DEFAULTS_GLOB or f.resolve().is_relative_to(settings_app_dir):
            skip_files.add(f.resolve())

    literal_corpus: set[str] = set()
    for f in app_files:
        if f.resolve() in skip_files:
            continue
        literal_corpus |= extract_string_literals(f)

    corpus_parts: list[str] = []

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
        # Python literal corpus (tokenized — a comment mention can never count as usage)
        if key in literal_corpus:
            continue
        # Template corpus (raw text: template tags reference keys unquoted)
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


# ─── Check 3: Hardcoded Candidates (AST-aware semantic classification) ───────


def _classify_constant_value(node: ast.expr, const_name: str) -> str | None:
    """Classify AST value node. Returns skip-reason string or None if tunable."""
    # Hex literals / bitmasks → protocol/bitwise constant
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        # Power of 2 minus 1 (bitmasks: 0xFF, 0xFFFF, 0xFFFFFFFF)
        if node.value > 255 and (node.value & (node.value + 1)) == 0:
            return "bitmask"
    # Constants with VALUE/COUNT/SIZE/LENGTH in name + small-to-medium int → protocol boundary
    boundary_suffixes = ("_VALUE", "_COUNT", "_SIZE", "_LENGTH")
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        if any(const_name.endswith(s) for s in boundary_suffixes):
            return "boundary"
    # frozenset/set/tuple constructors → structural collection
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("frozenset", "set", "tuple"):
            return "collection"
    # Set/Dict/List literals → structural
    if isinstance(node, ast.Set | ast.Dict | ast.List | ast.Tuple):
        return "collection"
    # String values → not a tunable numeric
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "string"
    # Bool values → feature flag (usually structural)
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return "boolean"
    return None


def _is_model_field_default(const_name: str, tree: ast.Module) -> bool:
    """Check if constant is used as default= in a Django model field."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.keyword):
            continue
        if node.arg != "default":
            continue
        if isinstance(node.value, ast.Name) and node.value.id == const_name:
            return True
    return False


def check_hardcoded_candidates(app_files: list[Path], allowlist: set[str]) -> list[Finding]:
    """Find module-level constants that could be settings candidates.

    Uses AST-based semantic classification to auto-skip:
    - Bitmask constants (0xFFFFFFFF, powers-of-2-minus-1)
    - Collection constants (frozenset, set, tuple, list, dict literals)
    - String/boolean constants
    - Constants used as Django model field defaults (default=CONST)
    """
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

        # AST-parse for semantic classification
        try:
            tree = ast.parse(content, filename=str(filepath))
        except SyntaxError:
            continue

        # Build map of module-level constant assignments: name → (line, value_node)
        const_assignments: dict[str, tuple[int, ast.expr]] = {}
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if node.value is not None:
                    const_assignments[name] = (node.lineno, node.value)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                const_assignments[node.target.id] = (node.lineno, node.value)

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

                # ── AST semantic classification ──────────────────────────
                if const_name in const_assignments:
                    _lineno, value_node = const_assignments[const_name]

                    # 1. Value-based classification (hex, collection, string, bool, boundary)
                    skip_reason = _classify_constant_value(value_node, const_name)
                    if skip_reason:
                        continue

                    # 2. Model field default (default=CONST in same file)
                    if _is_model_field_default(const_name, tree):
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
    """Detect when an inline fallback disagrees with the catalog default.

    Example: the catalog has "billing.efactura_batch_size": 100 while a call site passes
    `SettingsService.get_integer_setting("billing.efactura_batch_size", 50)`.

    Reported at LOW, not medium, and the reason is worth stating. Since ADR-0042 made the catalog
    the resolution source, `get_setting` falls back to `DEFAULT_SETTINGS[key]` and only reaches the
    caller's argument for a key the catalog does not declare - so for every catalog key the inline
    fallback is UNREACHABLE. A drift is therefore misinformation rather than misbehaviour: it is
    the number a reader of that module believes, and the number that would become operative if the
    key ever left the catalog. Worth fixing, not worth failing a build over.

    What the drift is genuinely diagnostic OF is check 6: eleven of the twelve drifts this first
    surfaced belong to a getter nothing calls. The two numbers drifted apart precisely because no
    live code path ever made them agree.
    """
    findings: list[Finding] = []

    for call in call_sites:
        # A named fallback resolved to a module-level literal is as comparable as an inline one.
        # Only a genuinely unresolvable fallback is skipped, and `check_unresolved_fallbacks`
        # counts those so the blind spot cannot go quiet again.
        if call.fallback_value is _UNRESOLVED:
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
                severity="low",
                check="default-drift",
                name=call.key,
                message=(
                    f"Inline fallback {inline!r} disagrees with the catalog default {canonical!r} "
                    f'for key "{call.key}". The catalog wins at runtime, so this number is '
                    f"unreachable - and misleading to whoever reads it next. Align it."
                ),
            )
        )

    return findings


# ─── Output formatters ───────────────────────────────────────────────────────

SEVERITY_ICONS = {"medium": "📋", "low": "ℹ️", "info": "💡"}


@cache
def _module_string_constants(text: str) -> dict[str, str]:
    """Module-level `NAME = "literal"` pairs, so a test may name its key once and reuse it.

    Without this the detector silently dictates test style: the first tests written against it
    used `SERIES_KEY = "integrations.smartbill_invoice_series"` and were reported as untested
    while passing, because only the literal at the call site was ever matched. That is the same
    blind spot `key_scan.extract_settings_call_keys` documents, and a measurement that quietly
    under-reports is worse than none.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    return constants


@cache
def _write_helper_names(text: str) -> frozenset[str]:
    """Local functions that forward a key parameter to a real writer.

    Matching only the direct `SettingsService.update_setting("literal")` call is a style rule
    masquerading as a measurement. `tests/settings/test_localisation_consumers.py` drives four
    localisation settings through customer forms, rendered dates and persisted addresses - about
    as thorough an effect test as this repo has - through a two-line `set_value` helper, and the
    detector called all four untested. One level of indirection is where real tests live.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return frozenset()
    helpers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        for call in ast.walk(node):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in _DIRECT_WRITERS
                and call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id in params
            ):
                helpers.add(node.name)
    return frozenset(helpers)


def _writes_this_key(text: str, key: str) -> bool:
    """A write addressed to THIS key, not merely a file that happens to write something."""
    quoted = re.escape(key)
    writers = "|".join(re.escape(name) for name in (*_DIRECT_WRITERS, *_write_helper_names(text)))
    if (
        re.search(rf'({writers})\(\s*["\']{quoted}["\']', text)
        or re.search(rf'["\']{quoted}["\']\s*:', text)
        or re.search(rf'key\s*=\s*["\']{quoted}["\']', text)
    ):
        return True
    aliases = [name for name, value in _module_string_constants(text).items() if value == key]
    return any(
        re.search(rf"({writers})\(\s*{re.escape(alias)}\b", text) or re.search(rf"\b{re.escape(alias)}\s*:", text)
        for alias in aliases
    )


def _reaches_another_app(text: str) -> bool:
    """An effect test observes the change OUTSIDE the settings app; a read-back is not an effect.

    Two shapes qualify. A test that imports another app's code, and a test that requests a page
    through the Django test client - which leaves the settings app by construction, since the
    view, the template and every tag it loads live elsewhere. The second shape was missing, and
    it is the only one available to six of the nine `company.*` keys, whose sole consumer is
    `{% setting %}` in `templates/legal/`: such a test imports nothing from `apps.` at all.
    A request to the settings app's own pages still does not count.
    """
    if any(app != "settings" for app in re.findall(r"from apps\.(\w+)", text)):
        return True
    targets = re.findall(r'client\.(?:get|post|put|patch|delete)\(\s*(?:reverse\(\s*)?["\']([^"\']+)', text)
    return any(not target.lstrip("/").startswith("settings") for target in targets)


def effect_tested_keys(catalog_keys: set[str], test_files: list[Path]) -> set[str]:
    """Keys some test writes and then observes through another app's behaviour.

    This is the shape `tests/settings/test_settings_integration.py` established: set the value,
    call a different app's object, assert what it does. Reading the key back through
    `SettingsService` proves storage, which the other four checks already cover.
    """
    texts = {path: path.read_text(errors="ignore") for path in test_files}
    return {
        key
        for key in catalog_keys
        for path, text in texts.items()
        if key in text and _writes_this_key(text, key) and _reaches_another_app(text)
    }


def check_untested_effects(catalog_keys: set[str], test_files: list[Path], baseline: set[str]) -> list[Finding]:
    """Check 5 — a setting whose EFFECT nothing asserts.

    The other four checks are about wiring: is the key referenced, do the defaults agree, does a
    fallback drift. `system.maintenance_mode` passed every one of them while having no
    customer-facing consequence at all - it was referenced, its default matched, its fallback was
    consistent, and enabling it did nothing a portal customer could see. Wiring is not effect.

    A ratchet, not a cliff. 185 of 262 keys currently have no test that mentions them, and
    demanding 185 tests today would only teach people to bypass the gate. So the baseline records
    the keys that ARE effect-tested, and this fails when one of them stops being - which makes
    progress monotonic and every future effect test permanent.
    """
    tested = effect_tested_keys(catalog_keys, test_files)
    findings: list[Finding] = [
        Finding(
            file=str(DEFAULT_EFFECT_BASELINE.relative_to(PROJECT_ROOT)),
            line=0,
            severity="medium",
            check="untested-effect-regression",
            name=key,
            message=(
                f"'{key}' was effect-tested and no longer is. Restore the test, or remove the key "
                f"from the baseline in the same commit and say why."
            ),
        )
        for key in sorted(baseline - tested)
    ]

    untested = sorted(catalog_keys - tested)
    if untested:
        findings.append(
            Finding(
                file=str(DEFAULT_EFFECT_BASELINE.relative_to(PROJECT_ROOT)),
                line=0,
                severity="info",
                check="untested-effect",
                name=f"{len(untested)}-of-{len(catalog_keys)}",
                message=(
                    f"{len(tested)}/{len(catalog_keys)} settings have an effect test. "
                    f"Add one with any change that touches a setting; the baseline only moves up."
                ),
            )
        )
    return findings


# ─── Check 6: Inert Settings ──────────────────────────────────────────────────


def _settings_readers(files: list[Path]) -> dict[tuple[str, str], set[str]]:
    """Module-level functions that read settings, mapped to the keys each one reads.

    Module level only. A method's call sites resolve through `self`, an instance, or a subclass,
    and guessing at that would manufacture false positives in a check whose whole value is that
    its findings are certain.
    """
    readers: dict[tuple[str, str], set[str]] = {}
    for path in files:
        text = path.read_text(errors="ignore")
        if "SettingsService" not in text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            keys = {
                call.args[0].value
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in SETTINGS_GETTER_METHODS
                and call.args
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)
            }
            if keys:
                readers[(str(path.relative_to(PROJECT_ROOT)), node.name)] = keys
    return readers


def _names_referenced_somewhere(files: list[Path], names: set[str]) -> set[str]:
    """Of `names`, those appearing on any line that is not their own `def`.

    A plain textual sweep on purpose: it counts a decorator, a dict of handlers, an `__all__`, a
    string passed to `import_string` - every indirect route a caller can take. Over-counting is
    the safe direction here, because a name this misses is reported as dead.
    """
    if not names:
        return set()
    patterns = {name: re.compile(rf"\b{re.escape(name)}\b") for name in names}
    definitions = {name: re.compile(rf"\s*(?:async\s+)?def\s+{re.escape(name)}\b") for name in names}
    referenced: set[str] = set()
    for path in files:
        for line in path.read_text(errors="ignore").splitlines():
            for name in names - referenced:
                if patterns[name].search(line) and not definitions[name].match(line):
                    referenced.add(name)
    return referenced


def check_inert_settings(catalog_keys: set[str], files: list[Path], baseline: set[str]) -> list[Finding]:
    """Check 6 — a setting whose only reader is a function nothing calls.

    This is the shape that let `system.maintenance_mode` ship with no effect, and it is not rare.
    The repeated pattern is three lines:

        _DEFAULT_X = 100                                    # what the code enforces
        X = _DEFAULT_X                                      # what live logic actually reads
        def get_x(): return SettingsService.get_integer_setting("app.x", _DEFAULT_X)   # uncalled

    Live code compares against `X`; the getter that would consult the operator's configured value
    is never called. The setting is editable in the UI and provably inert. Check 1 passes on every
    one of them, because the key IS "referenced in app code" - inside the dead getter. That is the
    difference between a key being present and a key having consequences, and 43 of 262 keys were
    on the wrong side of it when this check was written.

    Ratchet, not cliff, and it ratchets in both directions: a NEW inert setting fails at medium,
    and a baseline entry that became live fails at low until it is removed, so the list cannot rot
    into a permanent excuse.
    """
    readers = _settings_readers(files)
    reader_names = {name for _, name in readers}
    referenced = _names_referenced_somewhere(files, reader_names)

    inert_keys: dict[str, str] = {}
    live_keys: set[str] = set()
    for (rel_path, func_name), keys in readers.items():
        for key in keys & catalog_keys:
            if func_name in referenced:
                live_keys.add(key)
            else:
                inert_keys.setdefault(key, f"{rel_path}:{func_name}()")

    # A key read from both a live path and a dead getter is not inert.
    inert_keys = {key: where for key, where in inert_keys.items() if key not in live_keys}

    findings: list[Finding] = [
        Finding(
            file=where.rsplit(":", 1)[0],
            line=0,
            severity="medium",
            check="inert-setting",
            name=key,
            message=(
                f"'{key}' is read only by {where}, which nothing calls. The setting is editable "
                f"and has no effect. Call the getter from the code that enforces the limit, or "
                f"delete the key from the catalog."
            ),
        )
        for key, where in sorted(inert_keys.items())
        if key not in baseline
    ]
    findings.extend(
        Finding(
            file=str(DEFAULT_INERT_BASELINE.relative_to(PROJECT_ROOT)),
            line=0,
            severity="low",
            check="inert-setting-fixed",
            name=key,
            message=f"'{key}' is no longer inert. Remove it from the baseline in the same commit.",
        )
        for key in sorted(baseline - set(inert_keys))
    )
    if inert_keys:
        findings.append(
            Finding(
                file=str(DEFAULT_INERT_BASELINE.relative_to(PROJECT_ROOT)),
                line=0,
                severity="info",
                check="inert-setting",
                name=f"{len(inert_keys)}-of-{len(catalog_keys)}",
                message=(
                    f"{len(inert_keys)}/{len(catalog_keys)} settings are read only from a getter "
                    f"nothing calls. Every one is editable in the UI and inert."
                ),
            )
        )
    return findings


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
    parser.add_argument(
        "--effect-baseline",
        type=Path,
        default=DEFAULT_EFFECT_BASELINE,
        help="Keys known to have an effect test (default: scripts/settings_effect_baseline.txt)",
    )
    parser.add_argument(
        "--inert-baseline",
        type=Path,
        default=DEFAULT_INERT_BASELINE,
        help="Keys known to be read only from an uncalled getter (default: scripts/settings_inert_baseline.txt)",
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
    catalog_keys = set(extract_catalog_keys(CATALOG_FILE))
    all_findings.extend(
        check_untested_effects(
            catalog_keys,
            iter_python_files(PLATFORM_TESTS_DIR),
            load_key_baseline(args.effect_baseline),
        )
    )
    # Check 6 sweeps the whole platform tree, not just apps/: a getter may be called from a
    # management command, a settings module or a test, and any of those makes it live.
    all_findings.extend(
        check_inert_settings(
            catalog_keys,
            iter_python_files(PLATFORM_DIR),
            load_key_baseline(args.inert_baseline),
        )
    )

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
