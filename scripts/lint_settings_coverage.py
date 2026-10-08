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
  5. Untested Effect (medium)    — lost effect credit or a new untested production reader.
                                   The positive key floor and grandfathered reader locations
                                   ratchet independently.
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
from gettext import gettext
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
DEFAULT_DRIFT_BASELINE = PROJECT_ROOT / "scripts" / "settings_drift_baseline.txt"
DEFAULT_READER_BASELINE = PROJECT_ROOT / "scripts" / "settings_reader_baseline.txt"
PLATFORM_DIR = PROJECT_ROOT / "services" / "platform"

# The two SettingsService methods that actually persist a value; helpers forwarding to either
# count as writers too (see `_write_helper_positions`).
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


def load_reader_baseline(path: Path) -> set[str]:
    """Grouped locations; each @ header gives the consumer path for subsequent entries."""
    if not path.exists():
        return set()
    consumer = ""
    locations: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@ "):
            consumer = line[2:]
            continue
        key, scope, ordinal = line.split("|")
        if not consumer or not ordinal.isdecimal():
            raise ValueError(f"Invalid reader baseline location: {line}")
        locations.add(f"{key}|{consumer}|{scope}|{ordinal}")
    return locations


def write_reader_baseline(path: Path, findings: list[Finding], call_sites: list[SettingsCallSite]) -> int:
    """Replace the grouped baseline with the complete current untested-reader inventory."""
    untested_sites = {
        (finding.file, finding.line, finding.name) for finding in findings if finding.check == "untested-new-reader"
    }
    grouped: dict[str, list[str]] = {}
    for location, call in reader_locations(call_sites).items():
        if (call.file, call.line, call.key) in untested_sites:
            key, consumer, scope, ordinal = location.split("|")
            grouped.setdefault(consumer, []).append(f"{key}|{scope}|{ordinal}")
    lines = [
        "# Grandfathered untested settings readers.",
        "# Regenerate intentionally with lint_settings_coverage.py --write-reader-baseline.",
        "# @ headers name consumer files. Entries are key|qualified callable|ordinal; line shifts are harmless.",
    ]
    for consumer, entries in sorted(grouped.items()):
        lines.extend(["", f"@ {consumer}", *sorted(entries)])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sum(len(entries) for entries in grouped.values())


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
    row_only: bool = False
    scope: str = "<module>"


_UNRESOLVED = object()  # sentinel for values we can't statically resolve

# Row-only resolvers must not acquire catalog-fallback semantics.
_ROW_READERS = {("SystemSetting", "get_value_by_key"), ("SettingsService", "get_stored_setting")}
_FORWARDING_DEPTH = 4


def _expression_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_expression_name(node.value)}.{node.attr}"
    return ""


def _key_values(node: ast.expr, symbols: dict[str, set[str]]) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Subscript):
        # A dynamic index into a finite map can select only its declared values.
        return symbols.get(_expression_name(node.value), set())
    if isinstance(node, ast.Attribute) and _expression_name(node.value) in ("self", "cls"):
        return symbols.get(node.attr, set())
    return symbols.get(_expression_name(node), set())


def _scope_symbols(nodes: list[ast.stmt], inherited: dict[str, set[str]]) -> dict[str, set[str]]:
    symbols = dict(inherited)
    for _ in range(_FORWARDING_DEPTH):
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                for name, values in _scope_symbols(node.body, symbols).items():
                    if name not in symbols:
                        symbols[f"{node.name}.{name}"] = values
                continue
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if isinstance(value, ast.Dict):
                parts = [_key_values(v, symbols) for v in value.values]
                values = set().union(*parts) if parts and all(parts) else set()
            else:
                values = _key_values(value, symbols)
            for target in targets:
                if isinstance(target, ast.Name) and values:
                    symbols[target.id] = values
    return symbols


def _imported_key_symbols(tree: ast.Module, depth: int = 0) -> dict[str, set[str]]:
    symbols: dict[str, set[str]] = {}
    if depth >= _FORWARDING_DEPTH:
        return symbols
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module or not node.module.startswith("apps."):
            continue
        exported = _exported_key_symbols(node.module, depth + 1)
        for alias in node.names:
            local = alias.asname or alias.name
            for name, values in exported.items():
                if name == alias.name or name.startswith(f"{alias.name}."):
                    symbols[local + name[len(alias.name) :]] = values
    return symbols


@cache
def _exported_key_symbols(module: str, depth: int) -> dict[str, set[str]]:
    path = PLATFORM_DIR.joinpath(*module.split(".")).with_suffix(".py")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return {}
    return _scope_symbols(tree.body, _imported_key_symbols(tree, depth))


def _row_reader(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and (node.value.id, node.attr) in _ROW_READERS
    )


def _key_argument(call: ast.Call, position: int = 0, parameter: str = "key") -> ast.expr | None:
    if len(call.args) > position:
        return call.args[position]
    return next((kw.value for kw in call.keywords if kw.arg == parameter), None)


def _row_forwarders(nodes: list[ast.stmt]) -> dict[str, tuple[int, str]]:
    """Only explicit parameter forwarding, at most four same-scope hops; never arbitrary getters."""
    forwarders: dict[str, tuple[int, str]] = {}
    for _ in range(_FORWARDING_DEPTH):
        previous = dict(forwarders)
        for node in nodes:
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            params = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args)]
            if params and params[0] in ("self", "cls"):
                params = params[1:]
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                target = previous.get(_called_name(call.func))
                if _row_reader(call.func):
                    target = (0, "key")
                elif isinstance(call.func, ast.Attribute) and _expression_name(call.func.value) not in ("self", "cls"):
                    target = None
                if target is None:
                    continue
                argument = _key_argument(call, *target)
                if isinstance(argument, ast.Name) and argument.id in params:
                    forwarders[node.name] = (params.index(argument.id), argument.id)
    return forwarders


def reader_locations(call_sites: list[SettingsCallSite]) -> dict[str, SettingsCallSite]:
    """Stable path/callable/ordinal identities: line shifts do not excuse a new read."""
    counts: dict[str, int] = {}
    locations: dict[str, SettingsCallSite] = {}
    for call in call_sites:
        prefix = f"{call.key}|{call.file}|{call.scope}"
        counts[prefix] = counts.get(prefix, 0) + 1
        locations[f"{prefix}|{counts[prefix]}"] = call
    return locations


class SettingsCallVisitor(ast.NodeVisitor):
    """Walk an AST and collect all SettingsService.get_*_setting() call sites."""

    def __init__(self, filepath: Path, module_constants: dict[str, Any] | None = None) -> None:
        self.filepath = filepath
        self.calls: list[SettingsCallSite] = []
        self.module_constants = module_constants or {}
        self.symbols: dict[str, set[str]] = {}
        self.forwarders: dict[str, tuple[int, str]] = {}
        self.scope: list[str] = []

    def visit_Module(self, node: ast.Module) -> None:
        self.symbols = _scope_symbols(node.body, _imported_key_symbols(node))
        self.forwarders = _row_forwarders(node.body)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbols, forwarders = self.symbols, self.forwarders
        self.symbols = _scope_symbols(node.body, symbols)
        self.forwarders = _row_forwarders(node.body)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.symbols, self.forwarders = symbols, forwarders

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        symbols = self.symbols
        self.symbols = _scope_symbols(node.body, symbols)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.symbols = symbols

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_settings_call(node)
        self.generic_visit(node)

    def _check_settings_call(self, node: ast.Call) -> None:
        func = node.func
        row_only = _row_reader(func)
        forwarded = self.forwarders.get(_called_name(func))
        if isinstance(func, ast.Attribute) and _expression_name(func.value) not in ("self", "cls"):
            forwarded = None
        if not row_only and forwarded is None:
            if not isinstance(func, ast.Attribute) or func.attr not in SETTINGS_GETTER_METHODS:
                return
            if isinstance(func.value, ast.Name) and func.value.id not in ("SettingsService", "cls"):
                return

        argument = _key_argument(node, *(forwarded or (0, "key")))
        keys = _key_values(argument, self.symbols) if argument is not None else set()
        if not keys:
            return
        row_only = row_only or forwarded is not None

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

        for key_value in sorted(keys):
            self.calls.append(
                SettingsCallSite(
                    key=key_value,
                    fallback_value=fallback_value,
                    fallback_is_name=fallback_is_name,
                    fallback_name=fallback_name,
                    line=node.lineno,
                    file=_display_path(self.filepath),
                    fallback_resolved_from_name=resolved_from_name,
                    row_only=row_only,
                    scope=".".join(self.scope) or "<module>",
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
        if "SettingsService" not in source and "SystemSetting" not in source:
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
    baseline: set[str] | None = None,
) -> list[Finding]:
    """Detect when an inline fallback disagrees with the catalog default.

    Example: the catalog has "billing.efactura_batch_size": 100 while a call site passes
    `SettingsService.get_integer_setting("billing.efactura_batch_size", 50)`.

    The inline fallback IS reachable for a catalog key, which is why this is medium rather than a
    documentation nit. I first demoted it on the reasoning that `get_setting` falls back to
    `DEFAULT_SETTINGS[key]` so the caller's argument is dead - true of `get_setting` itself, and
    wrong about the typed wrappers. `get_integer_setting` returns the caller's `default` on
    ValueError/TypeError (`services.py:475`), `get_decimal_setting` returns `default or
    Decimal("0")` (`:486`), `get_list_setting` returns `default or []` (`:503`). A cached `None`, a
    stored value that will not coerce, or a row written through a path that skipped validation all
    land on the caller's number. So a drift is a live behavioural difference that appears exactly
    when something has already gone slightly wrong - the worst time to also change a limit.

    Baselined rather than fixed in bulk, because in this codebase the drifting `_DEFAULT_*`
    constant is nearly always ALSO read directly by the enforcing code through a public alias, so
    "align it to the catalog" changes what the system accepts. `products.max_price_cents` would
    raise a price ceiling 100x. Each needs its intended value established and a consumer test.

    What the drift is diagnostic OF is check 6: almost every drift here belongs to a getter nothing
    calls. The two numbers drifted apart precisely because no live path ever made them agree.
    """
    findings: list[Finding] = []
    known = baseline or set()
    seen: set[str] = set()

    for call in call_sites:
        if call.row_only:
            continue
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

        seen.add(call.key)
        if call.key in known:
            continue

        findings.append(
            Finding(
                file=call.file,
                line=call.line,
                severity="medium",
                check="default-drift",
                name=call.key,
                message=(
                    f"Inline fallback {inline!r} disagrees with the catalog default {canonical!r} "
                    f'for key "{call.key}". The typed getters return this number when the stored '
                    f"value will not coerce, so the two disagree in production. Establish which is "
                    f"intended, test the consumer, then align - and check whether the constant is "
                    f"also read directly by the enforcing code before changing it."
                ),
            )
        )

    findings.extend(
        Finding(
            file=str(DEFAULT_DRIFT_BASELINE.relative_to(PROJECT_ROOT)),
            line=0,
            severity="low",
            check="default-drift-fixed",
            name=key,
            message=f"'{key}' no longer drifts. Remove it from the baseline in the same commit.",
        )
        for key in sorted(known - seen)
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
    # Module level, and one level into class bodies: a test class naming its key as
    # `KEY = "app.x"` and writing `self.KEY` is as ordinary as a module constant, and a detector
    # that only understands one of the two silently dictates which to use.
    scopes = [tree.body, *(node.body for node in tree.body if isinstance(node, ast.ClassDef))]
    for body in scopes:
        for node in body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = node.value.value
    return constants


@cache
def _write_helper_positions(text: str) -> dict[str, int]:
    """Local functions that forward a key parameter to a real writer, and WHICH parameter it is.

    Matching only the direct `SettingsService.update_setting("literal")` call is a style rule
    masquerading as a measurement. `tests/settings/test_localisation_consumers.py` drives four
    localisation settings through customer forms, rendered dates and persisted addresses - about as
    thorough an effect test as this repo has - through a two-line `set_value` helper, and the
    detector called all four untested. One level of indirection is where real tests live.

    The position matters and assuming zero was wrong: a helper written `def write(value, key)` would
    have credited `write("some.key", "other.key")` to the wrong key. `self` is discounted so the
    index matches the call site's positional arguments.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    helpers: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args)]
        if params and params[0] in ("self", "cls"):
            params = params[1:]
        for call in ast.walk(node):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in _DIRECT_WRITERS
                and call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id in params
            ):
                helpers[node.name] = params.index(call.args[0].id)
    return helpers


def _called_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


@cache
def _written_keys(text: str) -> frozenset[str]:
    r"""Setting keys this file WRITES, resolved from the AST rather than matched textually.

    The regex version counted a read as a write: a bare `key\s*=\s*"..."` pattern matches
    `SettingsService.get_setting(key="system.maintenance_mode")`, so a test that only read a key
    back could earn it an effect credit. Only a writer's key argument counts now.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return frozenset()
    constants = _module_string_constants(text)
    helpers = _write_helper_positions(text)
    written: set[str] = set()

    def resolve(node: ast.expr | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
            return constants.get(node.attr)
        return None

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = _called_name(call.func)
        if name in _DIRECT_WRITERS:
            position = 0
        elif name in helpers:
            position = helpers[name]
        else:
            continue
        if len(call.args) > position:
            key = resolve(call.args[position])
            if key:
                written.add(key)
        for keyword in call.keywords:
            if keyword.arg == "key":
                key = resolve(keyword.value)
                if key:
                    written.add(key)

    # The bulk-save payload shape: `{"app.key": value}`. A read never spells a key this way.
    written |= {
        node.value
        for dict_node in ast.walk(tree)
        if isinstance(dict_node, ast.Dict)
        for node in dict_node.keys
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "." in node.value
    }
    return frozenset(written)


def production_readers(app_files: list[Path]) -> dict[str, set[str]]:
    """Which production MODULES read each setting key.

    This is what makes an effect claim checkable. The earlier version asked only whether a test file
    reached "another app" somewhere, which is satisfied by any import at all - so
    `virtualmin.rate_limit_qps` earned credit from a settings-permissions test because an unrelated
    dashboard request elsewhere in the same file qualified it. Knowing the key's actual consumer turns
    "this test touches something" into "this test touches the code that reads this setting".
    """
    readers: dict[str, set[str]] = {}
    for call in collect_settings_calls(app_files):
        readers.setdefault(call.key, set()).add(_module_name(call.file))
    return readers


def _module_name(relative_path: str) -> str:
    """`services/platform/apps/orders/tasks.py` -> `apps.orders.tasks`."""
    return relative_path.replace("services/platform/", "").removesuffix(".py").replace("/", ".")


def _scope_nodes(node: ast.AST) -> list[ast.AST]:
    """Walk one lexical scope, leaving nested declarations for separate resolution."""
    nodes = [node]
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            nodes.append(child)
        else:
            nodes.extend(_scope_nodes(child))
    return nodes


def _import_bindings(node: ast.AST) -> dict[str, str]:
    """Resolve imports in this lexical scope only."""
    bindings: dict[str, str] = {}
    for child in _scope_nodes(node):
        if isinstance(child, ast.ImportFrom) and child.module and not child.level:
            for alias in child.names:
                if alias.name != "*":
                    bindings[alias.asname or alias.name] = f"{child.module}.{alias.name}"
        elif isinstance(child, ast.Import):
            for alias in child.names:
                bindings[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
    return bindings


def _bound_callable(node: ast.expr, bindings: dict[str, str]) -> str:
    if isinstance(node, ast.Call):
        return _bound_callable(node.func, bindings)
    if target := bindings.get(_expression_name(node)):
        return target
    if isinstance(node, ast.Attribute):
        parent = _bound_callable(node.value, bindings)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _local_callable_bindings(
    node: ast.AST, inherited: dict[str, str], instances: set[str] | None = None
) -> dict[str, str]:
    """Resolve constructed instances without merging sibling methods' local variables."""
    local = {**inherited, **_import_bindings(node)}
    for child in _scope_nodes(node):
        if isinstance(child, ast.Assign | ast.AnnAssign) and isinstance(child.value, ast.Call):
            target = _bound_callable(child.value.func, local)
            if target:
                names = child.targets if isinstance(child, ast.Assign) else [child.target]
                for name in names:
                    if isinstance(name, ast.Name) or (
                        isinstance(name, ast.Attribute) and _expression_name(name.value) in ("self", "cls")
                    ):
                        symbol = _expression_name(name)
                        local[symbol] = target
                        if instances is not None:
                            instances.add(symbol)
    return local


def _exercised_callables(
    node: ast.AST,
    bindings: dict[str, str],
    graph: dict[str, set[str]] | None = None,
    instance_names: set[str] | None = None,
) -> set[str]:
    """Combine scope-local calls and resolved descriptor accesses, sharing only class instances."""
    constructed = set(instance_names or ())
    local = _local_callable_bindings(node, bindings, constructed)
    if isinstance(node, ast.ClassDef):
        # setUp, setUpTestData and helpers can initialise an instance used by another method. A test
        # method's own assignments stay in that method, so they never replace the fixture's instance.
        instances: dict[str, str] = {}
        for method in node.body:
            if isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef) and not method.name.startswith("test"):
                for name, target in _local_callable_bindings(method, local).items():
                    if name.startswith(("self.", "cls.")):
                        attribute = name.split(".", 1)[1]
                        instances[f"self.{attribute}"] = target
                        instances[f"cls.{attribute}"] = target
        local.update(instances)
        constructed.update(instances)
    exercised: set[str] = set()
    for child in _scope_nodes(node):
        if child is not node and isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            inherited = local
            if isinstance(child, ast.ClassDef):
                inherited = {name: target for name, target in local.items() if not name.startswith(("self.", "cls."))}
            inherited_instances = constructed
            if isinstance(child, ast.ClassDef):
                inherited_instances = {name for name in constructed if not name.startswith(("self.", "cls."))}
            exercised |= _exercised_callables(child, inherited, graph, inherited_instances)
            if not isinstance(child, ast.ClassDef):
                # `@factory()` applies the factory's result to the decorated function.
                exercised |= {
                    f"{target}()"
                    for decorator in child.decorator_list
                    if isinstance(decorator, ast.Call) and (target := _bound_callable(decorator.func, local))
                }
        elif isinstance(child, ast.Call) and (target := _bound_callable(child.func, local)):
            exercised.add(target)
            if isinstance(child.func, ast.Call):
                # `factory()(func)` runs what the factory returned, not only the factory.
                exercised.add(f"{target}()")
        elif isinstance(child, ast.Attribute) and isinstance(child.ctx, ast.Load) and graph is not None:
            # Only marked descriptors execute a getter; ordinary attribute reads earn no credit.
            receiver = _expression_name(child.value)
            if receiver in constructed or isinstance(child.value, ast.Call) or receiver == "self":
                target = _bound_callable(child, local)
                exercised.update(graph.get(f"@property:{target}", set()))
    return exercised


def _callable_edges(tree: ast.Module, module: str) -> dict[str, set[str]]:
    """Callable edges share the module graph's bounded reachability, without sibling credit.

    Decorator factories need one more node. Calling `factory()` runs only the factory's own body; the
    closure it returns runs when that result is applied. So the closure's edges - transitively through
    returned nested functions and returned factory calls - hang off a separate `factory()` node, which
    is reached only by application: a production function decorated with `@factory()` gets an edge to
    it, and a test earns it through `@factory()` or `factory()(func)`. That is how
    `SecureUserRegistrationService.register_new_customer_owner` reaches `_execute_security_checks`
    through `secure_user_registration()`, `secure_service_method()`, `decorator` and `wrapper`.
    """
    edges: dict[str, set[str]] = {}
    returned: dict[str, set[str]] = {}
    returned_calls: dict[str, set[str]] = {}
    decorated: dict[str, set[str]] = {}

    def visit(nodes: list[ast.stmt], scope: str, inherited: dict[str, str]) -> None:
        bindings = {**inherited, **_import_bindings(ast.Module(body=nodes, type_ignores=[]))}
        for node in nodes:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                bindings[node.name] = f"{scope}.{node.name}"
        # Descriptor markers point to getter callables, whose own edges remain independent.
        for node in nodes:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
                (_bound_callable(decorator, bindings) or _expression_name(decorator))
                in {
                    "property",
                    "builtins.property",
                    "functools.cached_property",
                    "django.utils.functional.cached_property",
                }
                for decorator in node.decorator_list
            ):
                getter = f"{scope}.{node.name}"
                edges[f"@property:{getter}"] = {getter}
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{scope}.{node.name}", bindings)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                local = {**bindings, **_import_bindings(node)}
                if scope != module:
                    local.update({"self": scope, "cls": scope})
                # Nested declarations are separate callables; defining one does not exercise it.
                body = ast.Module(
                    body=[
                        child
                        for child in node.body
                        if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                    ],
                    type_ignores=[],
                )
                target = f"{scope}.{node.name}"
                edges[target] = _exercised_callables(body, local, edges)
                nested = {
                    child.name for child in node.body if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                }
                returns = [child.value for child in ast.walk(body) if isinstance(child, ast.Return) and child.value]
                returned[target] = {
                    f"{target}.{value.id}" for value in returns if isinstance(value, ast.Name) and value.id in nested
                }
                returned_calls[target] = {
                    factory
                    for value in returns
                    if isinstance(value, ast.Call) and (factory := _bound_callable(value.func, local))
                }
                decorated[target] = {
                    factory
                    for decorator in node.decorator_list
                    if isinstance(decorator, ast.Call) and (factory := _bound_callable(decorator.func, bindings))
                }
                visit(node.body, target, local)
                if node.name == "__init__":
                    edges.setdefault(scope, set()).add(target)

    visit(tree.body, module, _import_bindings(tree))
    applied: dict[str, set[str]] = {target: set() for target in returned}
    changed = True
    while changed:
        changed = False
        for target, current in applied.items():
            closure = set().union(
                *(edges.get(nested, set()) | applied.get(nested, set()) for nested in returned[target]),
                *(applied.get(factory, set()) for factory in returned_calls[target]),
            )
            if closure - current:
                current |= closure
                changed = True
    for target, closure in applied.items():
        # A factory returned from another module is resolved through its own `()` node.
        foreign = {f"{factory}()" for factory in returned_calls[target] if factory not in applied}
        if closure | foreign:
            edges[f"{target}()"] = closure | foreign
    for target, factories in decorated.items():
        edges[target] |= {f"{factory}()" for factory in factories}
    return edges


def production_import_graph(app_files: list[Path]) -> dict[str, set[str]]:
    """Module and callable edges, with function-level imports included.

    ADR-0007 pushes cross-app imports inside functions, so a module-level-only scan would miss most
    of this codebase's real edges.
    """
    graph: dict[str, set[str]] = {}
    for path in app_files:
        text = path.read_text(errors="ignore")
        module = _module_name(str(path.relative_to(PROJECT_ROOT)))
        graph[module] = set(re.findall(r"from (apps\.[\w.]+) import", text))
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        graph.update(_callable_edges(tree, module))
    return graph


def reaches_reader(start: str, readers: set[str], graph: dict[str, set[str]], depth: int = 2) -> bool:
    """Whether `start` reaches a reading module within `depth` import hops.

    Depth matters and 0 is too strict: `tests/settings/test_localisation_api.py` drives
    `system.customer_date_format` through `apps.api.localisation.views`, which calls
    `get_localisation_defaults()` in `apps.common.localisation_services` - the module that actually
    reads the key. Requiring the test to import the reader itself would reject a genuine effect test
    for the crime of going through the front door.
    """
    seen, frontier = {start}, [(start, 0)]
    while frontier:
        module, hops = frontier.pop()
        if module in readers:
            return True
        if hops >= depth:
            continue
        for nxt in graph.get(module, ()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append((nxt, hops + 1))
    return False


def template_consumed_keys(template_files: list[Path]) -> set[str]:
    """Keys a template reads via `{% setting %}` and its typed siblings.

    Nine keys have no Python reader at all - the `company.*` identity values are consumed only by
    `templates/legal/`. For those the only possible observation is a rendered page.
    """
    keys: set[str] = set()
    for path in template_files:
        keys |= set(re.findall(r'setting\w*\s+["\']([a-z0-9_.]+)["\']', path.read_text(errors="ignore")))
    return keys


def _module_key_collections(tree: ast.Module, catalog_keys: set[str]) -> dict[str, set[str]]:
    """Module-level `NAME = {"app.key": ...}` collections, so a class that uses NAME counts as writing them.

    Without this, `tests/settings/test_company_identity_effects.py` loses seven of its ten keys: they
    live in module-level `PRIVACY_KEYS`/`TERMS_KEYS` dicts that the test class iterates. Scoping the
    write to the class is right; pretending the class cannot see its own module is not.
    """
    collections: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
            continue
        value = node.value
        if isinstance(value, ast.Dict):
            literals = {k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        elif isinstance(value, ast.List | ast.Tuple | ast.Set):
            literals = {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        else:
            continue
        if literals & catalog_keys:
            collections[node.targets[0].id] = literals & catalog_keys
    return collections


def _written_under(
    node: ast.AST,
    constants: dict[str, str],
    helpers: dict[str, int],
    collections: dict[str, set[str]],
    referenced: set[str],
) -> set[str]:
    """Keys written anywhere under `node`, resolving aliases from the module's constants."""

    def resolve(expr: ast.expr | None) -> str | None:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.Name):
            return constants.get(expr.id)
        if isinstance(expr, ast.Attribute):
            return constants.get(_expression_name(expr)) or (
                constants.get(expr.attr) if _expression_name(expr.value) in ("self", "cls") else None
            )
        return None

    written: set[str] = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        name = _called_name(call.func)
        persisted_row = _expression_name(call.func) in {
            "SystemSetting.objects.create",
            "SystemSetting.objects.get_or_create",
            "SystemSetting.objects.update_or_create",
        }
        position = 0 if name in _DIRECT_WRITERS or persisted_row else helpers.get(name)
        if position is None:
            continue
        if len(call.args) > position and (key := resolve(call.args[position])):
            written.add(key)
        written |= {resolved for kw in call.keywords if kw.arg == "key" and (resolved := resolve(kw.value))}
    for dict_node in ast.walk(node):
        if isinstance(dict_node, ast.Dict):
            written |= {
                k.value
                for k in dict_node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and "." in k.value
            }
    for name, keys in collections.items():
        if name in referenced:
            written |= keys
    return written


def effect_tested_keys(  # noqa: PLR0913  # Criterion inputs and optional per-consumer credit output
    catalog_keys: set[str],
    test_files: list[Path],
    readers: dict[str, set[str]],
    graph: dict[str, set[str]],
    template_keys: set[str],
    reader_credits: dict[str, set[str]] | None = None,
) -> set[str]:
    """Keys a test writes and then observes through the code that actually reads them.

    The criterion, per TEST CLASS rather than per file:

    1. the class writes the key, and
    2. the class uses a symbol imported from a module that reads that key, or reaches one within two
       import hops - or, for a key whose only consumer is a template, the class requests a page.

    Scope is the class because that is the unit real tests are organised in: the write often sits in
    `setUp` or a helper while each test observes. File scope, which this used before, let a write in
    one class be qualified by an unrelated request in another - eight keys held credit that way,
    including `audit.compliant_score_threshold`, whose qualifying test only checks that settings
    validation rejects a negative score and never touches compliance classification.

    What this still cannot do is inspect assertions: a qualifying class with every `assert` stripped
    keeps its credit. It now measures that a test drove the setting INTO its consumer, which is a far
    stronger claim than the previous "the file mentions both", and still not a proof of coverage.
    """
    credited: set[str] = set()
    for path in test_files:
        source = path.read_text(errors="ignore")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        constants = _module_string_constants(source)
        key_symbols = _imported_key_symbols(tree)
        constants.update({name: next(iter(values)) for name, values in key_symbols.items() if len(values) == 1})
        helpers = _write_helper_positions(source)
        collections = _module_key_collections(tree, catalog_keys)
        imported: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.setdefault(node.module, set()).update(a.asname or a.name for a in node.names)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported.setdefault(alias.name, set()).add(alias.asname or alias.name.split(".")[0])
        lines = source.splitlines()
        bindings = _import_bindings(tree)

        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            referenced = {n.id for n in ast.walk(cls) if isinstance(n, ast.Name)} | {
                n.attr for n in ast.walk(cls) if isinstance(n, ast.Attribute)
            }
            written = _written_under(cls, constants, helpers, collections, referenced) & catalog_keys
            if not written:
                continue
            body = "\n".join(lines[cls.lineno - 1 : (cls.end_lineno or cls.lineno)])
            makes_request = bool(re.search(r"client\.(?:get|post|put|patch|delete)\(", body))
            used_modules = {
                module
                for module, names in imported.items()
                if {
                    name
                    for name in names
                    if not any(
                        (symbol == name or symbol.startswith(f"{name}.")) and values & catalog_keys
                        for symbol, values in key_symbols.items()
                    )
                }
                & referenced
            }
            for key in written:
                key_readers = readers.get(key, set())
                observed_readers = {
                    reader
                    for reader in key_readers
                    if any(reaches_reader(module, {reader}, graph) for module in used_modules)
                }
                observed_through_reader = bool(observed_readers)
                if reader_credits is not None:
                    reader_credits.setdefault(key, set()).update(_exercised_callables(cls, bindings, graph))
                # A key with no Python reader at all - the `company.*` identity values - can only be
                # observed on a rendered page.
                rendered_on_a_page = key in template_keys and makes_request
                if observed_through_reader or rendered_on_a_page:
                    credited.add(key)
    return credited


def check_untested_effects(  # noqa: PLR0913  # One argument per input the criterion needs
    catalog_keys: set[str],
    test_files: list[Path],
    baseline: set[str],
    readers: dict[str, set[str]],
    graph: dict[str, set[str]],
    template_keys: set[str],
    reader_baseline: set[str] | None = None,
    call_sites: list[SettingsCallSite] | None = None,
) -> list[Finding]:
    """Check 5 — a setting whose EFFECT nothing asserts.

    The other four checks are about wiring: is the key referenced, do the defaults agree, does a
    fallback drift. `system.maintenance_mode` passed every one of them while having no
    customer-facing consequence at all - it was referenced, its default matched, its fallback was
    consistent, and enabling it did nothing a portal customer could see. Wiring is not effect.

    A ratchet, not a cliff. Most keys have no test that mentions them at all, and demanding that
    many tests at once would only teach people to bypass the gate. So the baseline records the keys
    that ARE effect-tested, and this fails when one of them stops being - which makes progress
    monotonic and every future effect test permanent.

    What a static check cannot do, said plainly: it cannot see assertions. Strip every assert from a
    qualifying test file and the credit survives, because the write, the cross-app reach and the
    request are all still there. So this measures the SHAPE of an effect test, not its force, and
    the baseline is a floor on what has been attempted rather than a proof of what is covered.
    Reading the test is still the only thing that establishes the assertion discriminates, which is
    why the tests behind entries added here were mutation-checked by hand.
    """
    reader_credits: dict[str, set[str]] = {}
    tested = effect_tested_keys(catalog_keys, test_files, readers, graph, template_keys, reader_credits)
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

    known_readers = reader_baseline or set()
    for location, call in reader_locations(call_sites or []).items():
        if (
            call.key in catalog_keys
            and not any(
                reaches_reader(target, {f"{_module_name(call.file)}.{call.scope}"}, graph)
                for target in reader_credits.get(call.key, set())
            )
            and location not in known_readers
        ):
            findings.append(
                Finding(
                    file=call.file,
                    line=call.line,
                    severity="medium",
                    check="untested-new-reader",
                    name=call.key,
                    message=f"New reader {location} has no qualifying effect test. Test its consumer.",
                )
            )

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

# Modules doing any of these can reach a function without naming it, so no claim of deadness is
# safe there. Narrow on purpose: a broad "looks dynamic" heuristic would excuse everything.
_DYNAMIC_DISPATCH_MARKERS = ("import_string(", "globals()[", "getattr(sys.modules", "vars()[")


def _keys_read(node: ast.AST) -> set[str]:
    """Literal setting keys read by `SettingsService.get_*` anywhere under `node`."""
    return {
        call.args[0].value
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in SETTINGS_GETTER_METHODS
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }


def _display_path(path: Path) -> str:
    """Repo-relative where possible. Tolerating an outside path keeps the check unit-testable."""
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _module_path(path: Path) -> str:
    """`services/platform/apps/orders/tasks.py` -> `apps.orders.tasks`."""
    try:
        rel = path.relative_to(PLATFORM_DIR)
    except ValueError:
        return ""
    return ".".join(rel.with_suffix("").parts)


def _candidate_caller_files(reader: Path, texts: dict[Path, str]) -> list[Path]:
    """Files that could possibly reference a function defined in `reader`.

    Its own file; anything naming its module path (absolute import); and anything in the same
    package directory, which may reach it by a relative import. Over-inclusion is the safe
    direction - a file wrongly included can only make the check claim LESS.

    Without this the sweep was name-only, and three modules define `get_task_time_limit()`:
    `customers/tasks.py` calls its own, and that call made `provisioning/virtualmin_tasks.py`'s
    unused copy look live. Name collisions hid four real dead readers.
    """
    dotted = _module_path(reader)
    tail = dotted.rsplit(".", 1)[-1]
    return [
        path
        for path, text in texts.items()
        if path == reader
        or path.parent == reader.parent
        or (dotted and dotted in text)
        # An empty tail would make this `"import " in text` and match every module that imports
        # anything, quietly turning the whole check off.
        or (tail and f"import {tail}" in text)
    ]


def check_inert_settings(catalog_keys: set[str], files: list[Path], baseline: set[str]) -> list[Finding]:
    """Check 6 — a setting whose only reader is a function nothing calls.

    This is the shape that let `system.maintenance_mode` ship with no effect, and it is not rare.
    The repeated pattern is three lines:

        _DEFAULT_X = 100                                                 # what the code enforces
        X = _DEFAULT_X                                                   # what live logic reads
        def get_x(): return SettingsService.get_integer_setting("app.x", _DEFAULT_X)   # uncalled

    Live code compares against the module constant. The getter that would consult the operator's
    configured value is never called. The setting is editable in the UI and inert. Check 1 passes on
    every one of them, because the key IS "referenced in app code" - inside the dead getter.

    What this check can and cannot establish, stated plainly because the first version overclaimed.
    It is a STATIC criterion: a module-level, undecorated function whose name appears nowhere in any
    file that could import it. That is strong evidence and it is not proof of runtime
    unreachability. Three escapes are handled by refusing to judge rather than by guessing -
    decorated functions (a decorator receives the object, so the name need never appear again),
    modules using `import_string`/`globals()[...]` dispatch, and any key that some OTHER reader
    reads, including a method or module-level code. Anything else - a persisted task schedule naming
    a dotted path, a caller outside services/platform - remains outside its reach, so a finding here
    is "no reachable reader found", which is what the message says.

    Ratchet, not cliff, and it ratchets both ways: a NEW inert setting fails at medium, and a
    baseline entry that became live fails at low until removed, so the list cannot rot.
    """
    # Production files only. A setting read back by a test proves storage, not effect, and a getter
    # called only from a test still leaves the setting with no production consequence - which is
    # what this check is about. Including `tests/` had `audit.compliant_score_threshold` looking
    # live on the strength of one `get_setting` call inside a storage test.
    production = [path for path in files if "tests" not in path.parts]
    texts = {path: path.read_text(errors="ignore") for path in production}

    parsed: list[tuple[Path, ast.Module, str]] = []
    for path, text in texts.items():
        if "SettingsService" not in text:
            continue
        try:
            parsed.append((path, ast.parse(text), text))
        except SyntaxError:
            continue

    # Candidate dead readers: module-level, undecorated, in a module with no dynamic dispatch.
    candidates: dict[tuple[Path, str], set[str]] = {}
    for path, tree, text in parsed:
        if any(marker in text for marker in _DYNAMIC_DISPATCH_MARKERS):
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                continue
            keys = _keys_read(node) & catalog_keys
            if keys:
                candidates[(path, node.name)] = keys

    dead: dict[tuple[Path, str], set[str]] = {}
    for (path, name), keys in candidates.items():
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        definition = re.compile(rf"\s*(?:async\s+)?def\s+{re.escape(name)}\b")
        referenced = any(
            pattern.search(line) and not definition.match(line)
            for candidate in _candidate_caller_files(path, texts)
            for line in texts[candidate].splitlines()
        )
        if not referenced:
            dead[(path, name)] = keys

    # Every key read from anywhere that is NOT one of those dead functions is live - including from
    # a method, a class body or module scope. Codex found no case among the first 43 where a live
    # method read the same key as a dead getter, but the subtraction costs nothing and removes a
    # whole false-positive class rather than relying on that staying true.
    dead_nodes = {(path, name) for path, name in dead}
    live_keys: set[str] = set()
    for path, tree, _text in parsed:
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and (path, node.name) in dead_nodes:
                continue
            live_keys |= _keys_read(node) & catalog_keys
        live_keys |= {
            key
            for node in tree.body
            if not isinstance(node, ast.FunctionDef | ast.ClassDef)
            for key in _keys_read(node) & catalog_keys
        }

    inert: dict[str, str] = {}
    for (path, name), keys in sorted(dead.items(), key=lambda item: (str(item[0][0]), item[0][1])):
        for key in sorted(keys - live_keys):
            inert.setdefault(key, f"{_display_path(path)}:{name}()")

    findings: list[Finding] = [
        Finding(
            file=where.rsplit(":", 1)[0],
            line=0,
            severity="medium",
            check="inert-setting",
            name=key,
            message=(
                f"'{key}' is read only by {where}, for which no reachable caller was found. The "
                f"setting is editable and has no effect. Call the getter from the code that "
                f"enforces the limit, or delete the key from the catalog."
            ),
        )
        for key, where in sorted(inert.items())
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
        for key in sorted(baseline - set(inert))
    )
    if inert:
        findings.append(
            Finding(
                file=str(DEFAULT_INERT_BASELINE.relative_to(PROJECT_ROOT)),
                line=0,
                severity="info",
                check="inert-setting",
                name=f"{len(inert)}-of-{len(catalog_keys)}",
                message=(
                    f"{len(inert)}/{len(catalog_keys)} settings are read only from a getter with no "
                    f"reachable caller. Every one is editable in the UI and inert."
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
        "--drift-baseline",
        type=Path,
        default=DEFAULT_DRIFT_BASELINE,
        help="Keys with a known fallback/catalog drift (default: scripts/settings_drift_baseline.txt)",
    )
    parser.add_argument(
        "--inert-baseline",
        type=Path,
        default=DEFAULT_INERT_BASELINE,
        help="Keys known to be read only from an uncalled getter (default: scripts/settings_inert_baseline.txt)",
    )
    parser.add_argument(
        "--reader-baseline",
        type=Path,
        default=DEFAULT_READER_BASELINE,
        help="Existing untested reader locations (default: scripts/settings_reader_baseline.txt)",
    )
    parser.add_argument(
        "--write-reader-baseline",
        action="store_true",
        help=gettext("Regenerate the reader baseline from all current untested readers"),
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
    all_findings.extend(check_default_drift(defaults, call_sites, load_key_baseline(args.drift_baseline)))
    catalog_keys = set(extract_catalog_keys(CATALOG_FILE))
    all_findings.extend(
        check_untested_effects(
            catalog_keys,
            iter_python_files(PLATFORM_TESTS_DIR),
            load_key_baseline(args.effect_baseline),
            production_readers(app_files),
            production_import_graph(app_files),
            template_consumed_keys(template_files),
            set() if args.write_reader_baseline else load_reader_baseline(args.reader_baseline),
            call_sites,
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

    if args.write_reader_baseline:
        count = write_reader_baseline(args.reader_baseline, all_findings, call_sites)
        print(gettext("✅ Reader baseline written: %(count)s entries") % {"count": count})
        return 0

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
