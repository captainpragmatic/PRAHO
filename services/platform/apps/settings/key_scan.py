"""
Shared settings-key extraction used by both guardrails (ADR-0040):
scripts/lint_settings_coverage.py and tests/settings/test_catalog_consumer_contract.py.

Python sources are scanned via tokenize so string literals in comments can never
fake consumption (the historical failure mode: DEPRECATED comment blocks in
constants.py kept dead keys "alive"). Templates are scanned as raw text.
"""

from __future__ import annotations

import ast
import tokenize
from pathlib import Path
from typing import Any

EXCLUDED_DIR_NAMES = frozenset(
    {"__pycache__", "migrations", ".mypy_cache", ".pytest_cache", ".ruff_cache", "staticfiles", "node_modules"}
)


def extract_string_literals(path: Path) -> set[str]:
    """String literals in a Python file via tokenize — comments drop out by construction"""
    literals: set[str] = set()
    try:
        with tokenize.open(path) as handle:
            for token in tokenize.generate_tokens(handle.readline):
                if token.type != tokenize.STRING:
                    continue
                try:
                    value = ast.literal_eval(token.string)
                except (ValueError, SyntaxError):
                    continue
                if isinstance(value, str):
                    literals.add(value)
    except (OSError, SyntaxError, UnicodeDecodeError, tokenize.TokenError):
        pass
    return literals


def extract_catalog_defaults(catalog_path: Path) -> dict[str, Any]:
    """Parse catalog.py without importing Django: every SettingDef(key=…, default=…) call"""
    defaults: dict[str, Any] = {}
    tree = ast.parse(catalog_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "SettingDef"):
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if "key" not in kwargs:
            continue
        try:
            key = ast.literal_eval(kwargs["key"])
            default = ast.literal_eval(kwargs["default"]) if "default" in kwargs else None
        except (ValueError, SyntaxError):
            continue
        defaults[key] = default
    return defaults


def iter_scannable_python_files(root: Path) -> list[Path]:
    """Python files under root, minus caches/migrations"""
    return [
        path
        for path in sorted(root.rglob("*.py"))
        if not any(part in EXCLUDED_DIR_NAMES for part in path.relative_to(root).parts)
    ]
