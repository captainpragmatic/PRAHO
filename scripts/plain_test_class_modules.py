#!/usr/bin/env python3
"""List the platform test modules that hold plain pytest-style ``Test*`` classes.

The Django test runner only collects ``unittest.TestCase`` subclasses, so a ``class TestX:`` with
``test_*`` methods and pytest fixtures never runs under ``manage.py test``. CI feeds this list to
pytest so a new plain class is picked up without anyone editing a workflow.

Prints one repo-relative path per line (relative to services/platform), sorted. Stdlib only.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PLATFORM = Path(__file__).resolve().parents[1] / "services" / "platform"
TESTS = PLATFORM / "tests"


def _base_name(node: ast.expr) -> str:
    """The last dotted segment of a base-class expression: ``unittest.TestCase`` -> ``TestCase``."""
    return node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""


def _module_classes(source: str) -> dict[str, tuple[list[str], bool]]:
    """Module-level class name -> (base names, whether it defines a ``test_*`` method)."""
    classes = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            has_tests = any(
                isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name.startswith("test_")
                for item in node.body
            )
            classes[node.name] = ([_base_name(base) for base in node.bases], has_tests)
    return classes


def _is_unittest_class(name: str, table: dict[str, list[str]], seen: frozenset[str] = frozenset()) -> bool:
    """Whether the Django runner collects ``name``: it reaches a ``*TestCase`` base through the bases."""
    if name.endswith("TestCase"):
        return True
    if name in seen:
        return False
    return any(_is_unittest_class(base, table, seen | {name}) for base in table.get(name, []))


def plain_test_classes(source: str, table: dict[str, list[str]] | None = None) -> list[str]:
    """Module-level ``Test*`` classes with ``test_*`` methods that the Django runner would not collect.

    ``table`` maps class names across the whole test tree to their bases, so a class whose
    fixture base lives in another module is resolved. Without it only this module is consulted.
    """
    classes = _module_classes(source)
    # This module's own definitions win over a same-named class elsewhere in the tree.
    table = {**(table or {}), **{name: bases for name, (bases, _) in classes.items()}}
    return [
        name
        for name, (_, has_tests) in classes.items()
        if name.startswith("Test") and has_tests and not _is_unittest_class(name, table)
    ]


def plain_class_modules(tests_dir: Path = TESTS) -> dict[str, list[str]]:
    """Path (relative to services/platform) -> plain Test* class names, for every test module holding any."""
    sources = {path: path.read_text(encoding="utf-8") for path in sorted(tests_dir.rglob("*.py"))}
    table: dict[str, list[str]] = {}
    for source in sources.values():
        for name, (bases, _) in _module_classes(source).items():
            table.setdefault(name, []).extend(bases)
    found = {}
    for path, source in sources.items():
        if not path.name.startswith("test"):
            continue
        names = plain_test_classes(source, table)
        if names:
            found[path.relative_to(tests_dir.parent).as_posix()] = names
    return found


def main() -> int:
    modules = plain_class_modules()
    if not modules:
        print("no plain Test* classes found: the scan is broken", file=sys.stderr)
        return 1
    print("\n".join(modules))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
