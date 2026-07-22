#!/usr/bin/env python3
"""Reject new module-level cross-app model imports (ADR-0007)."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path

APP_ROOT = "services/platform/apps/"
EXEMPT_PATH_PARTS = frozenset({"management", "migrations", "tests", "__pycache__"})
EXEMPT_SOURCE_APPS = frozenset({"api"})


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    imported_module: str
    imported_name: str

    @property
    def key(self) -> str:
        return f"{self.file}|{self.imported_module}|{self.imported_name}"


def _stable_path(path: Path) -> str:
    value = path.as_posix()
    marker_index = value.find(APP_ROOT)
    return value[marker_index:] if marker_index >= 0 else value


def _source_app(path: Path) -> str | None:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part == "apps" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _is_model_module(module: str) -> bool:
    parts = module.split(".")
    return (
        len(parts) >= 3
        and parts[0] == "apps"
        and any(part == "models" or part.endswith("_models") for part in parts[2:])
    )


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, source_app: str) -> None:
        self.path = path
        self.source_app = source_app
        self.violations: list[Violation] = []

    def _add(self, node: ast.Import | ast.ImportFrom, module: str, name: str) -> None:
        parts = module.split(".")
        if _is_model_module(module) and parts[1] != self.source_app:
            self.violations.append(
                Violation(
                    file=_stable_path(self.path),
                    line=node.lineno,
                    imported_module=module,
                    imported_name=name,
                )
            )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._add(node, alias.name, alias.name.rsplit(".", maxsplit=1)[-1])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        for alias in node.names:
            if _is_model_module(node.module):
                self._add(node, node.module, alias.name)
            else:
                self._add(node, f"{node.module}.{alias.name}", alias.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_If(self, node: ast.If) -> None:
        is_type_checking = isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING"
        is_qualified_type_checking = (
            isinstance(node.test, ast.Attribute)
            and isinstance(node.test.value, ast.Name)
            and node.test.value.id == "typing"
            and node.test.attr == "TYPE_CHECKING"
        )
        if is_type_checking or is_qualified_type_checking:
            for statement in node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)


def scan_source(source: str, path: Path) -> list[Violation]:
    source_app = _source_app(path)
    if source_app is None or source_app in EXEMPT_SOURCE_APPS or EXEMPT_PATH_PARTS.intersection(path.parts):
        return []
    visitor = _ImportVisitor(path, source_app)
    visitor.visit(ast.parse(source, filename=str(path)))
    return sorted(visitor.violations, key=lambda violation: violation.key)


def _python_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        candidates = [root] if root.is_file() else root.rglob("*.py")
        files.extend(path for path in candidates if not EXEMPT_PATH_PARTS.intersection(path.parts))
    return sorted(files)


def scan_paths(roots: list[Path]) -> list[Violation]:
    violations: list[Violation] = []
    for path in _python_files(roots):
        try:
            violations.extend(scan_source(path.read_text(encoding="utf-8"), path))
        except (OSError, SyntaxError) as exc:
            raise RuntimeError(f"Unable to scan {path}: {exc}") from exc
    return sorted(violations, key=lambda violation: violation.key)


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def compare_baseline(violations: list[Violation], baseline: set[str]) -> tuple[list[Violation], list[str]]:
    current = {violation.key for violation in violations}
    return [violation for violation in violations if violation.key not in baseline], sorted(baseline - current)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", type=Path, default=[Path(APP_ROOT)])
    parser.add_argument("--baseline", type=Path, default=Path("scripts/cross_app_model_imports_baseline.txt"))
    parser.add_argument("--print-baseline", action="store_true")
    args = parser.parse_args()
    violations = scan_paths(args.roots)
    if args.print_baseline:
        for violation in violations:
            print(violation.key)
        return 0

    new, stale = compare_baseline(violations, load_baseline(args.baseline))
    for violation in new:
        print(
            f"{violation.file}:{violation.line}: ADR-0007: defer "
            f"{violation.imported_module}.{violation.imported_name} to function scope"
        )
    for entry in stale:
        print(f"ADR-0007 baseline entry is stale and must be removed: {entry}")
    if new or stale:
        print(f"Cross-app model import guard failed: {len(new)} new, {len(stale)} stale")
        return 1
    print(f"Cross-app model import guard passed ({len(violations)} legacy dependencies baselined)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
