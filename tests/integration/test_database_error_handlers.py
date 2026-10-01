"""A handler that catches ``DatabaseError`` to degrade must also catch ``InterfaceError`` (#548).

PEP 249 makes ``InterfaceError`` a sibling of ``DatabaseError``, not a subclass: both
derive from ``django.db.Error``. A connection that is closed or unusable raises
``InterfaceError``, so ``except DatabaseError`` written as "the database is unavailable,
fall back" lets exactly that outage through. The staff locale lookup on every page was
one such site.

This guard scans both services' apps for handlers that name the base ``DatabaseError``
without also covering ``InterfaceError`` (directly, or through ``Error`` / ``Exception``).
A handler that is deliberately narrow carries ``# narrow-db-catch: <reason>`` on its
``except`` / ``with`` line or the line after it. The portal's
``from django.db import Error as DatabaseError`` alias is resolved, so it is not flagged.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_ROOTS = (ROOT / "services" / "platform" / "apps", ROOT / "services" / "portal" / "apps")
MARKER = "# narrow-db-catch:"

_DB_MODULES = {"django.db", "django.db.utils"}
_NARROW = "DatabaseError"
_COVERING = {"InterfaceError", "Error"}
_BROAD_BUILTINS = {"Exception", "BaseException"}


class _Imports:
    """What each local name means, as far as django.db exceptions are concerned."""

    def __init__(self, tree: ast.Module) -> None:
        self.names: dict[str, str] = {}  # local name -> django.db exception name
        self.modules: set[str] = set()  # local names bound to django.db / django.db.utils
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in _DB_MODULES:
                for alias in node.names:
                    if node.module == "django.db" and alias.name == "utils":
                        self.modules.add(alias.asname or "utils")
                    else:
                        self.names[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module == "django":
                self.modules.update(alias.asname or "db" for alias in node.names if alias.name == "db")
            elif isinstance(node, ast.Import):
                self.modules.update(alias.asname for alias in node.names if alias.name in _DB_MODULES and alias.asname)

    def resolve(self, expr: ast.expr) -> str | None:
        """Return the django.db exception an expression names, a builtin, or None."""
        if isinstance(expr, ast.Name):
            if expr.id in self.names:
                return self.names[expr.id]
            if expr.id in _BROAD_BUILTINS:
                return expr.id
            return None
        if isinstance(expr, ast.Attribute):
            base = expr.value
            if isinstance(base, ast.Name) and base.id in self.modules:
                return expr.attr
            if ast.unparse(base) in _DB_MODULES:
                return expr.attr
        return None


def _caught(node: ast.expr | None) -> list[ast.expr]:
    if node is None:
        return []
    return list(node.elts) if isinstance(node, ast.Tuple) else [node]


def _is_suppress(call: ast.expr) -> bool:
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "suppress") or (
        isinstance(func, ast.Attribute) and func.attr == "suppress"
    )


def _narrow(imports: _Imports, exprs: list[ast.expr]) -> bool:
    resolved = {imports.resolve(expr) for expr in exprs}
    return _NARROW in resolved and not (resolved & (_COVERING | _BROAD_BUILTINS))


def find_narrow_handlers(source: str) -> list[int]:
    """Line numbers of handlers catching DatabaseError but not InterfaceError, unmarked."""
    tree = ast.parse(source)
    imports = _Imports(tree)
    lines = source.splitlines()

    def marked(lineno: int) -> bool:
        return any(MARKER in lines[i] for i in (lineno - 1, lineno) if i < len(lines))

    found: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if _narrow(imports, _caught(node.type)) and not marked(node.lineno):
                found.append(node.lineno)
        elif isinstance(node, ast.With | ast.AsyncWith):
            found.extend(
                item.context_expr.lineno
                for item in node.items
                if isinstance(item.context_expr, ast.Call)
                and _is_suppress(item.context_expr)
                and _narrow(imports, list(item.context_expr.args))
                and not marked(item.context_expr.lineno)
            )
    return sorted(found)


def _app_sources() -> list[Path]:
    return sorted(
        path for root in APP_ROOTS for path in root.rglob("*.py") if "migrations" not in path.relative_to(root).parts
    )


def test_no_unmarked_database_error_handler_misses_interface_error() -> None:
    offenders = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in _app_sources()
        for line in find_narrow_handlers(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "These handlers catch DatabaseError but not InterfaceError, so an unusable connection "
        "escapes them. Add InterfaceError, or mark a deliberately narrow catch with "
        f"'{MARKER} <reason>':\n" + "\n".join(offenders)
    )


def test_scan_covers_both_services() -> None:
    sources = _app_sources()
    assert any("services/platform/apps" in str(path) for path in sources)
    assert any("services/portal/apps" in str(path) for path in sources)


# --- Detector self-tests: a guard that cannot fail protects nothing. -----------------


def test_detects_plain_except() -> None:
    src = "from django.db import DatabaseError\ntry:\n    x()\nexcept DatabaseError:\n    pass\n"
    assert find_narrow_handlers(src) == [4]


def test_detects_tuple_and_attribute_spellings() -> None:
    src = (
        "from django.db import utils as db_utils\n"
        "import django.db\n"
        "try:\n    x()\nexcept (db_utils.DatabaseError, OSError):\n    pass\n"
        "try:\n    x()\nexcept django.db.DatabaseError:\n    pass\n"
    )
    assert find_narrow_handlers(src) == [5, 9]


def test_detects_suppress() -> None:
    src = (
        "from contextlib import suppress\nfrom django.db import DatabaseError\nwith suppress(DatabaseError):\n    x()\n"
    )
    assert find_narrow_handlers(src) == [3]


def test_accepts_interface_error_error_alias_and_broad_catches() -> None:
    src = (
        "from django.db import DatabaseError, InterfaceError\n"
        "try:\n    x()\nexcept (DatabaseError, InterfaceError):\n    pass\n"
        "try:\n    x()\nexcept (DatabaseError, Exception):\n    pass\n"
    )
    assert find_narrow_handlers(src) == []
    portal_alias = "from django.db import Error as DatabaseError\ntry:\n    x()\nexcept DatabaseError:\n    pass\n"
    assert find_narrow_handlers(portal_alias) == []


def test_unrelated_database_error_name_is_ignored() -> None:
    src = "from somewhere import DatabaseError\ntry:\n    x()\nexcept DatabaseError:\n    pass\n"
    assert find_narrow_handlers(src) == []


def test_marker_exempts_on_handler_line_or_next() -> None:
    src = (
        "from django.db import DatabaseError\n"
        "try:\n    x()\nexcept DatabaseError:  # narrow-db-catch: table-missing check only\n    pass\n"
        "try:\n    x()\nexcept DatabaseError:\n    # narrow-db-catch: fallback writes, so it would fail anyway\n    pass\n"
    )
    assert find_narrow_handlers(src) == []
