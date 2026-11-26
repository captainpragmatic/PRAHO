"""No TypeVar in the services' app code is bound by a string forward reference.

A queryset generic over a TypeVar bound to a model named in a string, defined further down the same
module, which that model then turns into its manager with ``as_manager()``, crashed mypy 1.19.1 with
django-stubs 5.2.9 ("Must not defer during final iteration"). The crash appeared only when the module
was reached through another file's imports, such as ``make check-types FILE=apps/settings/catalog.py``,
never in the full run CI does, so nothing caught it. Binding to a class that already exists avoids it.
"""

import ast
from pathlib import Path

from django.test import SimpleTestCase

SERVICES = Path(__file__).resolve().parents[3]
APP_ROOTS = (SERVICES / "platform" / "apps", SERVICES / "portal" / "apps")


def forward_reference_bounds(root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "TypeVar"):
                continue
            found.extend(
                f"{path.relative_to(SERVICES)}:{node.lineno}"
                for keyword in node.keywords
                if keyword.arg == "bound" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str)
            )
    return found


class TypeVarForwardBoundTests(SimpleTestCase):
    def test_the_scan_finds_a_string_bound(self) -> None:
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=SERVICES) as tmp:
            module = Path(tmp) / "models.py"
            module.write_text('from typing import TypeVar\nRecord = TypeVar("Record", bound="Later")\n', encoding="utf-8")
            self.assertEqual(len(forward_reference_bounds(Path(tmp))), 1)

    def test_no_app_typevar_has_a_string_bound(self) -> None:
        self.assertTrue(all(root.is_dir() for root in APP_ROOTS))
        found = [site for root in APP_ROOTS for site in forward_reference_bounds(root)]
        self.assertEqual(found, [], "bind the TypeVar to a class that is already defined")
