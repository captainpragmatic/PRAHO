"""
Guardrail: every async_task() dotted-path string literal in the platform apps
must import-resolve.

A wrong dotted path (e.g. 'apps.provisioning.tasks.provision_order_item' when
the function actually lives in apps.orders.tasks) does NOT raise at enqueue time
— django-q resolves it only in the worker — so the try/except around async_task
never catches it and the order item silently stays provisioning_status='pending'
forever (#328). This test fails loudly the moment a dotted path drifts.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from django.test import SimpleTestCase
from django.utils.module_loading import import_string

APPS_DIR = Path(__file__).resolve().parents[2] / "apps"

# Matches async_task("some.dotted.path", ...) — a string literal as the first arg.
_ASYNC_TASK_LITERAL = re.compile(r"""async_task\(\s*["']([a-zA-Z_][\w.]+)["']""")


class TestAsyncTaskDottedPathsResolve(SimpleTestCase):
    def test_every_async_task_string_literal_import_resolves(self) -> None:
        offenders: list[str] = []
        seen = 0

        for py in APPS_DIR.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            if "async_task(" not in text:
                continue
            for match in _ASYNC_TASK_LITERAL.finditer(text):
                dotted = match.group(1)
                # Only dotted callables (contain a '.') are import_string targets;
                # a bare identifier is a local function reference, not a string path.
                if "." not in dotted:
                    continue
                seen += 1
                try:
                    import_string(dotted)
                except ImportError as exc:
                    line = text[: match.start()].count("\n") + 1
                    rel = py.relative_to(APPS_DIR.parent)
                    offenders.append(f"{rel}:{line} -> {dotted} ({exc})")

        self.assertGreater(seen, 0, "scanner found no async_task dotted-path literals — regex likely broke")
        self.assertEqual(
            offenders,
            [],
            "async_task dotted paths that do not import-resolve (worker would fail silently):\n" + "\n".join(offenders),
        )

    def test_ast_scan_agrees_no_missing_import_of_string_paths(self) -> None:
        """AST cross-check so a reformat of the call can't hide a bad literal
        from the regex (belt and braces on a silent-failure class)."""
        offenders: list[str] = []

        for py in APPS_DIR.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            if "async_task(" not in text:
                continue
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "async_task"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and "." in node.args[0].value
                ):
                    dotted = node.args[0].value
                    try:
                        import_string(dotted)
                    except ImportError:
                        rel = py.relative_to(APPS_DIR.parent)
                        offenders.append(f"{rel}:{node.lineno} -> {dotted}")

        self.assertEqual(offenders, [], "unresolvable async_task dotted paths:\n" + "\n".join(offenders))
