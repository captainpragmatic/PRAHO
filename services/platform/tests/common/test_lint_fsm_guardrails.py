"""
Tests for scripts/lint_fsm_guardrails.py checks.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase


def _load_lint_module():
    script_path = Path(__file__).resolve().parents[4] / "scripts" / "lint_fsm_guardrails.py"
    spec = importlib.util.spec_from_file_location("lint_fsm_guardrails", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load lint module from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FSMLintGuardrailsTests(SimpleTestCase):
    """Guardrail checks for FSM bypass patterns."""

    def test_vars_status_bypass_is_flagged(self) -> None:
        lint_module = _load_lint_module()
        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "sample.py"
            file_path.write_text(
                "def f(instance):\n"
                "    vars(instance)['status'] = 'active'\n",
                encoding="utf-8",
            )

            result = lint_module.ScanResult()
            lint_module.scan_file(file_path, result)

        self.assertTrue(any(v.check == "dict-bypass" for v in result.violations))

    def test_dunder_setattr_status_bypass_is_flagged(self) -> None:
        lint_module = _load_lint_module()
        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "sample.py"
            file_path.write_text(
                "def f(instance):\n"
                "    object.__setattr__(instance, 'status', 'active')\n",
                encoding="utf-8",
            )

            result = lint_module.ScanResult()
            lint_module.scan_file(file_path, result)

        self.assertTrue(any(v.check == "dict-bypass" for v in result.violations))

    def _scan_service_file(self, relative_path: str, source: str) -> list[str]:
        lint_module = _load_lint_module()
        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / relative_path
            file_path.parent.mkdir(parents=True)
            file_path.write_text(source, encoding="utf-8")
            result = lint_module.ScanResult()
            lint_module.scan_file(file_path, result)
        return [v.check for v in result.violations]

    def test_status_writes_in_the_former_service_file_exemptions_are_checked(self) -> None:
        source = (
            "def f(account):\n"
            "    account.status = 'active'\n"
            "    Model.objects.filter(pk=1).update(status='failed')\n"
        )
        for relative_path in (
            "apps/billing/tasks.py",
            "apps/provisioning/virtualmin_service.py",
            "apps/provisioning/virtualmin_views.py",
        ):
            with self.subTest(path=relative_path):
                checks = self._scan_service_file(relative_path, source)
                self.assertIn("direct-assignment", checks)
                self.assertIn("queryset-update", checks)

    def test_a_line_that_names_why_it_is_not_fsm_protected_passes(self) -> None:
        source = (
            "def f(account):\n"
            "    account.status = 'active'  # fsm-bypass: plain CharField\n"
            "    Model.objects.filter(pk=1).update(  # fsm-bypass: plain CharField\n"
            "        status='failed',\n"
            "    )\n"
        )
        self.assertEqual(self._scan_service_file("apps/billing/tasks.py", source), [])

    def test_a_comment_only_line_above_the_statement_also_passes(self) -> None:
        source = (
            "def f(account):\n"
            "    # fsm-bypass: plain CharField\n"
            "    account.status = (\n"
            "        'active'\n"
            "    )\n"
        )
        self.assertEqual(self._scan_service_file("apps/billing/tasks.py", source), [])
