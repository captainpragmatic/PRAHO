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
