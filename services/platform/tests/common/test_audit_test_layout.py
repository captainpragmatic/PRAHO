"""Filename policy is applied to complete tokens by the layout audit."""

import sys
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[4] / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import audit_test_layout  # noqa: E402


class AuditTestLayoutNamesTests(TestCase):
    def test_filename_tokens_are_classified_by_the_audit(self) -> None:
        cases = {
            "test_fixed_window.py": False,
            "test_vat_rounding.py": False,
            "test_fixtures.py": False,
            "test_prefix.py": False,
            "test_bugfix.py": False,
            "test_roundtrip.py": False,
            "test_fixes.py": True,
            "test_hotfixes.py": True,
            "test_fix_round2.py": True,
            "test_misc_helpers.py": True,
            "test_coverage_report.py": True,
            "test_FIXUP.py": True,
            "test_todos.py": True,
            "test_basics.py": True,
            "test_rounds.py": True,
        }
        for name, flagged in cases.items():
            with self.subTest(name=name):
                path = audit_test_layout.PROJECT_ROOT / "tests" / name
                with patch.object(audit_test_layout, "iter_test_files", return_value=[path]):
                    result = audit_test_layout.scan(audit_test_layout.DEFAULT_ALLOWLIST_PATH)
                expected = [f"tests/{name}"] if flagged else []
                self.assertEqual(result["suspicious_filenames"], expected)
                self.assertEqual(result["summary"]["suspiciously_named_files"], int(flagged))


class AuditTestLayoutPlacementTests(TestCase):
    """A test module under an app package is run by no gate: every suite runs only its tests/ root."""

    def test_test_modules_under_app_packages_are_reported_and_fail_strict(self) -> None:
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "apps"
            (app_root / "billing" / "tests").mkdir(parents=True)
            (app_root / "billing" / "tests" / "test_invoices.py").write_text("def test_x():\n    pass\n")
            (app_root / "billing" / "helpers.py").write_text("")
            # A management command named test_* and a startapp placeholder define no test: not reported.
            (app_root / "billing" / "management" / "commands").mkdir(parents=True)
            (app_root / "billing" / "management" / "commands" / "test_gateway.py").write_text(
                "class Command:\n    def handle(self):\n        pass\n"
            )
            (app_root / "billing" / "tests.py").write_text("# Create your tests here.\n")
            with (
                patch.object(audit_test_layout, "APP_ROOTS", [app_root]),
                patch.object(audit_test_layout, "iter_test_files", return_value=[]),
            ):
                result = audit_test_layout.scan(audit_test_layout.DEFAULT_ALLOWLIST_PATH)
                with patch.object(sys, "argv", ["audit_test_layout.py", "--strict", "--json"]), patch("builtins.print"):
                    exit_code = audit_test_layout.main()
        self.assertEqual(result["summary"]["test_files_outside_test_roots"], 1)
        self.assertEqual(len(result["test_files_outside_test_roots"]), 1)
        self.assertTrue(result["test_files_outside_test_roots"][0].endswith("billing/tests/test_invoices.py"))
        self.assertEqual(exit_code, 1)

    def test_a_tests_module_with_a_test_case_is_reported(self) -> None:
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "apps"
            (app_root / "orders").mkdir(parents=True)
            (app_root / "orders" / "tests.py").write_text(
                "from django.test import TestCase\n\nclass OrderTests(TestCase):\n    def test_total(self):\n        pass\n"
            )
            with patch.object(audit_test_layout, "APP_ROOTS", [app_root]):
                misplaced = audit_test_layout.iter_misplaced_test_files()
        self.assertEqual([path.name for path in misplaced], ["tests.py"])

    def test_every_runner_discovery_pattern_is_covered(self) -> None:
        """Django collects test*.py; pytest also collects *_test.py and *_tests.py (pytest.ini)."""
        import tempfile  # noqa: PLC0415

        test_body = "def test_total():\n    pass\n"
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "apps" / "billing"
            app_root.mkdir(parents=True)
            for name in ("test_totals.py", "invoice_test.py", "invoice_tests.py", "helpers.py"):
                (app_root / name).write_text(test_body)
            with patch.object(audit_test_layout, "APP_ROOTS", [app_root.parent]):
                misplaced = sorted(path.name for path in audit_test_layout.iter_misplaced_test_files())
        # helpers.py is collected by no runner anywhere, so it is not a placement problem.
        self.assertEqual(misplaced, ["invoice_test.py", "invoice_tests.py", "test_totals.py"])

    def test_no_app_package_holds_a_test_module(self) -> None:
        misplaced = [str(path) for path in audit_test_layout.iter_misplaced_test_files()]
        self.assertEqual(misplaced, [], "move these into the service's tests/ tree (ADR-0011)")
