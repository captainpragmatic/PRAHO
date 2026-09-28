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
