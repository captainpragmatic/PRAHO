"""Tests for the ADR-0007 cross-app model import guard."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from django.test import SimpleTestCase

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SCRIPTS_DIR = str(_REPO_ROOT / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import lint_cross_app_model_imports as lint  # noqa: E402


class CrossAppModelImportLintTests(SimpleTestCase):
    def test_module_level_cross_app_model_imports_are_reported_per_symbol(self) -> None:
        violations = lint.scan_source(
            "from apps.billing.models import Currency, Invoice\n",
            Path("services/platform/apps/customers/views.py"),
        )

        self.assertEqual(
            [violation.key for violation in violations],
            [
                "services/platform/apps/customers/views.py|apps.billing.models|Currency",
                "services/platform/apps/customers/views.py|apps.billing.models|Invoice",
            ],
        )

    def test_split_model_modules_and_import_syntax_are_reported(self) -> None:
        violations = lint.scan_source(
            "import apps.provisioning.service_models as service_models\n"
            "from apps.customers import contact_models\n",
            Path("services/platform/apps/orders/services.py"),
        )

        self.assertEqual(len(violations), 2)
        self.assertEqual(
            {violation.imported_module for violation in violations},
            {"apps.customers.contact_models", "apps.provisioning.service_models"},
        )

    def test_adr_compliant_imports_are_ignored(self) -> None:
        source = """
from typing import TYPE_CHECKING
from apps.customers.models import Customer

if TYPE_CHECKING:
    from apps.billing.models import Invoice

def load_invoice():
    from apps.billing.models import Invoice
    return Invoice
"""

        violations = lint.scan_source(source, Path("services/platform/apps/customers/services.py"))

        self.assertEqual(violations, [])

    def test_composition_roots_and_management_commands_are_exempt(self) -> None:
        source = "from apps.billing.models import Invoice\n"

        self.assertEqual(
            lint.scan_source(source, Path("services/platform/apps/api/billing/views.py")),
            [],
        )
        self.assertEqual(
            lint.scan_source(
                source,
                Path("services/platform/apps/common/management/commands/generate_sample_data.py"),
            ),
            [],
        )

    def test_baseline_suppresses_only_the_exact_legacy_dependency(self) -> None:
        violations = lint.scan_source(
            "from apps.billing.models import Currency, Invoice\n",
            Path("services/platform/apps/customers/views.py"),
        )

        new_violations, stale = lint.compare_baseline(
            violations,
            {"services/platform/apps/customers/views.py|apps.billing.models|Invoice"},
        )

        self.assertEqual([violation.imported_name for violation in new_violations], ["Currency"])
        self.assertEqual(stale, [])

    def test_baseline_drift_reports_new_and_stale_entries(self) -> None:
        violations = lint.scan_source(
            "from apps.billing.models import Currency\n",
            Path("services/platform/apps/customers/views.py"),
        )

        new, stale = lint.compare_baseline(
            violations,
            {"services/platform/apps/customers/views.py|apps.billing.models|Invoice"},
        )

        self.assertEqual([violation.imported_name for violation in new], ["Currency"])
        self.assertEqual(stale, ["services/platform/apps/customers/views.py|apps.billing.models|Invoice"])


class ViolationMessageTests(SimpleTestCase):
    """The error message must name the dependency without duplicating the
    trailing segment for module-style imports (review of #373)."""

    def test_module_import_message_has_no_duplicated_segment(self) -> None:
        violations = lint.scan_source(
            "import apps.provisioning.service_models\n",
            Path("services/platform/apps/billing/services.py"),
        )
        self.assertEqual(len(violations), 1)
        message = lint.format_violation(violations[0])
        self.assertIn("apps.provisioning.service_models", message)
        self.assertNotIn("service_models.service_models", message)

    def test_symbol_import_message_names_module_and_symbol(self) -> None:
        violations = lint.scan_source(
            "from apps.provisioning.service_models import Service\n",
            Path("services/platform/apps/billing/services.py"),
        )
        self.assertEqual(len(violations), 1)
        message = lint.format_violation(violations[0])
        self.assertIn("apps.provisioning.service_models.Service", message)


class PreCommitCoverageTests(SimpleTestCase):
    """Editing the guard or its baseline must itself trigger the guard hook
    (review of #373): a weakened script or hand-edited baseline should not
    slip through a commit that touches nothing under apps/."""

    def test_hook_matcher_covers_the_guard_and_its_baseline(self) -> None:
        config = (_REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        match = re.search(
            r"id: cross-app-model-import-check.*?files: (?P<pattern>\S+)", config, flags=re.S
        )
        self.assertIsNotNone(match, "the cross-app hook must declare a files matcher")
        pattern = match.group("pattern")
        for covered in (
            "services/platform/apps/billing/services.py",
            "scripts/lint_cross_app_model_imports.py",
            "scripts/cross_app_model_imports_baseline.txt",
        ):
            self.assertIsNotNone(re.match(pattern, covered), f"matcher must cover {covered}")
