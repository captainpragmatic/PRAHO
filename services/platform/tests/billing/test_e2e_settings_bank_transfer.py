"""config.settings.e2e must configure a RON bank account, or every bank-transfer
checkout in the e2e/Playwright suite renders no IBAN - bank_transfer_instructions()
silently returns None whenever COMPANY_BANK_ACCOUNT/COMPANY_BANK_NAME are unset,
and the confirmation page has no error path for that; it just omits the section.

Reads the settings module's source with ast instead of importing it: e2e.py runs
`from .dev import *` then mutates the inherited MIDDLEWARE list in place and sets
process-global os.environ defaults, all as import-time side effects. Importing it
under any other DJANGO_SETTINGS_MODULE (as this suite runs under) leaks those
mutations into every test that runs afterward. Parsing the literal assignments
gets the same regression protection - a future edit that removes or empties either
setting still fails this test - without executing the module at all.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from apps.billing.bank_transfer import bank_transfer_instructions

_E2E_SETTINGS_PATH = Path(__file__).resolve().parents[2] / "config" / "settings" / "e2e.py"


def _read_string_assignment(name: str) -> str:
    tree = ast.parse(_E2E_SETTINGS_PATH.read_text())
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise AssertionError(f"config/settings/e2e.py has no top-level string assignment named {name!r}")


class E2ESettingsBankTransferTests(SimpleTestCase):
    @override_settings(
        COMPANY_BANK_ACCOUNT=_read_string_assignment("COMPANY_BANK_ACCOUNT"),
        COMPANY_BANK_NAME=_read_string_assignment("COMPANY_BANK_NAME"),
        COMPANY_NAME=_read_string_assignment("COMPANY_NAME"),
    )
    def test_e2e_settings_produce_the_iban_the_browser_suite_expects(self) -> None:
        with patch("apps.settings.services.SettingsService.get_setting", return_value={}):
            instructions = bank_transfer_instructions("RON")

        self.assertIsNotNone(
            instructions,
            "bank_transfer_instructions('RON') returned None under config.settings.e2e's own "
            "COMPANY_BANK_ACCOUNT/COMPANY_BANK_NAME - the e2e settings module must set both to "
            "non-empty values, or the Playwright bank-transfer checkout tests render no IBAN.",
        )
        assert instructions is not None
        # The exact value tests/e2e/helpers/orders.py:bank_checkout asserts on the confirmation
        # page - a differently-shaped but still-valid IBAN would pass a weaker assertion here
        # while still breaking those four browser tests.
        self.assertEqual(instructions["iban"], "RO49AAAA1B31007593840000")
        self.assertTrue(instructions["bank_name"])
