"""
Test that every template_key referenced in signals/tasks matches a key
defined in the setup_email_templates management command.

Catches mismatches like ``template_key="order_confirmation"`` when the
actual template is registered as ``"order_placed"``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from django.test import SimpleTestCase

PLATFORM_DIR = Path(__file__).resolve().parent.parent.parent


def _extract_setup_template_keys() -> set[str]:
    """Parse the setup_email_templates command and extract all template keys."""
    setup_file = PLATFORM_DIR / "apps/notifications/management/commands/setup_email_templates.py"
    source = setup_file.read_text()
    # Keys appear as "key": "some_key" in dict literals
    return set(re.findall(r'"key":\s*"(\w+)"', source))


def _extract_signal_template_keys() -> list[tuple[str, str, int]]:
    """Find all template_key="..." usages in signals and tasks files.

    Returns [(file_path, key, line_number), ...]
    """
    results: list[tuple[str, str, int]] = []
    for pattern in ("apps/*/signals.py", "apps/*/tasks.py"):
        for filepath in PLATFORM_DIR.glob(pattern):
            tree = ast.parse(filepath.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.keyword):
                    continue
                if node.arg == "template_key" and isinstance(node.value, ast.Constant):
                    results.append((str(filepath.relative_to(PLATFORM_DIR)), node.value.value, node.value.lineno))
    return results


class TestTemplateKeyConsistency(SimpleTestCase):
    """Every template_key used in signals/tasks must exist in setup_email_templates."""

    def test_all_signal_template_keys_are_registered(self) -> None:
        registered_keys = _extract_setup_template_keys()
        usages = _extract_signal_template_keys()

        self.assertGreater(len(registered_keys), 0, "No template keys found in setup command")
        self.assertGreater(len(usages), 0, "No template_key= usages found in signals/tasks")

        missing = []
        for filepath, key, lineno in usages:
            if key not in registered_keys:
                missing.append(f'  {filepath}:{lineno} — template_key="{key}" not in setup_email_templates')

        self.assertEqual(
            missing,
            [],
            "Template keys referenced but not registered:\n" + "\n".join(missing),
        )
