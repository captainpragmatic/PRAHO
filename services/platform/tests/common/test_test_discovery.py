"""Prevent passing suites that silently omit non-package test directories."""

from pathlib import Path

from django.test import SimpleTestCase


class DjangoTestDiscoveryTests(SimpleTestCase):
    def test_all_platform_test_directories_are_discoverable_packages(self):
        root = Path(__file__).resolve().parents[1]
        missing = set()
        for test_file in root.rglob("test_*.py"):
            for directory in test_file.relative_to(root).parents:
                package = root / directory
                if not (package / "__init__.py").is_file():
                    missing.add(str(directory))
        self.assertEqual(missing, set(), "Django silently omits directories without __init__.py")
