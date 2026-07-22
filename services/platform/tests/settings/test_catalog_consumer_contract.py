"""
Consumer-contract guardrail (ADR-0042): decoy settings are structurally impossible.

Two invariants, enforced with the same tokenize-based extraction the coverage
lint script uses (comments can never fake consumption):

1. Every catalog key is consumed somewhere in production code or templates.
2. Every key passed to a SettingsService read call is declared in the catalog.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.key_scan import (
    extract_settings_call_keys,
    extract_string_literals,
    iter_scannable_python_files,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
APPS_ROOT = PLATFORM_ROOT / "apps"
TEMPLATE_ROOTS = (
    PLATFORM_ROOT / "templates",
    PLATFORM_ROOT.parents[1] / "shared" / "ui" / "templates",
)

# Keys kept without a scannable consumer — every entry needs a justification
CONSUMER_EXEMPTIONS: dict[str, str] = {}

# Read-call keys allowed to stay outside the catalog — every entry needs a justification
CATALOG_EXEMPTIONS: dict[str, str] = {}


def _production_python_files() -> list[Path]:
    return [
        path
        for path in iter_scannable_python_files(APPS_ROOT)
        if path.relative_to(APPS_ROOT).parts[0] != "settings"  # settings machinery is not a consumer
    ]


class ConsumerContractTests(SimpleTestCase):
    """Static-scan invariants — no database needed."""

    literal_corpus: set[str]
    consumed_keys: set[str]
    template_corpus: str

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.literal_corpus = set()
        cls.consumed_keys = set()
        for path in _production_python_files():
            cls.literal_corpus |= extract_string_literals(path)
            cls.consumed_keys |= extract_settings_call_keys(path)
        template_parts: list[str] = []
        for root in TEMPLATE_ROOTS:
            for html in sorted(root.rglob("*.html")):
                if "templates/settings" in str(html):
                    continue
                template_parts.append(html.read_text(errors="ignore"))
        cls.template_corpus = "\n".join(template_parts)

    def test_every_catalog_key_has_a_consumer(self) -> None:
        """A key nobody reads is a decoy — it must be wired or retired, never shipped."""
        orphans = [
            key
            for key in CATALOG_BY_KEY
            if key not in CONSUMER_EXEMPTIONS
            and key not in self.literal_corpus
            and key not in self.template_corpus
        ]
        self.assertEqual(
            orphans,
            [],
            f"Catalog keys with no consumer in apps/ or templates/: {orphans}. "
            "Wire them, retire them, or add a justified CONSUMER_EXEMPTIONS entry.",
        )

    def test_every_consumed_key_is_in_catalog(self) -> None:
        """Reading an undeclared key silently falls back — declare it in the catalog."""
        undeclared = sorted(
            key for key in self.consumed_keys if key not in CATALOG_BY_KEY and key not in CATALOG_EXEMPTIONS
        )
        self.assertEqual(
            undeclared,
            [],
            f"SettingsService reads for keys missing from the catalog: {undeclared}. "
            "Declare them in apps/settings/catalog.py or add a justified CATALOG_EXEMPTIONS entry.",
        )

    def test_exemption_lists_stay_honest(self) -> None:
        """Exempted keys must still exist in the catalog (stale exemptions rot the guardrail)."""
        for key in CONSUMER_EXEMPTIONS:
            self.assertIn(key, CATALOG_BY_KEY, f"CONSUMER_EXEMPTIONS entry {key} is not a catalog key")
        for key in CATALOG_EXEMPTIONS:
            self.assertNotIn(key, CATALOG_BY_KEY, f"CATALOG_EXEMPTIONS entry {key} is already cataloged")
