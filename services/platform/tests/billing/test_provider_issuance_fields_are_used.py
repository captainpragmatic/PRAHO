"""Every ProviderIssuance column is read or written somewhere outside its own definition.

Two forensic columns were declared for a feature that never wrote them. Nothing read them
either, so they only stored empty strings. A column nobody touches misleads the next reader
into thinking the data exists, so this fails when one appears.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

from apps.billing.issuers.models import ProviderIssuance

APPS = Path(__file__).resolve().parents[2] / "apps"
OWN_DEFINITION = APPS / "billing" / "issuers" / "models.py"


def _sources() -> str:
    parts = []
    for path in APPS.rglob("*.py"):
        if path == OWN_DEFINITION or "migrations" in path.parts:
            continue
        parts.append(path.read_text())
    return "\n".join(parts)


class ProviderIssuanceFieldUsageTests(SimpleTestCase):
    def test_every_column_is_used_outside_its_definition(self) -> None:
        source = _sources()
        names = [field.name for field in ProviderIssuance._meta.concrete_fields]
        self.assertIn("request_hash", names, "the scan must see the model's real columns")

        unused = [name for name in names if not re.search(rf"\b{re.escape(name)}\b", source)]

        self.assertEqual(unused, [], f"columns nothing reads or writes: {unused}")
