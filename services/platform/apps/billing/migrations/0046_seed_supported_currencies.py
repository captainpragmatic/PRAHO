"""Seed the supported Currency rows (RON/EUR/USD) — #103.

Only RON was guaranteed in production (migration 0024 creates it on demand);
EUR/USD rows existed only in dev/sample data. Staff can select EUR/USD when
creating a proforma, so those Currency rows must exist for the selection to
resolve. Idempotent get_or_create preserves any existing metadata; the reverse
is a deliberate no-op (never delete a currency referenced by issued documents).
"""

from __future__ import annotations

from django.db import migrations

# code, symbol, decimals, name
_SUPPORTED_CURRENCIES = [
    ("RON", "lei", 2, "Romanian Leu"),
    ("EUR", "€", 2, "Euro"),
    ("USD", "$", 2, "US Dollar"),
]


def seed_currencies(apps, schema_editor):
    Currency = apps.get_model("billing", "Currency")
    for code, symbol, decimals, name in _SUPPORTED_CURRENCIES:
        Currency.objects.get_or_create(
            code=code,
            defaults={"symbol": symbol, "decimals": decimals, "name": name},
        )


def unseed_currencies(apps, schema_editor):
    # No-op: currencies may be referenced by issued (immutable) documents.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0045_rerun_legacy_refund_recovery"),
    ]

    operations = [
        migrations.RunPython(seed_currencies, unseed_currencies),
    ]
