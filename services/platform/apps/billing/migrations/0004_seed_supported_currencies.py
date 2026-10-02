"""Seed the supported Currency rows (RON/EUR/USD) — #103.

Staff can select EUR/USD when creating a proforma, so those Currency rows
must exist for the selection to resolve. Idempotent get_or_create preserves
any existing metadata; the reverse is a deliberate no-op (never delete a
currency referenced by issued documents).

Carried forward from billing 0047 of the old history (ADR-0052). On the old
history RON was first created with an empty name by billing 0024, so it kept
that name; a fresh install now names it "Romanian Leu".
"""

from typing import Any

from django.db import migrations

# code, symbol, decimals, name
_SUPPORTED_CURRENCIES = [
    ("RON", "lei", 2, "Romanian Leu"),
    ("EUR", "€", 2, "Euro"),
    ("USD", "$", 2, "US Dollar"),
]


def seed_currencies(apps: Any, schema_editor: Any) -> None:
    Currency = apps.get_model("billing", "Currency")
    for code, symbol, decimals, name in _SUPPORTED_CURRENCIES:
        Currency.objects.get_or_create(
            code=code,
            defaults={"symbol": symbol, "decimals": decimals, "name": name},
        )


def unseed_currencies(apps: Any, schema_editor: Any) -> None:
    # No-op: currencies may be referenced by issued (immutable) documents.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0003_postgres_event_storage_indexes"),
    ]

    operations = [
        migrations.RunPython(seed_currencies, unseed_currencies),
    ]
