"""Reconcile legacy refund metadata that migration 0024 left behind.

The original 0024 migration removed metadata after creating at least one row,
so multiplicity already erased from that JSON cannot be reconstructed here.
This repair safely processes evidence that remains and fixes 0024 itself for
fresh installations.
"""

from importlib import import_module

from django.db import migrations


def recover_remaining_legacy_refunds(apps, schema_editor):
    migration_0024 = import_module(
        "apps.billing.migrations.0024_backfill_refunds_from_meta"
    )
    migration_0024.backfill_refunds_from_meta(apps, schema_editor)


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0040_efactura_submission_integrity"),
    ]

    operations = [
        migrations.RunPython(
            recover_remaining_legacy_refunds,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
