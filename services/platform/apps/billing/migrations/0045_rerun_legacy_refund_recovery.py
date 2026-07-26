"""Re-run legacy refund recovery with corrected amount-pool multiplicity.

The original pool counted completed gateway-ID rows that ID entries in the
same metadata also consumed, so one physical row could satisfy two distinct
legacy entries and the no-ID entry was dropped without a Refund row. The
corrected 0024 logic excludes ID-consumed rows from the amount pool; this
re-run processes any meta.refunds evidence still present. Evidence already
removed by the earlier pass cannot be reconstructed and stays subject to
manual gateway reconciliation.
"""

from importlib import import_module

from django.db import migrations


def rerun_legacy_refund_recovery(apps, schema_editor):
    migration_0024 = import_module(
        "apps.billing.migrations.0024_backfill_refunds_from_meta"
    )
    migration_0024.backfill_refunds_from_meta(apps, schema_editor)


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0044_recurring_payment_submission"),
    ]

    operations = [
        migrations.RunPython(
            rerun_legacy_refund_recovery,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
