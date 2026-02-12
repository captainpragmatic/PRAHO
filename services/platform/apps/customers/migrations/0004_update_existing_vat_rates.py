"""Data migration: update existing CustomerTaxProfile records from 19% to 21%.

Migration 0003 changed the MODEL DEFAULT but didn't touch existing rows.
Customers who were created with the old 19% default should be updated to 21%
so their future invoices use the correct current rate.

Note: This is safe because 19.00 was always the auto-generated default,
never a meaningful per-customer override. Customers with actual custom rates
(e.g., 15.00 for a special agreement) are NOT affected.

Uses raw SQL because the SoftDeleteManager on CustomerTaxProfile doesn't have
use_in_migrations=True, making .objects unavailable in historical model state.

Reverse: noop — we cannot distinguish rows that were 21.00 before this migration
from rows we updated. A blanket revert to 19.00 would corrupt legitimate data.
If you need to revert, restore from a database backup taken before this migration.

Romanian VAT: 19% → 21% effective August 1, 2025 (Emergency Ordinance 156/2024).
"""

from django.db import migrations


def update_stale_vat_rates(apps, schema_editor):
    """Update CustomerTaxProfile records still at the old 19% default."""
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE customer_tax_profiles SET vat_rate = 21.00 WHERE vat_rate = 19.00"
        )
        updated = cursor.rowcount
    if updated:
        print(f"  Updated {updated} CustomerTaxProfile record(s) from 19% to 21%")


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0003_update_vat_rate_default"),
    ]

    operations = [
        migrations.RunPython(
            update_stale_vat_rates,
            # Reverse is noop: we can't safely distinguish rows we updated
            # from rows that were already 21.00. Restore from backup if needed.
            reverse_code=migrations.RunPython.noop,
        ),
    ]
