"""
Replace address_type CharField with boolean flags is_primary, is_billing, and label.

Data migration logic:
- address_type="primary" → is_primary=True, is_billing=True  (single address = both roles)
- address_type="billing" → is_billing=True
- For customers with only ONE non-deleted address (regardless of type) → set both flags

INTENTIONALLY NOT REVERSIBLE for the data migration (RunPython.noop).
"""

from django.db import migrations, models


def migrate_address_type_to_flags(apps, schema_editor):
    """Convert address_type string values to is_primary / is_billing boolean flags."""
    with schema_editor.connection.cursor() as cursor:
        # Step 1: primary → is_primary=True, is_billing=True
        cursor.execute("""
            UPDATE customer_addresses
            SET is_primary = TRUE, is_billing = TRUE
            WHERE address_type = 'primary'
              AND deleted_at IS NULL
        """)

        # Step 2: billing → is_billing=True (is_primary stays FALSE)
        cursor.execute("""
            UPDATE customer_addresses
            SET is_billing = TRUE
            WHERE address_type = 'billing'
              AND deleted_at IS NULL
        """)

        # Step 3: Customers with only ONE active address (any type) → both flags
        # This handles edge cases such as solo 'legal' or 'delivery' addresses that
        # survived the 0016 migration as primary/billing, or any remaining types.
        cursor.execute("""
            UPDATE customer_addresses
            SET is_primary = TRUE, is_billing = TRUE
            WHERE deleted_at IS NULL
              AND customer_id IN (
                  SELECT customer_id
                  FROM customer_addresses
                  WHERE deleted_at IS NULL
                  GROUP BY customer_id
                  HAVING COUNT(*) = 1
              )
        """)


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0016_simplify_address_types"),
    ]

    operations = [
        # Step 1: Add new boolean fields with defaults
        migrations.AddField(
            model_name="customeraddress",
            name="is_primary",
            field=models.BooleanField(default=False, verbose_name="Adresa principală"),
        ),
        migrations.AddField(
            model_name="customeraddress",
            name="is_billing",
            field=models.BooleanField(default=False, verbose_name="Adresa facturare"),
        ),
        migrations.AddField(
            model_name="customeraddress",
            name="label",
            field=models.CharField(blank=True, max_length=50, verbose_name="Etichetă"),
        ),
        # Step 2: Data migration
        migrations.RunPython(migrate_address_type_to_flags, migrations.RunPython.noop),
        # Step 3: Remove old unique constraint and indexes BEFORE dropping the column.
        # SQLite validates constraints/indexes on column removal; removing them first avoids
        # "no such column: address_type" errors in the constraint definition.
        migrations.RemoveConstraint(
            model_name="customeraddress",
            name="unique_current_address_per_type",
        ),
        migrations.RemoveIndex(
            model_name="customeraddress",
            name="customer_ad_custome_7e9853_idx",  # (customer, address_type) plain index
        ),
        migrations.RemoveIndex(
            model_name="customeraddress",
            name="addr_cust_type_active_idx",  # partial index on (customer, address_type)
        ),
        # Step 4: Remove the old address_type field (constraint + indexes already gone)
        migrations.RemoveField(
            model_name="customeraddress",
            name="address_type",
        ),
        # Step 6: Add new indexes on boolean flags (partial: active addresses only)
        migrations.AddIndex(
            model_name="customeraddress",
            index=models.Index(
                fields=["customer", "is_primary"],
                condition=models.Q(deleted_at__isnull=True),
                name="addr_cust_primary_active_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="customeraddress",
            index=models.Index(
                fields=["customer", "is_billing"],
                condition=models.Q(deleted_at__isnull=True),
                name="addr_cust_billing_active_idx",
            ),
        ),
        # Plain (non-partial) indexes for full-table queries
        migrations.AddIndex(
            model_name="customeraddress",
            index=models.Index(fields=["customer", "is_primary"], name="addr_cust_is_primary_idx"),
        ),
        migrations.AddIndex(
            model_name="customeraddress",
            index=models.Index(fields=["customer", "is_billing"], name="addr_cust_is_billing_idx"),
        ),
    ]
