"""Repair primary addresses incorrectly promoted to billing addresses by 0017."""

from django.db import migrations


def repair_address_billing_flags(apps, schema_editor):
    """Preserve the distinct current billing row when one exists."""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            UPDATE customer_addresses
            SET is_billing = FALSE
            WHERE is_primary = TRUE
              AND is_billing = TRUE
              AND deleted_at IS NULL
              AND EXISTS (
                  SELECT 1
                  FROM customer_addresses AS distinct_billing
                  WHERE distinct_billing.customer_id = customer_addresses.customer_id
                    AND distinct_billing.is_billing = TRUE
                    AND distinct_billing.is_primary = FALSE
                    AND distinct_billing.is_current = TRUE
                    AND distinct_billing.deleted_at IS NULL
              )
        """)


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0019_bind_payment_method_encryption_context"),
    ]

    operations = [
        migrations.RunPython(
            repair_address_billing_flags,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
