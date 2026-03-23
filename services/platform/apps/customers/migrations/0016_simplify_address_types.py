"""Simplify address types to primary + billing only.

Converts existing delivery/legal addresses:
- delivery → billing (if no billing exists for that customer, else soft-delete)
- legal → primary (if no primary exists for that customer, else soft-delete)

INTENTIONALLY IRREVERSIBLE: address type semantics changed.
"""

from django.db import migrations


def simplify_address_types(apps, schema_editor):
    """Convert delivery→billing and legal→primary, soft-deleting duplicates."""
    # Raw SQL because SoftDeleteManager lacks use_in_migrations=True
    # Use CURRENT_TIMESTAMP instead of NOW() for SQLite/PostgreSQL compatibility.
    # delivery → billing (if no current billing exists for that customer)
    with schema_editor.connection.cursor() as cursor:
        # Update delivery addresses to billing where no current billing exists
        cursor.execute("""
            UPDATE customer_addresses
            SET address_type = 'billing'
            WHERE address_type = 'delivery'
              AND deleted_at IS NULL
              AND customer_id NOT IN (
                  SELECT customer_id FROM customer_addresses
                  WHERE address_type = 'billing' AND is_current = TRUE AND deleted_at IS NULL
              )
        """)
        # Soft-delete remaining delivery addresses (customer already has billing)
        cursor.execute("""
            UPDATE customer_addresses
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE address_type = 'delivery' AND deleted_at IS NULL
        """)

        # legal → primary (if no current primary exists for that customer)
        cursor.execute("""
            UPDATE customer_addresses
            SET address_type = 'primary'
            WHERE address_type = 'legal'
              AND deleted_at IS NULL
              AND customer_id NOT IN (
                  SELECT customer_id FROM customer_addresses
                  WHERE address_type = 'primary' AND is_current = TRUE AND deleted_at IS NULL
              )
        """)
        # Soft-delete remaining legal addresses
        cursor.execute("""
            UPDATE customer_addresses
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE address_type = 'legal' AND deleted_at IS NULL
        """)


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0015_remove_invoice_delivery_method"),
    ]

    operations = [
        migrations.RunPython(simplify_address_types, migrations.RunPython.noop),
    ]
