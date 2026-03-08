"""
Zero-downtime fix: recreate meta CHECK constraint with NOT VALID + VALIDATE.

Migration 0008 used ADD CONSTRAINT without NOT VALID, which acquires
ACCESS EXCLUSIVE lock and scans the entire table. This migration:
1. Drops the blocking constraint from 0008
2. Re-adds it with NOT VALID (instant, no table scan)
3. Validates it separately (SHARE UPDATE EXCLUSIVE lock — allows concurrent reads/writes)
"""

from django.db import migrations


def add_meta_check_not_valid(apps, schema_editor):
    """Drop and recreate constraint with NOT VALID (PostgreSQL only)."""
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE customers DROP CONSTRAINT IF EXISTS customer_meta_is_object;"
    )
    schema_editor.execute(
        "ALTER TABLE customers ADD CONSTRAINT customer_meta_is_object "
        "CHECK (jsonb_typeof(meta) = 'object') NOT VALID;"
    )


def validate_meta_check(apps, schema_editor):
    """Validate the constraint in a separate step (allows concurrent DML)."""
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE customers VALIDATE CONSTRAINT customer_meta_is_object;"
    )


def reverse_migration(apps, schema_editor):
    """Reverse: drop the constraint entirely."""
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE customers DROP CONSTRAINT IF EXISTS customer_meta_is_object;"
    )


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0008_customer_meta_check_constraint"),
    ]

    operations = [
        migrations.RunPython(add_meta_check_not_valid, reverse_code=reverse_migration),
        migrations.RunPython(validate_meta_check, reverse_code=migrations.RunPython.noop),
    ]
