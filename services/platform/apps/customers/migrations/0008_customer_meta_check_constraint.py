"""Add CHECK constraint to ensure Customer.meta is always a JSON object (dict).

Belt-and-suspenders enforcement alongside the app-level save() guard.
Prevents non-dict values from being written at the database level.
PostgreSQL only — SQLite lacks jsonb_typeof and ALTER TABLE ADD CONSTRAINT.
"""

from django.db import migrations


def add_meta_check_constraint(apps, schema_editor):
    """Add jsonb CHECK constraint on PostgreSQL only."""
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE customers ADD CONSTRAINT customer_meta_is_object "
        "CHECK (jsonb_typeof(meta) = 'object');"
    )


def remove_meta_check_constraint(apps, schema_editor):
    """Remove jsonb CHECK constraint on PostgreSQL only."""
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        "ALTER TABLE customers DROP CONSTRAINT IF EXISTS customer_meta_is_object;"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0007_alter_customer_managers_and_more"),
    ]

    operations = [
        migrations.RunPython(
            code=add_meta_check_constraint,
            reverse_code=remove_meta_check_constraint,
        ),
    ]
