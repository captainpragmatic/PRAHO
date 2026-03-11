"""
Zero-downtime fix: recreate all domains CHECK constraints with NOT VALID + VALIDATE.

The standard ADD CONSTRAINT acquires ACCESS EXCLUSIVE lock for the full table scan.
This pattern splits the operation into two steps:
  1. ADD CONSTRAINT ... NOT VALID  — acquires only ShareUpdateExclusiveLock, no scan
  2. VALIDATE CONSTRAINT           — acquires ShareUpdateExclusiveLock, scans but allows reads/writes
"""
from django.db import migrations

_CONSTRAINTS = [
    (
        "domains_domain",
        "domain_status_valid_values",
        "status IN ('pending','active','expired','suspended','transfer_in','transfer_out','cancelled')",
    ),
]


def add_constraints_not_valid(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name};")
        schema_editor.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({expr}) NOT VALID;")


def validate_constraints(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, _expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {name};")


def reverse_migration(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for table, name, _expr in _CONSTRAINTS:
        schema_editor.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name};")


class Migration(migrations.Migration):
    atomic = False

    dependencies = [("domains", "0005_domain_domain_status_valid_values")]

    operations = [
        migrations.RunPython(add_constraints_not_valid, reverse_code=reverse_migration),
        migrations.RunPython(validate_constraints, reverse_code=migrations.RunPython.noop),
    ]
