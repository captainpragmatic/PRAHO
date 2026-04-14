"""Data migration: clean up invalid staff_role values.

- Sets staff_role="" where staff_role="customer" (invalid value that caused security hole)
- Sets staff_role="admin" on superusers with empty staff_role (ensures is_staff_user consistency)
"""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError


def fix_staff_role_data(apps, schema_editor):
    User = apps.get_model("users", "User")

    # Fix customers incorrectly marked with staff_role="customer"
    updated_customers = User.objects.filter(staff_role="customer").update(staff_role="")

    # Fix superusers with empty staff_role
    updated_superusers = User.objects.filter(
        is_superuser=True, staff_role=""
    ).update(staff_role="admin")

    if updated_customers or updated_superusers:
        print(
            f"\n  Fixed staff_role: {updated_customers} customer(s) cleared, "
            f"{updated_superusers} superuser(s) set to 'admin'"
        )


def reverse_fix(apps, schema_editor):
    raise IrreversibleError("Migration 0002_fix_staff_role_data cannot be reversed — staff_role cleanup is a security fix")


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(fix_staff_role_data, reverse_fix),
    ]
