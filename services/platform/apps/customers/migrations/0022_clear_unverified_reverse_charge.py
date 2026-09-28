"""Clear legacy reverse-charge flags that have no VIES confirmation."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


def clear_unverified_reverse_charge(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    """Retain flags only for VIES-valid profiles without firing model signals."""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "UPDATE customer_tax_profiles SET reverse_charge_eligible = %s WHERE vies_verification_status <> %s",
            (False, "valid"),
        )


class Migration(migrations.Migration):
    dependencies = [("customers", "0021_repair_address_billing_flags")]

    operations = [
        migrations.RunPython(clear_unverified_reverse_charge, reverse_code=migrations.RunPython.noop),
    ]
