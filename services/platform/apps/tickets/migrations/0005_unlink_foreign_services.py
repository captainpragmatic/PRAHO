"""Remove ticket service links that cross customer boundaries."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


def unlink_foreign_services(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    """Repair legacy links without firing ticket lifecycle signals."""
    quote_name = schema_editor.connection.ops.quote_name
    tickets_table = quote_name(apps.get_model("tickets", "Ticket")._meta.db_table)
    services_table = quote_name(apps.get_model("provisioning", "Service")._meta.db_table)
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {tickets_table} SET related_service_id = NULL "  # noqa: S608 -- quoted migration table names
            f"WHERE related_service_id IN (SELECT s.id FROM {services_table} s "
            f"WHERE s.customer_id <> {tickets_table}.customer_id)"
        )


class Migration(migrations.Migration):
    dependencies = [("tickets", "0004_alter_ticket_assigned_to")]

    operations = [
        migrations.RunPython(unlink_foreign_services, reverse_code=migrations.RunPython.noop),
    ]
