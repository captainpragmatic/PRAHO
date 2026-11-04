from importlib import import_module

from django.db import migrations, models

restore_server_identity_guard = import_module(
    "apps.provisioning.migrations.0015_ssh_transport_state"
).restore_server_identity_guard


class Migration(migrations.Migration):
    dependencies = [("provisioning", "0028_component_migration_authority")]

    operations = [
        # SQLite rebuilds this table for these columns, dropping its identity guard.
        # Restore it after the schema changes in either migration direction.
        migrations.RunPython(migrations.RunPython.noop, restore_server_identity_guard),
        migrations.AddField(
            model_name="virtualminserver",
            name="security_policy_version",
            field=models.CharField(default="virtualmin-web-only-v2", editable=False, max_length=40),
        ),
        migrations.AddField(
            model_name="virtualminserver",
            name="security_configuration_digest",
            field=models.CharField(blank=True, default="", editable=False, max_length=64),
        ),
        migrations.RunPython(restore_server_identity_guard, migrations.RunPython.noop),
    ]
