"""Delete the audit.file_hash_cache_timeout row: its only consumer was the
cache-based file-integrity baseline mechanism, replaced by durable
FileIntegrityBaseline rows (ADR-0043)."""

from django.db import migrations

DEAD_KEYS = ("audit.file_hash_cache_timeout",)


def _delete_dead_rows(apps, schema_editor):
    system_setting = apps.get_model("settings", "SystemSetting")
    system_setting.objects.filter(key__in=DEAD_KEYS).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0004_delete_settingcategory_and_more"),
    ]

    operations = [
        migrations.RunPython(_delete_dead_rows, migrations.RunPython.noop),
    ]
