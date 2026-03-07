"""Clear encrypted setting values for AES-256-GCM encryption upgrade.

Settings signed with Django Signer (enc:v1: prefix) become unreadable.
Sensitive settings must be re-configured after this migration.
"""

from django.db import migrations


def clear_encrypted_settings(apps, schema_editor):
    """Reset sensitive SystemSettings to their default_value.

    The value column is NOT NULL, so we cannot set it to None.
    Instead, copy default_value back into value so the old encrypted
    data is discarded and the setting falls back to its default.
    """
    SystemSetting = apps.get_model("settings", "SystemSetting")
    sensitive = SystemSetting.objects.filter(is_sensitive=True).exclude(value__isnull=True)
    updated = 0
    for setting in sensitive:
        setting.value = setting.default_value
        setting.save(update_fields=["value"])
        updated += 1
    if updated:
        print(f"\n  Reset {updated} sensitive setting(s) to defaults. Re-configure via admin.")


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0002_rename_invoice_due_days_key"),
    ]

    operations = [
        migrations.RunPython(clear_encrypted_settings, migrations.RunPython.noop),
    ]
