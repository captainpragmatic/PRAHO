"""Clear encrypted setting values for AES-256-GCM encryption upgrade.

Settings signed with Django Signer (enc:v1: prefix) become unreadable.
Sensitive settings must be re-configured after this migration.
"""

from django.db import migrations


def clear_encrypted_settings(apps, schema_editor):
    """Clear value on sensitive SystemSettings."""
    SystemSetting = apps.get_model("settings", "SystemSetting")
    updated = SystemSetting.objects.filter(is_sensitive=True).exclude(value__isnull=True).update(
        value=None,
    )
    if updated:
        print(f"\n  Cleared {updated} sensitive setting(s). Re-configure via admin.")


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0002_rename_invoice_due_days_key"),
    ]

    operations = [
        migrations.RunPython(clear_encrypted_settings, migrations.RunPython.noop),
    ]
