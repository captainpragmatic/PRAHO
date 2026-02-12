"""
Data migration: rename billing.invoice_due_days → billing.invoice_payment_terms_days.

Preserves any admin-customized value from the old key.
"""
from django.db import migrations


def rename_setting_key(apps, schema_editor):
    """Rename the old SettingsService key to the new canonical name.

    Handles key collision: if the new key already exists (e.g., pre-created
    manually), the old key's value wins and the duplicate is removed.
    """
    SystemSetting = apps.get_model("settings", "SystemSetting")
    old_key = "billing.invoice_due_days"
    new_key = "billing.invoice_payment_terms_days"

    old_qs = SystemSetting.objects.filter(key=old_key)
    if not old_qs.exists():
        return  # Nothing to rename — idempotent

    if SystemSetting.objects.filter(key=new_key).exists():
        # Collision: preserve old key's (admin-customized) value, drop the old row
        old_setting = old_qs.first()
        SystemSetting.objects.filter(key=new_key).update(value=old_setting.value)
        old_qs.delete()
    else:
        old_qs.update(key=new_key)


def revert_setting_key(apps, schema_editor):
    """Revert the key rename."""
    SystemSetting = apps.get_model("settings", "SystemSetting")
    old_key = "billing.invoice_payment_terms_days"
    new_key = "billing.invoice_due_days"

    old_qs = SystemSetting.objects.filter(key=old_key)
    if not old_qs.exists():
        return

    if SystemSetting.objects.filter(key=new_key).exists():
        old_setting = old_qs.first()
        SystemSetting.objects.filter(key=new_key).update(value=old_setting.value)
        old_qs.delete()
    else:
        old_qs.update(key=new_key)


class Migration(migrations.Migration):

    dependencies = [
        ("settings", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(rename_setting_key, revert_setting_key),
    ]
