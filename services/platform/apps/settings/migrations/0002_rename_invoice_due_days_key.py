"""
Data migration: rename billing.invoice_due_days → billing.invoice_payment_terms_days.

Preserves any admin-customized value from the old key.
"""
from django.db import migrations


def rename_setting_key(apps, schema_editor):
    """Rename the old SettingsService key to the new canonical name."""
    SystemSetting = apps.get_model("settings", "SystemSetting")
    SystemSetting.objects.filter(key="billing.invoice_due_days").update(
        key="billing.invoice_payment_terms_days"
    )


def revert_setting_key(apps, schema_editor):
    """Revert the key rename."""
    SystemSetting = apps.get_model("settings", "SystemSetting")
    SystemSetting.objects.filter(key="billing.invoice_payment_terms_days").update(
        key="billing.invoice_due_days"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("settings", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(rename_setting_key, revert_setting_key),
    ]
