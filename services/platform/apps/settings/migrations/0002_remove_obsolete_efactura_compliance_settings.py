"""Remove obsolete gates for mandatory Romanian B2B and B2C e-Factura."""

from django.db import migrations

OBSOLETE_SETTING_KEYS = (
    "billing.efactura_minimum_amount_cents",
    "efactura.b2b.minimum_amount_cents",
    "efactura.b2c.enabled",
    "efactura.b2c.minimum_amount_cents",
)


def remove_obsolete_efactura_compliance_settings(apps, schema_editor) -> None:
    """Delete settings that could suppress legally mandatory submissions."""
    system_setting = apps.get_model("settings", "SystemSetting")
    system_setting.objects.filter(key__in=OBSOLETE_SETTING_KEYS).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0001_initial"),
    ]

    operations = [
        # Intentionally irreversible: rolling back code must not restore a
        # compliance control that can suppress mandatory B2B/B2C submissions.
        migrations.RunPython(
            remove_obsolete_efactura_compliance_settings,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
