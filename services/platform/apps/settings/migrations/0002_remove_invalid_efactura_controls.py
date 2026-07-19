from django.db import migrations

INVALID_EFACTURA_CONTROL_KEYS = (
    "billing.efactura_minimum_amount_cents",
    "efactura.b2b.enabled",
    "efactura.b2c.enabled",
    "efactura.b2b.minimum_amount_cents",
    "efactura.b2c.minimum_amount_cents",
)


def remove_invalid_efactura_controls(apps, schema_editor):
    system_setting = apps.get_model("settings", "SystemSetting")
    system_setting.objects.filter(key__in=INVALID_EFACTURA_CONTROL_KEYS).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("settings", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(remove_invalid_efactura_controls, migrations.RunPython.noop),
    ]
