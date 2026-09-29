from django.db import migrations, models


def preserve_legacy_currency(apps, schema_editor):
    # The old environment option did not control sales. Upgrades keep RON until
    # an explicit validated switch; no historical money is converted or renamed.
    setting = apps.get_model("settings", "SystemSetting")
    setting.objects.using(schema_editor.connection.alias).get_or_create(
        key="billing.default_currency",
        defaults={
            "value": "RON",
            "default_value": "RON",
            "name": "Selling currency",
            "description": "Currency for new sales; existing money keeps its original currency.",
            "category": "billing",
            "data_type": "string",
        },
    )


class Migration(migrations.Migration):
    dependencies = [("settings", "0006_rename_invitation_policy_settings")]
    operations = [
        migrations.AddField(
            model_name="systemsetting", name="revision", field=models.PositiveBigIntegerField(default=1, editable=False)
        ),
        # Reversing must not discard the operator's explicit selling policy.
        migrations.RunPython(preserve_legacy_currency, migrations.RunPython.noop),
    ]
