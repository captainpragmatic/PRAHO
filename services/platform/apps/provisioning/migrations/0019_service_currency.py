import django.db.models.deletion
from django.db import migrations, models


def set_default_currency(apps, schema_editor):
    Currency = apps.get_model("billing", "Currency")
    Service = apps.get_model("provisioning", "Service")
    _ron, _ = Currency.objects.get_or_create(
        code="RON",
        defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
    )
    Service.objects.filter(currency_id__isnull=True).update(currency_id="RON")


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0001_initial"),
        ("provisioning", "0018_server__api_password_encrypted_server_api_username_and_more"),
    ]

    operations = [
        # Step 1: Add as nullable
        migrations.AddField(
            model_name="service",
            name="currency",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="billing.currency",
                verbose_name="Currency",
            ),
        ),
        # Step 2: Backfill existing rows with RON
        migrations.RunPython(set_default_currency, reverse_code=migrations.RunPython.noop),
        # Step 3: Make required
        migrations.AlterField(
            model_name="service",
            name="currency",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                to="billing.currency",
                verbose_name="Currency",
            ),
        ),
    ]
