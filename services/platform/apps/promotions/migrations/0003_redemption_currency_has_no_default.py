"""A redemption records its order's currency; it no longer defaults to RON."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("promotions", "0002_initial")]

    operations = [
        migrations.AlterField(
            model_name="couponredemption",
            name="currency_code",
            field=models.CharField(help_text="Currency of discount", max_length=3),
        ),
    ]
