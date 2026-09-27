"""Record consultation references and explicit customer exemption reasons."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("customers", "0022_clear_unverified_reverse_charge")]

    operations = [
        migrations.AddField(
            model_name="customertaxprofile",
            name="vies_consultation_reference",
            field=models.CharField(blank=True, max_length=255, verbose_name="VIES consultation reference"),
        ),
        migrations.AddField(
            model_name="customertaxprofile",
            name="vat_rate_reason",
            field=models.CharField(
                blank=True,
                max_length=20,
                choices=[
                    ("diplomatic", "Diplomatic exemption"),
                    ("exempt_body", "Exempt body"),
                    ("other", "Other exemption"),
                ],
                verbose_name="VAT exemption reason",
            ),
        ),
    ]
