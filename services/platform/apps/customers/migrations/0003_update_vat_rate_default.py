"""Update CustomerTaxProfile VAT rate default from 19% to 21%.

Only changes the default for NEW records. Existing customers keep their stored rate.
Romanian VAT standard rate changed from 19% to 21% effective August 1, 2025
(Emergency Ordinance 156/2024).
"""

from decimal import Decimal

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0002_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customertaxprofile",
            name="vat_rate",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("21.00"),
                max_digits=5,
                verbose_name="Cota TVA (%)",
            ),
        ),
    ]
