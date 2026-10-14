"""Legacy plan prices and server costs are labelled without RON: they are in the default currency."""

from decimal import Decimal

import django.core.validators
from django.db import migrations, models

_NON_NEGATIVE = [django.core.validators.MinValueValidator(Decimal("0.00"))]


class Migration(migrations.Migration):
    dependencies = [("provisioning", "0002_initial")]

    operations = [
        migrations.AlterField(
            model_name="server",
            name="monthly_cost",
            field=models.DecimalField(
                decimal_places=2, default=Decimal("0.00"), max_digits=10, verbose_name="Monthly Cost"
            ),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="price_monthly",
            field=models.DecimalField(
                decimal_places=2, max_digits=10, validators=_NON_NEGATIVE, verbose_name="Monthly Price"
            ),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="price_quarterly",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=10, null=True, validators=_NON_NEGATIVE,
                verbose_name="Quarterly Price",
            ),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="price_annual",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=10, null=True, validators=_NON_NEGATIVE,
                verbose_name="Annual Price",
            ),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="setup_fee",
            field=models.DecimalField(
                decimal_places=2, default=Decimal("0.00"), max_digits=10, verbose_name="Setup Fee"
            ),
        ),
    ]
