"""A billing profile's preferred currency and credit limit follow the operator's default currency.

The preferred currency defaults to the selling default, not RON, and the credit limit's label no
longer names RON. customer_billing_profiles carries no trigger, so a table rebuild on SQLite needs
no repair.
"""

from decimal import Decimal

from django.db import migrations, models

import apps.billing.currency_service


class Migration(migrations.Migration):
    dependencies = [("customers", "0004_cnp_encryption")]

    operations = [
        migrations.AlterField(
            model_name="customerbillingprofile",
            name="preferred_currency",
            field=models.CharField(
                choices=[("RON", "RON"), ("EUR", "EUR"), ("USD", "USD")],
                default=apps.billing.currency_service.default_selling_currency,
                max_length=3,
                verbose_name="Monedă preferată",
            ),
        ),
        migrations.AlterField(
            model_name="customerbillingprofile",
            name="credit_limit",
            field=models.DecimalField(
                decimal_places=2, default=Decimal("0.00"), max_digits=10, verbose_name="Limită credit"
            ),
        ),
    ]
