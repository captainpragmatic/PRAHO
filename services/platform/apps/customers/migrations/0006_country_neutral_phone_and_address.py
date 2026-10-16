"""A customer's phone is stored in international form; a new address starts in the default country and
needs a county only in Romania (a form rule, as CIUS-RO requires it).

Neither customers nor customer_addresses carries a trigger, so a table rebuild on SQLite needs no repair.
"""

from django.db import migrations, models

import apps.common.identity_fields
import apps.customers.contact_models


class Migration(migrations.Migration):
    dependencies = [("customers", "0005_preferred_currency_follows_selling_default")]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="primary_phone",
            field=models.CharField(
                blank=True,
                default="",
                max_length=20,
                validators=[apps.common.identity_fields.validate_international_phone],
                verbose_name="Telefon principal",
            ),
        ),
        migrations.AlterField(
            model_name="customeraddress",
            name="county",
            field=models.CharField(blank=True, max_length=100, verbose_name="Județ"),
        ),
        migrations.AlterField(
            model_name="customeraddress",
            name="country",
            field=models.CharField(
                default=apps.customers.contact_models.default_address_country, max_length=100, verbose_name="Țara"
            ),
        ),
    ]
