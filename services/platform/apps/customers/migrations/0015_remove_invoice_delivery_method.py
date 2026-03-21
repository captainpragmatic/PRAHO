"""Remove invoice_delivery_method from CustomerBillingProfile.

This field is no longer used — invoices are always delivered via email.

INTENTIONALLY IRREVERSIBLE: This migration has no reverse operation.
All existing rows had invoice_delivery_method="email" (the only used value),
so no data is lost. If rollback is needed, re-add the column manually and
populate with "email" for all existing rows.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0014_add_vies_status_index"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="customerbillingprofile",
            name="invoice_delivery_method",
        ),
    ]
