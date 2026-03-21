"""Remove invoice_delivery_method from CustomerBillingProfile.

This field is no longer used — invoices are always delivered via email.
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
