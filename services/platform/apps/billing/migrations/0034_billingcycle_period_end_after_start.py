from django.db import migrations, models
from django.db.models import F


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0033_invoice_bill_to_cnp_proformainvoice_bill_to_cnp_and_more"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="billingcycle",
            constraint=models.CheckConstraint(
                condition=models.Q(period_end__gt=F("period_start")),
                name="billingcycle_period_end_after_start",
            ),
        ),
    ]
