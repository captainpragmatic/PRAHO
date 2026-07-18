from django.db import migrations, models

import apps.common.cnp_validator


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0032_usage_event_value_non_negative"),
    ]

    operations = [
        migrations.AddField(
            model_name="invoice",
            name="bill_to_cnp",
            field=models.CharField(
                blank=True,
                help_text="Romanian personal fiscal identifier snapshotted when the invoice is created",
                max_length=13,
                validators=[apps.common.cnp_validator.validate_cnp],
            ),
        ),
        migrations.AddField(
            model_name="proformainvoice",
            name="bill_to_cnp",
            field=models.CharField(
                blank=True,
                help_text="Romanian personal fiscal identifier snapshotted when the proforma is created",
                max_length=13,
                validators=[apps.common.cnp_validator.validate_cnp],
            ),
        ),
        migrations.AddConstraint(
            model_name="invoice",
            constraint=models.CheckConstraint(
                condition=models.Q(("bill_to_tax_id", ""), ("bill_to_cnp", ""), _connector="OR"),
                name="invoice_one_fiscal_id",
            ),
        ),
        migrations.AddConstraint(
            model_name="proformainvoice",
            constraint=models.CheckConstraint(
                condition=models.Q(("bill_to_tax_id", ""), ("bill_to_cnp", ""), _connector="OR"),
                name="proforma_one_fiscal_id",
            ),
        ),
    ]
