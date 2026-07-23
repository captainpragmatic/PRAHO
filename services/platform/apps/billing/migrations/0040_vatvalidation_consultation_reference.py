import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0039_invoice_tax_point_and_fx_snapshot"),
    ]

    operations = [
        migrations.AlterField(
            model_name="vatvalidation",
            name="validation_date",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name="vatvalidation",
            name="consultation_reference",
            field=models.CharField(
                blank=True,
                help_text="VIES proof-of-consultation request identifier",
                max_length=100,
            ),
        ),
    ]
