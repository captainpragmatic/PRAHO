import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0041_recover_remaining_legacy_refunds"),
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
