from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0024_backfill_refunds_from_meta"),
    ]

    operations = [
        migrations.AddField(
            model_name="invoice",
            name="bill_to_registration_number",
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name="proformainvoice",
            name="bill_to_registration_number",
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
