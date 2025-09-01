from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0004_rename_payment_method_field"),
    ]

    operations = [
        migrations.AddField(
            model_name="currency",
            name="name",
            field=models.CharField(default="", max_length=50),
        ),
    ]

