from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("integrations", "0002_postgres_event_storage_indexes")]

    operations = [
        migrations.AddField(
            model_name="webhookevent",
            name="staff_alerted_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
