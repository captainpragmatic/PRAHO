from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0014_migrationbridge"),
    ]

    operations = [
        migrations.AddField(
            model_name="accounthostname",
            name="ttl_confirmed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
