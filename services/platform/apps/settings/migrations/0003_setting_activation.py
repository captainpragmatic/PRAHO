"""Keep one-time setting activation independent of mutable setting rows."""

from django.db import migrations, models
from django.utils import timezone


class Migration(migrations.Migration):
    dependencies = [("settings", "0002_seed_selling_currency")]
    operations = [
        migrations.CreateModel(
            name="SettingActivation",
            fields=[
                ("key", models.CharField(max_length=100, primary_key=True, serialize=False)),
                ("version", models.CharField(max_length=40)),
                ("created_at", models.DateTimeField(default=timezone.now)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "setting_activations",
                "verbose_name": "Setting activation",
                "verbose_name_plural": "Setting activations",
            },
        ),
    ]
