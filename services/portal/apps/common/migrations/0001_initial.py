from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Counter",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=200, unique=True)),
                ("count", models.PositiveIntegerField()),
                ("expires_at", models.BigIntegerField(db_index=True)),
                ("value", models.CharField(max_length=255, null=True)),
            ],
            options={"db_table": "common_counters"},
        ),
    ]
