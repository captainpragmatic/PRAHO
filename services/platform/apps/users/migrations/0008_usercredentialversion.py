"""Separate monotonic MFA session revocation state from ordinary user saves."""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0007_usersession"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserCredentialVersion",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("version", models.PositiveIntegerField(default=0)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="credential_version",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
