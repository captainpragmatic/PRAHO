"""Seven-day completed-login observations, independent of host polling history."""

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("customers", "0004_cnp_encryption"),
        ("security", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomerIPObservation",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("address_family", models.PositiveSmallIntegerField()),
                ("address", models.BinaryField(max_length=16)),
                ("last_seen_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="security_ip_observations",
                        to="customers.customer",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="security_ip_observations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "security_customer_ip_observation",
                "db_table_comment": "Seven-day customer IP safety observations after complete authentication; no raw event samples.",
                "indexes": [
                    models.Index(
                        fields=["address_family", "address", "last_seen_at"], name="security_customer_ip_recent"
                    )
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(address_family__in=(4, 6)), name="security_customer_ip_family"
                    ),
                    models.UniqueConstraint(
                        fields=("user", "customer", "address_family", "address"), name="security_customer_ip_identity"
                    ),
                ],
            },
        ),
    ]
