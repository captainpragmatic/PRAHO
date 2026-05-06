"""Add DomainOperation model for async registrar operation tracking."""

from __future__ import annotations

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0002_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="DomainOperation",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "operation_type",
                    models.CharField(
                        choices=[
                            ("transfer_in", "Transfer In"),
                            ("transfer_out", "Transfer Out"),
                            ("nameserver_update", "Nameserver Update"),
                            ("lock_update", "Lock Status Update"),
                            ("whois_update", "WHOIS Privacy Update"),
                            ("domain_info", "Domain Info Sync"),
                        ],
                        max_length=30,
                    ),
                ),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("submitted", "Submitted to Registrar"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                            ("retrying", "Retrying"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("parameters", models.JSONField(blank=True, default=dict)),
                ("submitted_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("registrar_operation_id", models.CharField(blank=True, max_length=200)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True)),
                ("retry_count", models.PositiveIntegerField(default=0)),
                ("max_retries", models.PositiveIntegerField(default=3)),
                ("next_retry_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "domain",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="operations",
                        to="domains.domain",
                    ),
                ),
                (
                    "registrar",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="domain_operations",
                        to="domains.registrar",
                    ),
                ),
            ],
            options={
                "verbose_name": "Domain Operation",
                "verbose_name_plural": "Domain Operations",
                "db_table": "domain_operations",
                "ordering": ("-created_at",),
                "indexes": [
                    models.Index(fields=["state", "created_at"], name="domainop_state_created_idx"),
                    models.Index(fields=["domain", "operation_type"], name="domainop_domain_type_idx"),
                    models.Index(fields=["state", "next_retry_at"], name="domainop_retry_idx"),
                ],
            },
        ),
    ]
