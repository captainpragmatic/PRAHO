import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="APIToken",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "key_hash",
                    models.CharField(
                        db_index=True,
                        help_text="SHA-256 hex digest of the raw token key.",
                        max_length=64,
                        unique=True,
                    ),
                ),
                (
                    "key_prefix",
                    models.CharField(
                        help_text="First 8 characters of the raw key, for identification without exposing the full token.",
                        max_length=8,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        default="default",
                        help_text="Human-readable label for this token (e.g. 'ci-pipeline', 'monitoring-script').",
                        max_length=100,
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        blank=True,
                        help_text="Optional longer description of this token's purpose.",
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When this token expires. Null means no expiry.",
                        null=True,
                    ),
                ),
                (
                    "last_used_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="Last time this token was used for authentication. Updated at most every 5 minutes.",
                        null=True,
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="api_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "API Token",
                "verbose_name_plural": "API Tokens",
                "db_table": "users_api_tokens",
            },
        ),
        migrations.AddIndex(
            model_name="apitoken",
            index=models.Index(
                fields=["user", "created_at"],
                name="users_api_t_user_id_b2c3d4_idx",
            ),
        ),
    ]
