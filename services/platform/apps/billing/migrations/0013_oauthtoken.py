# Generated migration for e-Factura OAuth Token storage

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add OAuthToken model for secure e-Factura token storage."""

    dependencies = [
        ("billing", "0012_efacturadocument"),
    ]

    operations = [
        migrations.CreateModel(
            name="OAuthToken",
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
                    "cui",
                    models.CharField(
                        db_index=True,
                        help_text="Company CUI this token belongs to",
                        max_length=20,
                    ),
                ),
                (
                    "access_token",
                    models.TextField(help_text="Encrypted access token"),
                ),
                (
                    "refresh_token",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Encrypted refresh token",
                    ),
                ),
                (
                    "token_type",
                    models.CharField(
                        default="Bearer",
                        help_text="Token type (usually Bearer)",
                        max_length=50,
                    ),
                ),
                (
                    "scope",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="OAuth scopes granted",
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(help_text="When the access token expires"),
                ),
                (
                    "refresh_expires_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When the refresh token expires (if known)",
                        null=True,
                    ),
                ),
                (
                    "environment",
                    models.CharField(
                        choices=[("test", "Test"), ("production", "Production")],
                        default="test",
                        help_text="ANAF environment this token is for",
                        max_length=20,
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        db_index=True,
                        default=True,
                        help_text="Whether this token is currently active",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "last_used_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When this token was last used",
                        null=True,
                    ),
                ),
                (
                    "use_count",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of times this token was used",
                    ),
                ),
            ],
            options={
                "verbose_name": "e-Factura OAuth Token",
                "verbose_name_plural": "e-Factura OAuth Tokens",
                "db_table": "billing_efactura_oauth_token",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="oauthtoken",
            index=models.Index(
                fields=["cui", "is_active"],
                name="billing_efa_cui_0c6e9a_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="oauthtoken",
            index=models.Index(
                fields=["expires_at"],
                name="billing_efa_expires_d6b7c4_idx",
            ),
        ),
    ]
