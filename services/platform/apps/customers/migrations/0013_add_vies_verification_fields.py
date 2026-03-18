"""Add VIES verification fields to CustomerTaxProfile.

Supports EU cross-border VAT validation (issue #88).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0002_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="customertaxprofile",
            name="vies_verified_at",
            field=models.DateTimeField(
                blank=True,
                help_text="Timestamp of last successful VIES verification",
                null=True,
                verbose_name="VIES verified at",
            ),
        ),
        migrations.AddField(
            model_name="customertaxprofile",
            name="vies_verified_name",
            field=models.CharField(
                blank=True,
                help_text="Company name returned by VIES API",
                max_length=255,
                verbose_name="VIES company name",
            ),
        ),
        migrations.AddField(
            model_name="customertaxprofile",
            name="vies_verification_status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("valid", "VIES Verified"),
                    ("invalid", "VIES Invalid"),
                    ("format_only", "Format Valid (VIES unavailable)"),
                    ("not_applicable", "Not Applicable"),
                ],
                default="pending",
                max_length=25,
                verbose_name="VIES status",
            ),
        ),
    ]
