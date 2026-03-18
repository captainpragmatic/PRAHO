"""Add VIES verification fields to CustomerTaxProfile.

Supports EU cross-border VAT validation (issue #88).
"""

from django.db import migrations, models

# EU-27 VAT prefix codes (EL for Greece, not ISO GR).
# Inlined here so the migration is self-contained and doesn't import app code.
_EU_VAT_PREFIXES = frozenset({
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
    "FI", "FR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK",
})


def _backfill_not_applicable(apps, schema_editor):
    """Set vies_verification_status='not_applicable' for non-EU / no-VAT profiles."""
    CustomerTaxProfile = apps.get_model("customers", "CustomerTaxProfile")
    to_update = []
    for profile in CustomerTaxProfile.objects.all():
        prefix = profile.vat_number[:2].upper() if profile.vat_number else ""
        if not prefix or prefix not in _EU_VAT_PREFIXES:
            profile.vies_verification_status = "not_applicable"
            to_update.append(profile)
    if to_update:
        CustomerTaxProfile.objects.bulk_update(to_update, ["vies_verification_status"])


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
        migrations.RunPython(_backfill_not_applicable, migrations.RunPython.noop),
    ]
