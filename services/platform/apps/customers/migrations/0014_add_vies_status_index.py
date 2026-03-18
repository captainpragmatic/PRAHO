"""Add index on vies_verification_status for efficient batch queries."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0013_add_vies_verification_fields"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="customertaxprofile",
            index=models.Index(
                fields=["vies_verification_status"],
                name="customer_tax_vies_status_idx",
            ),
        ),
    ]
