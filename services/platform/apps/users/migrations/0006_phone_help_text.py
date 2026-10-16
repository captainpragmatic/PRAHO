"""A user's phone is stored with its country code, not in a Romanian format."""

from django.db import migrations, models

import apps.common.identity_fields


class Migration(migrations.Migration):
    dependencies = [("users", "0005_pending_totp_enrolment")]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="phone",
            field=models.CharField(
                blank=True,
                help_text="With its country code, e.g. +40 721 123 456",
                max_length=20,
                validators=[apps.common.identity_fields.validate_international_phone],
            ),
        ),
    ]
