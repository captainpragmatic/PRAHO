from django.db import migrations, models

import apps.billing.config
import apps.billing.subscription_models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0008_report_period_indexes"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usagemeter",
            name="event_grace_period_hours",
            field=models.PositiveIntegerField(
                default=apps.billing.config.get_event_grace_period_hours,
                help_text="Hours in past to accept late events",
            ),
        ),
        migrations.AlterField(
            model_name="subscription",
            name="grace_period_days",
            field=models.PositiveIntegerField(
                default=apps.billing.subscription_models.get_subscription_grace_period_days,
                help_text="Days of grace after payment failure before suspension",
            ),
        ),
    ]
