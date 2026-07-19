from decimal import Decimal

from django.core.validators import MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0031_separate_usage_invoice"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usageevent",
            name="value",
            field=models.DecimalField(
                decimal_places=8,
                help_text="Usage value (interpretation depends on meter aggregation)",
                max_digits=18,
                validators=[MinValueValidator(Decimal("0"))],
            ),
        ),
        migrations.AddConstraint(
            model_name="usageevent",
            constraint=models.CheckConstraint(
                condition=models.Q(("value__gte", 0)),
                name="usage_event_value_non_negative",
            ),
        ),
    ]
