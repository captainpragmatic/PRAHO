"""Seed the selling-currency policy row, billing.default_currency = RON.

The runtime falls back to the same value when the row is missing
(billing/currency_policy.py), so this keeps a fresh install identical to an
upgraded one: the row exists, at revision 1, until an explicit validated
switch. Carried forward from settings 0007 of the old history (ADR-0052).
Reversing must not discard the operator's explicit selling policy.
"""

from typing import Any

from django.db import migrations


def seed_selling_currency(apps: Any, schema_editor: Any) -> None:
    setting = apps.get_model("settings", "SystemSetting")
    setting.objects.using(schema_editor.connection.alias).get_or_create(
        key="billing.default_currency",
        defaults={
            "value": "RON",
            "default_value": "RON",
            "name": "Selling currency",
            "description": "Currency for new sales; existing money keeps its original currency.",
            "category": "billing",
            "data_type": "string",
        },
    )


class Migration(migrations.Migration):
    dependencies = [("settings", "0001_initial")]
    operations = [
        migrations.RunPython(seed_selling_currency, migrations.RunPython.noop),
    ]
