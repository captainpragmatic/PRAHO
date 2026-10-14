"""The FX snapshot converts into the operator's home currency and says which (ADR-0041 addendum).

`exchange_to_ron` becomes `exchange_rate_to_home`, and `home_currency_code` records the currency
it converts into, stamped at issue. The trigger step runs last: SQLite drops a table's triggers
whenever Django rebuilds the table, and re-creating the trigger is harmless when it did not.
"""

from typing import Any

from django.db import migrations, models

from apps.common.db_triggers import create_context_immutability_trigger, drop_context_immutability_trigger

_TABLE = "billing_invoices"
_TRIGGER = "billing_invoice_encryption_context_immutable"


def recreate_trigger(apps: Any, schema_editor: Any) -> None:
    drop_context_immutability_trigger(schema_editor, table=_TABLE, name=_TRIGGER)
    create_context_immutability_trigger(schema_editor, table=_TABLE, column="encryption_context_id", name=_TRIGGER)


class Migration(migrations.Migration):
    dependencies = [("billing", "0010_cnp_encryption")]

    operations = [
        migrations.RenameField(model_name="invoice", old_name="exchange_to_ron", new_name="exchange_rate_to_home"),
        migrations.AlterField(
            model_name="invoice",
            name="exchange_rate_to_home",
            field=models.DecimalField(
                blank=True,
                decimal_places=8,
                help_text="Exchange rate to the home currency, frozen at issue",
                max_digits=18,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="invoice",
            name="home_currency_code",
            field=models.CharField(blank=True, max_length=3, null=True),
        ),
        migrations.RunPython(recreate_trigger, recreate_trigger),
    ]
