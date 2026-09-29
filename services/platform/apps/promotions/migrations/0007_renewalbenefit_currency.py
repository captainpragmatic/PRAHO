"""Renewal credits retain the currency of the order that promised them."""

import django.db.models.deletion
from django.db import migrations, models


def backfill_benefit_currency(apps, schema_editor):
    Benefit = apps.get_model("promotions", "RenewalBenefit")
    alias = schema_editor.connection.alias
    for benefit in Benefit.objects.using(alias).filter(currency__isnull=True).select_related("application__order", "order_item__order").iterator():
        order = benefit.application.order
        if benefit.order_item.order_id == order.pk:
            currency_id, reason = order.currency_id, ""
        else:
            currency_id, reason = None, "Benefit application and item identify different original orders"
        Benefit.objects.using(alias).filter(pk=benefit.pk).update(
            currency_id=currency_id, currency_hold_reason=reason,
        )


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0060_currency_bound_balances"),
        ("promotions", "0006_giftcard_ledger_version_giftcard_reserved_cents_and_more"),
    ]
    operations = [
        migrations.AddField(
            model_name="renewalbenefit", name="currency",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="billing.currency"),
        ),
        migrations.AddField(
            model_name="renewalbenefit", name="currency_hold_reason",
            field=models.CharField(blank=True, editable=False, max_length=255),
        ),
        migrations.RunPython(backfill_benefit_currency, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="renewalbenefit",
            constraint=models.CheckConstraint(
                condition=(models.Q(currency__isnull=False, currency_hold_reason="")
                           | (models.Q(currency__isnull=True) & ~models.Q(currency_hold_reason=""))),
                name="benefit_currency_known_or_held",
            ),
        ),
    ]
