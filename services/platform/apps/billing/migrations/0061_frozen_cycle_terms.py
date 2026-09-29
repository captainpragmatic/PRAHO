"""Add optional contract fields without changing any historical billing records.

The upgrade is additive and reversible. Historical provenance is inspected by the
read-only cycle-terms audit; this migration performs no data backfill or amount writes.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("billing", "0060_currency_bound_balances")]

    operations = [
        migrations.AddField(model_name="billingcycle", name="currency", field=models.ForeignKey(
            blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="billing.currency")),
        migrations.AddField(model_name="billingcycle", name="quantity", field=models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="billingcycle", name="unit_price_cents", field=models.BigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="billingcycle", name="pricing_snapshot", field=models.JSONField(blank=True, default=dict)),
        migrations.AddField(model_name="billingcycle", name="terms_frozen_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="billingcycle", name="terms_hold_reason", field=models.CharField(blank=True, editable=False, max_length=255)),
        migrations.AddField(model_name="billingcycle", name="entitlement_skipped_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="subscription", name="effective_terms_cycle", field=models.ForeignKey(
            blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="effective_subscriptions", to="billing.billingcycle")),
        migrations.AddField(model_name="subscription", name="effective_terms_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="subscription", name="last_payment", field=models.ForeignKey(
            blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="last_paid_subscriptions", to="billing.payment")),
        migrations.AddField(model_name="subscription", name="last_payment_currency", field=models.ForeignKey(
            blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="last_paid_subscriptions", to="billing.currency")),
        migrations.AddField(model_name="subscriptionitem", name="currency", field=models.ForeignKey(
            blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="billing.currency")),
        migrations.AddField(model_name="subscriptionitem", name="currency_hold_reason", field=models.CharField(blank=True, editable=False, max_length=255)),
    ]
