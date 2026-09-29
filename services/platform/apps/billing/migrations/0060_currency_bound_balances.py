"""Preserve original monetary units; ambiguous history remains explicitly held."""

import django.db.models.deletion
from django.db import migrations, models


def _backfill_credit_currency(apps, alias):
    CreditLedger = apps.get_model("billing", "CreditLedger")

    for entry in CreditLedger.objects.using(alias).filter(currency__isnull=True).select_related("invoice", "payment").iterator():
        evidence = set()
        linked_currencies = set()
        wrong_customer = False
        if entry.invoice_id:
            linked_currencies.add(entry.invoice.currency_id)
            wrong_customer = entry.invoice.customer_id != entry.customer_id
            # Drafts can still change. An issued/locked source is historical evidence.
            if entry.invoice.locked_at or entry.invoice.status != "draft":
                evidence.add(entry.invoice.currency_id)
        if entry.payment_id:
            wrong_customer |= entry.payment.customer_id != entry.customer_id
            evidence.add(entry.payment.currency_id)
            linked_currencies.add(entry.payment.currency_id)
        if len(evidence) == 1 and len(linked_currencies) == 1 and not wrong_customer:
            currency_id, reason = evidence.pop(), ""
        else:
            currency_id = None
            reason = (
                "Conflicting linked currency or customer evidence"
                if len(linked_currencies) > 1 or wrong_customer
                else "No immutable source identifies the original currency"
            )
        CreditLedger.objects.using(alias).filter(pk=entry.pk).update(
            currency_id=currency_id, currency_hold_reason=reason,
        )


def _backfill_price_lock_currency(apps, alias):
    PriceGrandfathering = apps.get_model("billing", "PriceGrandfathering")
    BillingCycle = apps.get_model("billing", "BillingCycle")
    Subscription = apps.get_model("billing", "Subscription")
    OrderItem = apps.get_model("orders", "OrderItem")
    for promise in PriceGrandfathering.objects.using(alias).filter(currency__isnull=True).iterator():
        subscriptions = Subscription.objects.using(alias).filter(
            customer_id=promise.customer_id, product_id=promise.product_id, created_at__lte=promise.locked_at,
        )
        evidence = set()
        cycles = BillingCycle.objects.using(alias).filter(subscription__in=subscriptions).select_related(
            "invoice", "proforma", "usage_invoice",
        )
        for cycle in cycles.iterator():
            for source_name in ("invoice", "usage_invoice"):
                if getattr(cycle, f"{source_name}_id"):
                    source = getattr(cycle, source_name)
                    if (source.locked_at or source.status != "draft") and source.created_at <= promise.locked_at:
                        evidence.add(source.currency_id if source.customer_id == promise.customer_id else None)
            if (cycle.proforma_id and cycle.proforma.status != "draft"
                    and cycle.proforma.created_at <= promise.locked_at):
                evidence.add(
                    cycle.proforma.currency_id if cycle.proforma.customer_id == promise.customer_id else None
                )
        evidence.update(
            OrderItem.objects.using(alias).filter(
                service_id__in=subscriptions.exclude(service_id=None).values("service_id"),
                product_id=promise.product_id, order__customer_id=promise.customer_id,
                order__status__in=["paid", "in_review", "provisioning", "completed"],
                order__created_at__lte=promise.locked_at,
            ).values_list("order__currency_id", flat=True)
        )
        if len(evidence) == 1 and None not in evidence:
            currency_id, reason = evidence.pop(), ""
        else:
            currency_id = None
            reason = (
                "Conflicting historical currencies; retain existing subscription protection"
                if evidence else "No immutable source; retain existing subscription protection"
            )
        PriceGrandfathering.objects.using(alias).filter(pk=promise.pk).update(
            currency_id=currency_id, currency_hold_reason=reason,
        )


def backfill_currency_identities(apps, schema_editor):
    alias = schema_editor.connection.alias
    _backfill_credit_currency(apps, alias)
    _backfill_price_lock_currency(apps, alias)


class Migration(migrations.Migration):
    dependencies = [("billing", "0059_alter_payment_payment_method")]

    operations = [
        migrations.AddField(
            model_name="creditledger", name="currency",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="billing.currency"),
        ),
        migrations.AddField(
            model_name="creditledger", name="currency_hold_reason",
            field=models.CharField(blank=True, editable=False, max_length=255),
        ),
        migrations.AddField(
            model_name="pricegrandfathering", name="currency",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="billing.currency"),
        ),
        migrations.AddField(
            model_name="pricegrandfathering", name="currency_hold_reason",
            field=models.CharField(blank=True, editable=False, max_length=255),
        ),
        migrations.RunPython(backfill_currency_identities, migrations.RunPython.noop),
        migrations.AlterUniqueTogether(name="pricegrandfathering", unique_together={("customer", "product", "currency")}),
        migrations.AddIndex(
            model_name="creditledger",
            index=models.Index(fields=["customer", "currency"], name="credit_customer_currency_idx"),
        ),
        migrations.AddConstraint(
            model_name="creditledger",
            constraint=models.CheckConstraint(
                condition=(models.Q(currency__isnull=False, currency_hold_reason="")
                           | (models.Q(currency__isnull=True) & ~models.Q(currency_hold_reason=""))),
                name="credit_currency_known_or_held",
            ),
        ),
        migrations.AddConstraint(
            model_name="pricegrandfathering",
            constraint=models.CheckConstraint(
                condition=(models.Q(currency__isnull=False, currency_hold_reason="")
                           | (models.Q(currency__isnull=True) & ~models.Q(currency_hold_reason=""))),
                name="price_lock_currency_known_or_held",
            ),
        ),
        migrations.AddConstraint(
            model_name="pricegrandfathering",
            constraint=models.UniqueConstraint(
                fields=["customer", "product"], condition=models.Q(currency__isnull=True),
                name="one_unresolved_price_lock",
            ),
        ),
    ]
