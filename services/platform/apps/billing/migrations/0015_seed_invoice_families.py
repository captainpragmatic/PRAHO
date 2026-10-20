from django.db import migrations
from django.db.models import Q


def seed_invoice_families(apps, schema_editor):
    alias = schema_editor.connection.alias
    Sequence = apps.get_model("billing", "InvoiceSequence")
    Invoice = apps.get_model("billing", "Invoice")
    Subscription = apps.get_model("billing", "Subscription")
    families = {"default": "INV", "subscription": "SUB"}
    missing = [scope for scope in families if not Sequence.objects.using(alias).filter(scope=scope).exists()]
    issued = Invoice.objects.using(alias).filter(issuer_provider="builtin", number__isnull=False).exclude(number="")
    for scope in missing:
        family = Q(sequence_scope="subscription") if scope == "subscription" else ~Q(sequence_scope="subscription")
        subscription_history = (
            scope == "subscription" and Subscription.objects.using(alias).exclude(subscription_number="").exists()
        )
        if issued.filter(family).exists() or subscription_history:
            raise ValueError(
                f"Cannot seed missing invoice family {scope!r} at zero: issued numbers exist; repair the sequence first"
            )
    for scope in missing:
        Sequence.objects.using(alias).get_or_create(scope=scope, defaults={"prefix": families[scope], "last_value": 0})


class Migration(migrations.Migration):
    dependencies = [("billing", "0014_remove_unwritten_document_files")]

    operations = [migrations.RunPython(seed_invoice_families, migrations.RunPython.noop)]
