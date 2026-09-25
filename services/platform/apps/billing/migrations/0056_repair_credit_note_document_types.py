"""Correct e-Factura rows that call a credit note an invoice.

`EFacturaDocument.document_type` is written through `get_or_create(defaults=…)`, which
applies `defaults` only on create. Rows written before the type was derived from the
invoice's own kind kept INVOICE, and `_prepare_and_claim_submission` reads that stored
field to decide which builder runs and to set `is_credit_note` on the upload claim — so
such a row would go to ANAF as an ordinary invoice with negative amounts and no reference
to the document it reverses.

The runtime path now repairs these when it next touches them, but a row nothing touches
again would stay wrong, so this sweeps the existing ones.

Only rows that have not been sent. The status list is a point-in-time copy of
`EFacturaStatus.repairable_statuses()` rather than an import, because a migration must
keep describing what it did on the day it ran even if that set is redefined later.
"""

from __future__ import annotations

from django.db import migrations

# Snapshot of EFacturaStatus.repairable_statuses() at 2026-09-24. Anything else either
# holds an in-flight upload claim or describes bytes ANAF has already seen.
_UNSENT_STATUSES = ["draft", "queued", "error"]


def repair_credit_note_document_types(apps, schema_editor):
    document_model = apps.get_model("billing", "EFacturaDocument")
    document_model.objects.filter(
        document_type="invoice",
        status__in=_UNSENT_STATUSES,
        invoice__document_kind="credit_note",
    ).update(document_type="credit_note")


def unrepair(apps, schema_editor):
    # No-op: the corrected value is the true one, and the rows this touched cannot be
    # distinguished afterwards from rows that were always correct.
    #
    # A no-op reverse here reads as though the branch rolls back cleanly, and it does not.
    # `0054`'s reverse restores `invoice_discount_non_negative`, which any credit note with a
    # discount violates, and it refuses rather than letting the database abort - see
    # `refuse_while_signed_documents_exist` there for the walls and the manual recipe. Rolling
    # back only as far as `0055` is unaffected.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0055_providerissuance_submissions"),
    ]

    operations = [
        migrations.RunPython(repair_credit_note_document_types, unrepair),
    ]
