"""Credit-note documents repaired by `0056` kept XML the wrong builder had produced.

`0056` corrected `EFacturaDocument.document_type` on rows written before credit notes existed.
It did not touch their XML, and the XML is the half that gets filed: it was generated while the
row said INVOICE, so `UBLInvoiceBuilder` wrote it - a 380 carrying negative amounts, with no
reference to the document being reversed. Submission re-validates and sends what is stored, so
a corrected label over the old bytes fixes nothing that ANAF will see.

Blanking `xml_content` is the whole repair. `submit` regenerates whenever it is empty, and
`_generate_xml` chooses the builder with `builder_for(invoice)`, which keys on the INVOICE's
`document_kind` - so the replacement bytes come from `UBLCreditNoteBuilder` whatever the row
once said.

Scoped to every unsent credit-note document rather than only the rows `0056` changed, because
`0056` deliberately left no way to tell them apart afterwards - its own reverse says so. The
cost of the wider net is one regeneration at submission time for a row that may already have
been correct; the cost of the narrower one is bytes that cannot be identified and so are never
repaired. `xml_hash` is written explicitly here because `.update()` bypasses the `save()` that
would otherwise recompute it.
"""

from __future__ import annotations

from django.db import migrations

# Snapshotted rather than imported from `EFacturaStatus.repairable_statuses()`: a migration must
# keep describing what it did on the day it ran, even if that set is redefined later. These are
# exactly the statuses from which submission may still start, so nothing here has reached ANAF.
_UNSENT_STATUSES = ["draft", "queued", "error"]


def clear_wrong_builder_xml(apps, schema_editor):
    document = apps.get_model("billing", "EFacturaDocument")
    stale = document.objects.filter(
        status__in=_UNSENT_STATUSES,
        invoice__document_kind="credit_note",
    ).exclude(xml_content="")

    cleared = stale.update(xml_content="", xml_hash="", xml_generated_at=None)
    if cleared:
        print(f"\n  e-Factura XML: {cleared} unsent credit-note document(s) cleared for regeneration")


def keep_the_repair(apps, schema_editor):
    # No-op, and deliberately so: the bytes are gone and were wrong. Regenerating them on the
    # way back would mean re-deriving them from the current code, which produces the CORRECT
    # document - so a faithful inverse would have to reproduce a defect on purpose.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0057_backfill_provider_submission_budget"),
    ]

    operations = [
        migrations.RunPython(clear_wrong_builder_xml, keep_the_repair),
    ]
