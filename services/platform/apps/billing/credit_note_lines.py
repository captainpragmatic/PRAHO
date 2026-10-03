"""The lines of a credit note that restates its original in full.

Shared by both issuers: the SmartBill storno (`issuers/service.py`) and the built-in storno
(`fiscal_correction_worker.py`) mirror an original's lines the same way, so a whole-invoice
correction reads identically whichever path wrote it.
"""

from __future__ import annotations

from .invoice_models import Invoice, InvoiceLine


def mirror_lines_negated(original: Invoice, credit_note: Invoice) -> None:
    """Copy the original's lines with the money negated and the quantities intact.

    A credit note without lines is a total with no composition. The VAT report and
    the D390/EC-Sales builders attribute amounts by walking `InvoiceLine` rows for
    their rate and tax category, so a line-less correction is invisible to every one
    of them however correct the header totals are.

    Quantities stay positive and the per-unit money goes negative. Negating the
    quantity instead would reverse the same total while corrupting the mapper's
    discount line, whose `numberOfItems` counts the ordinary lines preceding it.

    `discount_amount_cents` is copied unchanged: it is a magnitude rather than a
    signed amount, and the e-Factura builder refuses a negative one.
    """
    InvoiceLine.objects.bulk_create(
        [
            InvoiceLine(
                invoice=credit_note,
                kind=line.kind,
                service=line.service,
                billing_cycle=line.billing_cycle,
                description=line.description,
                quantity=line.quantity,
                unit_price_cents=-line.unit_price_cents,
                tax_rate=line.tax_rate,
                tax_cents=-line.tax_cents,
                line_total_cents=-line.line_total_cents,
                domain_name=line.domain_name,
                period_start=line.period_start,
                period_end=line.period_end,
                unit_code=line.unit_code,
                tax_category_code=line.tax_category_code,
                note=line.note,
                discount_amount_cents=line.discount_amount_cents,
                seller_item_id=line.seller_item_id,
                sort_order=line.sort_order,
            )
            for line in original.lines.all().order_by("sort_order", "pk")
        ]
    )
