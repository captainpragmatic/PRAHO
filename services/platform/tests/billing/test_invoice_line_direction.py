"""A line's direction was never checked against the document it belongs to.

`invoiceline_amounts_share_one_sign` replaced three non-negative constraints when credit
notes started carrying negated lines. It is an intra-row rule: it proves `unit_price_cents`,
`tax_cents` and `line_total_cents` agree with *each other*, which is what makes a line quoting
a positive price against negative tax corrupt in either direction.

Its own comment then claims the remaining question is "settled one level up, by the
document-kind sign constraints on Invoice". Those settle the direction of the HEADER. Nothing
settled the direction of a LINE, so a negative line was insertable on an ordinary invoice -
three amounts in perfect agreement with each other and in complete disagreement with the
document. Every reader that walks the lines then diverges from the header it was summed into:
the e-Factura builder derives BT-92 as `line_gross - header_subtotal` and clamps it to
`max(0, ...)` for invoices, so the allowance silently stops explaining the gap; D390 and
EC-Sales attribute per line; the PDF and the detail screens display them.

A kind-aware CHECK constraint is not expressible - a SQL CHECK sees only its own row - so the
rule lives in `save()`, which already holds the parent under `select_for_update()` and so pays
nothing extra for it. Three things it must get right are each pinned below: the governing
parent is the one named by `invoice_id` and not whichever of the two locked rows comes first;
the check runs after `calculate_totals()`, because `subtotal_cents` is a property and the other
two amounts are derived from it; and the locked-invoice branch is left alone, because it exists
to permit linkage-only saves on frozen documents and must not start refusing them over
historical data nobody can fix.
"""

from __future__ import annotations

from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Currency,
    Invoice,
    InvoiceLine,
)
from tests.factories.billing_factories import CustomerFactory


class InvoiceLineDirectionTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _invoice(self, **overrides: object) -> Invoice:
        self._seq += 1
        fields: dict[str, object] = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"FCT-0007{self._seq:02d}",
            "status": "draft",
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Test Company SRL",
            "bill_to_country": "RO",
            "issuer_provider": ISSUER_BUILTIN,
        }
        fields.update(overrides)
        return Invoice.objects.create(**fields)

    def _credit_note(self) -> Invoice:
        original = self._invoice()
        self._seq += 1
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"CN-0007{self._seq:02d}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )

    @staticmethod
    def _line(invoice: Invoice, unit_price_cents: int) -> InvoiceLine:
        return InvoiceLine(
            invoice=invoice,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=unit_price_cents,
            tax_rate=Decimal("0.2100"),
        )

    # --- what must now be refused -------------------------------------------------

    def test_a_negative_line_is_refused_on_an_ordinary_invoice(self) -> None:
        invoice = self._invoice()

        with self.assertRaises(ValidationError):
            self._line(invoice, -10000).save()

    def test_a_positive_line_is_refused_on_a_credit_note(self) -> None:
        """The other direction is just as wrong, and is what the header constraints imply."""
        credit_note = self._credit_note()

        with self.assertRaises(ValidationError):
            self._line(credit_note, 10000).save()

    def test_flipping_an_existing_line_against_its_document_is_refused(self) -> None:
        """An update has to be checked too, not only the insert."""
        invoice = self._invoice()
        line = self._line(invoice, 10000)
        line.save()

        line.unit_price_cents = -10000

        with self.assertRaises(ValidationError):
            line.save()

    def test_reassigning_a_line_onto_a_document_of_the_other_kind_is_refused(self) -> None:
        """The governing parent is the new one, not whichever row the lock returns first."""
        credit_note = self._credit_note()
        line = self._line(credit_note, -10000)
        line.save()

        line.invoice = self._invoice()

        with self.assertRaises(ValidationError):
            line.save()

    def test_a_string_parent_id_does_not_bypass_the_guard(self) -> None:
        """`invoice_id="3"` is valid Django input, and the lock returns the row for it.

        The parents are keyed by `pk`, which is the column's own Python type, so a string id
        missed the lookup and the guard took its "document does not exist" exit - silently
        allowing exactly what it is there to refuse.
        """
        invoice = self._invoice()
        line = self._line(invoice, -10000)
        line.invoice_id = str(invoice.pk)

        with self.assertRaises(ValidationError):
            line.save()

    def test_a_partial_save_is_judged_on_what_will_actually_be_stored(self) -> None:
        """`update_fields` decides what lands, so it must decide what is judged.

        Reassigning a negative credit-note line onto an ordinary invoice while setting a
        positive price IN MEMORY passes a check that reads the in-memory row. But
        `update_fields=["invoice"]` writes only the parent, so the ordinary invoice ends up
        holding the original negative amounts - the state the guard exists to prevent,
        reached through the guard.
        """
        credit_note = self._credit_note()
        line = self._line(credit_note, -10000)
        line.save()
        line.invoice = self._invoice()
        line.unit_price_cents = 10000

        with self.assertRaises(ValidationError):
            line.save(update_fields=["invoice"])

    def test_a_zero_padded_parent_id_does_not_bypass_the_guard(self) -> None:
        """Django resolves `"00001"` and `"+1"` to invoice 1 and stores them there.

        Comparing ids as text fixed `str(pk)` and left these: `"1" != "00001"`, so the lookup
        missed and the guard took its "no such document" exit again. Only normalising through the
        primary-key field's own coercion closes the class, rather than one member of it.
        """
        invoice = self._invoice()
        for spelling in (f"{invoice.pk:05d}", f"+{invoice.pk}"):
            with self.subTest(invoice_id=spelling):
                line = self._line(invoice, -10000)
                line.invoice_id = spelling

                with self.assertRaises(ValidationError):
                    line.save()

    def test_a_partial_save_is_judged_against_the_parent_it_will_still_have(self) -> None:
        """The mirror of the amounts rule, and the half that was missing.

        `update_fields` decides what is written, so it decides the PARENT as well: reassigning
        `invoice` in memory while writing only the amounts leaves the persisted parent untouched.
        Judged against the in-memory credit note the negative amounts look right, and they land
        under the ordinary invoice that the row actually still points at.
        """
        invoice = self._invoice()
        line = self._line(invoice, 10000)
        line.save()
        line.invoice = self._credit_note()
        line.unit_price_cents = -10000

        with self.assertRaises(ValidationError):
            line.save(update_fields=("unit_price_cents", "tax_cents", "line_total_cents"))

    # --- what must still be allowed ------------------------------------------------

    def test_a_positive_line_is_allowed_on_an_ordinary_invoice(self) -> None:
        invoice = self._invoice()

        self._line(invoice, 10000).save()

        self.assertEqual(invoice.lines.count(), 1)

    def test_a_negative_line_is_allowed_on_a_credit_note(self) -> None:
        credit_note = self._credit_note()

        self._line(credit_note, -10000).save()

        self.assertEqual(credit_note.lines.count(), 1)

    def test_a_zero_line_is_allowed_on_either_kind(self) -> None:
        """Zero points nowhere, so it cannot disagree with anything."""
        self._line(self._invoice(), 0).save()
        self._line(self._credit_note(), 0).save()

    def test_correcting_a_wrong_signed_line_is_allowed(self) -> None:
        """This is what the check's position after `calculate_totals` buys.

        A credit-note line stored the wrong way round is corrected by setting the price and
        letting the derived amounts follow. Judged BEFORE that derivation the row still reads
        `(-10000, +2100, +12100)` - mixed, and so refused in the reversing direction - which
        would make the one save that repairs the row the one save that cannot happen.
        """
        credit_note = self._credit_note()
        InvoiceLine.objects.bulk_create(
            [
                InvoiceLine(
                    invoice=credit_note,
                    kind="service",
                    description="Stored the wrong way round",
                    quantity=Decimal("1"),
                    unit_price_cents=10000,
                    tax_rate=Decimal("0.2100"),
                    tax_cents=2100,
                    line_total_cents=12100,
                )
            ]
        )
        line = InvoiceLine.objects.get(invoice=credit_note)

        line.unit_price_cents = -10000
        line.save()

        stored = InvoiceLine.objects.get(pk=line.pk)
        self.assertEqual(stored.tax_cents, -2100)
        self.assertEqual(stored.line_total_cents, -12100)

    def test_a_linkage_only_save_on_a_locked_document_is_not_re_judged(self) -> None:
        """The frozen-document branch must not start refusing historical rows."""
        invoice = self._invoice()
        # `bulk_create` bypasses `save()`, which is how a wrong-signed line can already exist.
        InvoiceLine.objects.bulk_create(
            [
                InvoiceLine(
                    invoice=invoice,
                    kind="service",
                    description="Legacy",
                    quantity=Decimal("1"),
                    unit_price_cents=-10000,
                    tax_rate=Decimal("0.2100"),
                    tax_cents=-2100,
                    line_total_cents=-12100,
                )
            ]
        )
        Invoice.objects.filter(pk=invoice.pk).update(locked_at=timezone.now())
        line = InvoiceLine.objects.get(invoice=invoice)

        line.billing_cycle = None
        line.save()

        self.assertEqual(InvoiceLine.objects.get(pk=line.pk).unit_price_cents, -10000)
