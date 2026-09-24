"""A discounted credit note has to reconcile in the XML, not just in the ledger.

`_get_document_discount` returns a SIGNED value: negative for a credit note, so the
allowance points the same way as the lines it corrects. `_add_legal_monetary_total`
already consumes that sign (`tax_exclusive = line_gross - discount`), but the two
places that EMIT the allowance still asked `> 0` and so wrote nothing. The result is a
document whose TaxExclusiveAmount is 10.00 away from its own LineExtensionAmount with
no allowance to explain the gap - BR-CO-13, an ANAF rejection.

The earlier test for this asserted on `UBLInvoiceBuilder(credit_note)._get_document_discount()`:
a private derivation, on the builder a credit note never reaches. It passed throughout.
These assert on `CIUSROValidator` rule codes, which is what ANAF's Schematron approximates.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import UBLCreditNoteBuilder, UBLInvoiceBuilder
from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.service import _get_or_create_credit_note
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

COMPANY = {
    "COMPANY_NAME": "Test Company SRL",
    "EFACTURA_COMPANY_CUI": "12345678",
    "COMPANY_REGISTRATION_NUMBER": "J40/1234/2020",
    "COMPANY_STREET": "Test Street 123",
    "COMPANY_CITY": "Bucharest",
    "COMPANY_POSTAL_CODE": "010101",
    "COMPANY_COUNTRY_CODE": "RO",
    "COMPANY_EMAIL": "test@example.com",
    "COMPANY_BANK_ACCOUNT": "RO49AAAA1B31007593840000",
    "COMPANY_BANK_NAME": "Test Bank",
}


@override_settings(**COMPANY)
class DiscountedCreditNoteReconciliationTests(TestCase):
    """Lines gross 100.00, document discount 10.00, header net 90.00, VAT 21%."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.validator = CIUSROValidator()

    def _discounted_original(self, number: str = "FCT-000700") -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=9000,
            tax_cents=1890,
            total_cents=10890,
            discount_cents=1000,
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            bill_to_address1="Customer Street 456",
            bill_to_city="Cluj-Napoca",
            bill_to_postal="400001",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=1890,
            line_total_cents=11890,
        )
        return invoice

    def _issued_reversal(self, original: Invoice) -> Invoice:
        """Reverse, then stamp what the provider would have assigned.

        `_get_or_create_credit_note` leaves the number and issue date unset on purpose -
        the provider assigns them - but the XML is only ever built after issuance, so the
        document under test has to be in that state. Re-fetched rather than refreshed:
        `refresh_from_db` raises on a protected FSMField.
        """
        credit_note = _get_or_create_credit_note(original)
        Invoice.objects.filter(pk=credit_note.pk).update(
            number="CN-000700", issued_at=timezone.now(), due_at=timezone.now()
        )
        return Invoice.objects.get(pk=credit_note.pk)

    def _codes(self, xml: str) -> list[str]:
        return [error.code for error in self.validator.validate(xml).errors]

    def test_the_credit_note_totals_reconcile(self) -> None:
        original = self._discounted_original()
        credit_note = self._issued_reversal(original)

        xml = UBLCreditNoteBuilder(credit_note, original).build()
        codes = self._codes(xml)

        self.assertNotIn("BR-CO-13", codes, f"the allowance must explain the gap; got {codes}")
        self.assertNotIn("BR-CO-15", codes, f"got {codes}")
        self.assertNotIn("BR-CO-16", codes, f"got {codes}")
        # A distinct code, so `assertNotIn("BR-CO-16", ...)` does not cover it. This is the
        # validator's OWN sign-blind guard: with no prepayment at all it read `0 > -108.90`
        # as an overpayment and refused every reversal before submission.
        self.assertNotIn("BR-CO-16-PREPAID", codes, f"got {codes}")

    def test_the_credit_note_declares_the_allowance_it_reverses(self) -> None:
        """Reconciling by omitting BOTH the allowance and the gap would also pass above."""
        original = self._discounted_original("FCT-000701")
        credit_note = self._issued_reversal(original)

        xml = UBLCreditNoteBuilder(credit_note, original).build()

        self.assertIn("AllowanceTotalAmount", xml, "BT-107 must be present")
        self.assertIn("-10.00", xml, "the allowance carries the document's own direction")
        self.assertIn("AllowanceChargeReasonCode", xml, "the BG-20 detail must be emitted too")

    def test_a_discounted_ordinary_invoice_is_unaffected(self) -> None:
        """The regression guard: the shared emitter must not change for invoices."""
        invoice = self._discounted_original("FCT-000702")

        xml = UBLInvoiceBuilder(invoice).build()
        codes = self._codes(xml)

        self.assertNotIn("BR-CO-13", codes, f"got {codes}")
        self.assertIn("AllowanceTotalAmount", xml)
        self.assertIn("10.00", xml)

    def test_an_undiscounted_credit_note_emits_no_allowance(self) -> None:
        """The other regression guard: a zero discount must still emit nothing."""
        original = self._discounted_original("FCT-000703")
        Invoice.objects.filter(pk=original.pk).update(discount_cents=0, subtotal_cents=10000, tax_cents=2100, total_cents=12100)
        original.refresh_from_db()
        credit_note = self._issued_reversal(original)

        xml = UBLCreditNoteBuilder(credit_note, original).build()

        self.assertNotIn("AllowanceTotalAmount", xml)
        self.assertNotIn("BR-CO-13", self._codes(xml))
