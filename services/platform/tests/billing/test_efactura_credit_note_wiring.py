"""e-Factura must recognise a credit note as a credit note.

`UBLCreditNoteBuilder` and `EFacturaDocumentType.CREDIT_NOTE` predate the reversal
work, but nothing ever selected them: the document type was hardcoded to INVOICE, and
the branch that would have used the builder read `invoice.original_invoice`, an
attribute that does not exist on the model. A second site passed the credit note as its
OWN original. `reverses_invoice` is the link that was missing.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocumentType
from apps.billing.efactura.service import EFacturaService
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Currency,
    Invoice,
)
from apps.billing.invoice_service import generate_e_factura_xml
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


class CreditNoteDocumentTypeTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _invoice(self, number: str) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _credit_note(self, original: Invoice) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="CN-000001",
            status="draft",
            issued_at=timezone.now(),
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            issuer_provider=ISSUER_BUILTIN,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

    def test_a_credit_note_gets_the_credit_note_document_type(self) -> None:
        original = self._invoice("FCT-000900")
        credit_note = self._credit_note(original)

        document = EFacturaService()._get_or_create_document(credit_note)

        self.assertEqual(document.document_type, EFacturaDocumentType.CREDIT_NOTE.value)

    def test_an_ordinary_invoice_still_gets_the_invoice_type(self) -> None:
        """The regression guard."""
        invoice = self._invoice("FCT-000901")

        document = EFacturaService()._get_or_create_document(invoice)

        self.assertEqual(document.document_type, EFacturaDocumentType.INVOICE.value)

    def test_the_generated_document_references_the_invoice_it_reverses(self) -> None:
        """It used to pass the credit note as its own original, which references nothing.

        Asserted on the emitted BillingReference rather than on a mocked constructor:
        the builder is now selected by a shared helper, so a test that patched this
        module's name would have kept passing while pointing at nothing.
        """
        original = self._invoice("FCT-000902")
        credit_note = self._credit_note(original)
        document = EFacturaService()._get_or_create_document(credit_note)

        with override_settings(
            COMPANY_NAME="Test Company SRL",
            EFACTURA_COMPANY_CUI="12345678",
            COMPANY_STREET="Test Street 123",
            COMPANY_CITY="Bucharest",
            COMPANY_POSTAL_CODE="010101",
            COMPANY_COUNTRY_CODE="RO",
        ):
            xml = EFacturaService()._generate_xml(credit_note, document)

        reference = xml.split("<cac:BillingReference>")[1].split("</cac:BillingReference>")[0]
        self.assertIn("FCT-000902", reference, "the reversal must name the invoice it reverses")
        self.assertNotIn("CN-000001", reference, "and it cannot reference itself")


@override_settings(
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
)
class StaffXmlDownloadTests(CreditNoteDocumentTypeTests):
    """The submission path dispatches on document kind; the staff download did not.

    `generate_e_factura_xml` is what `billing:generate_e_factura` hands a staff member,
    and it called `UBLInvoiceBuilder` unconditionally - so the same credit note that ANAF
    receives as a `<CreditNote>` downloads from our own UI as an `<Invoice>` with a 380
    type code, no BillingReference to the document it reverses, and its allowance dropped
    by the `allowance_total > 0` guard on that builder. Two builders selected in two
    places is how the first selection came to be wrong; they now share one.
    """

    def test_a_credit_note_downloads_as_a_credit_note(self) -> None:
        original = self._invoice("FCT-000910")

        xml = generate_e_factura_xml(self._credit_note(original))

        self.assertIn("<CreditNote", xml, "the staff download must not restate a reversal as an invoice")
        self.assertIn("<cbc:CreditNoteTypeCode>381</cbc:CreditNoteTypeCode>", xml)
        self.assertIn("FCT-000910", xml, "and it must still reference the invoice it reverses")

    def test_an_ordinary_invoice_still_downloads_as_an_invoice(self) -> None:
        """The regression guard."""
        xml = generate_e_factura_xml(self._invoice("FCT-000911"))

        self.assertIn("<Invoice", xml)
        self.assertNotIn("<CreditNote", xml)
