"""e-Factura must recognise a credit note as a credit note.

`UBLCreditNoteBuilder` and `EFacturaDocumentType.CREDIT_NOTE` predate the reversal
work, but nothing ever selected them: the document type was hardcoded to INVOICE, and
the branch that would have used the builder read `invoice.original_invoice`, an
attribute that does not exist on the model. A second site passed the credit note as its
OWN original. `reverses_invoice` is the link that was missing.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocumentType
from apps.billing.efactura.service import EFacturaService
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Currency,
    Invoice,
)
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

    def test_the_builder_receives_the_real_original_not_the_credit_note(self) -> None:
        """It used to pass the credit note as its own original, which references nothing."""
        original = self._invoice("FCT-000902")
        credit_note = self._credit_note(original)
        document = EFacturaService()._get_or_create_document(credit_note)

        with patch("apps.billing.efactura.service.UBLCreditNoteBuilder") as builder:
            builder.return_value.build.return_value = "<CreditNote/>"
            EFacturaService()._generate_xml(credit_note, document)

        builder.assert_called_once()
        passed_original = builder.call_args.args[1]
        self.assertEqual(
            passed_original.pk,
            original.pk,
            "the builder must reference the invoice being reversed, not the reversal",
        )
