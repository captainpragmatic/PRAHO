"""Credit notes retain the original currency and frozen RON accounting evidence."""

from datetime import UTC, date, datetime
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import NAMESPACES, XMLBuilderError, builder_for
from apps.billing.invoice_models import Invoice
from apps.billing.issuers.service import _get_or_create_credit_note
from apps.settings.services import SettingsService
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


@override_settings(
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
)
class CreditNoteCurrencyXMLTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L"})[0]
        self.sequence = 0

    def _reversal(self, code: str, *, zero_tax: bool = False) -> tuple[Invoice, Invoice]:
        self.sequence += 1
        currency = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
        original = Invoice.objects.create(
            customer=self.customer,
            currency=currency,
            number=f"FCT-2026-{self.sequence:04d}",
            issued_at=datetime(2026, 7, 20, 9, tzinfo=UTC),
            tax_point_date=date(2026, 7, 20),
            subtotal_cents=9000,
            discount_cents=1000,
            tax_cents=0 if zero_tax else 1890,
            total_cents=9000 if zero_tax else 10890,
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            bill_to_address1="Customer Street 456",
            bill_to_city="Cluj-Napoca",
            bill_to_postal="400001",
            exchange_to_ron=None if code == "RON" else Decimal("5.01234567"),
            exchange_rate_as_of=None if code == "RON" else date(2026, 7, 17),
            exchange_rate_source="" if code == "RON" else "bnr",
            exchange_rate_source_reference="" if code == "RON" else "bnr:2026-07-17",
        )
        InvoiceLineFactory(
            invoice=original,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0") if zero_tax else Decimal("0.2100"),
        )
        credit_note = _get_or_create_credit_note(original)
        credit_note.number = f"CN-2026-{self.sequence:04d}"
        credit_note.issued_at = datetime(2026, 9, 29, 9, tzinfo=UTC)
        credit_note.issue()
        credit_note.save()
        return original, credit_note

    def _assert_accounting_xml(self, credit_note: Invoice, expected_tax: str = "94.73") -> None:
        xml = builder_for(credit_note).build()
        doc = etree.fromstring(xml.encode())
        self.assertEqual(etree.QName(doc).localname, "CreditNote")
        self.assertEqual(doc.findtext("cbc:CreditNoteTypeCode", namespaces=NAMESPACES), "381")
        self.assertEqual(doc.findtext("cbc:DocumentCurrencyCode", namespaces=NAMESPACES), credit_note.currency_id)
        self.assertEqual(
            doc.findtext("cac:BillingReference/cac:InvoiceDocumentReference/cbc:ID", namespaces=NAMESPACES),
            credit_note.reverses_invoice.number,
        )
        totals = doc.findall("cac:TaxTotal", namespaces=NAMESPACES)
        if credit_note.currency_id == "RON":
            self.assertIsNone(doc.find("cbc:TaxCurrencyCode", namespaces=NAMESPACES))
            self.assertEqual(len(totals), 1)
        else:
            self.assertEqual(doc.findtext("cbc:TaxCurrencyCode", namespaces=NAMESPACES), "RON")
            self.assertEqual(len(totals), 2)
            accounting = totals[0].find("cbc:TaxAmount", namespaces=NAMESPACES)
            self.assertEqual(accounting.get("currencyID"), "RON")
            self.assertEqual(accounting.text, expected_tax)
            self.assertIsNone(totals[0].find("cac:TaxSubtotal", namespaces=NAMESPACES))
        document_tax = totals[-1].find("cbc:TaxAmount", namespaces=NAMESPACES)
        self.assertEqual(document_tax.get("currencyID"), credit_note.currency_id)
        self.assertEqual(document_tax.text, "0.00" if credit_note.tax_cents == 0 else "18.90")
        self.assertIsNotNone(totals[-1].find("cac:TaxSubtotal", namespaces=NAMESPACES))
        self.assertIsNone(doc.find(".//cac:TaxExchangeRate", namespaces=NAMESPACES))
        amounts = doc.xpath(".//cac:LegalMonetaryTotal/*", namespaces=NAMESPACES)
        self.assertEqual(len(amounts), 5)
        for amount in amounts:
            self.assertEqual(amount.get("currencyID"), credit_note.currency_id)
            self.assertGreaterEqual(Decimal(amount.text), 0)
        self.assertEqual(
            doc.findtext("cac:LegalMonetaryTotal/cbc:PayableAmount", namespaces=NAMESPACES),
            "90.00" if credit_note.tax_cents == 0 else "108.90",
        )
        self.assertEqual(
            doc.findtext("cac:CreditNoteLine/cac:Price/cbc:PriceAmount", namespaces=NAMESPACES), "100.00"
        )
        result = CIUSROValidator().validate(xml)
        self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_all_selling_currencies_emit_credit_magnitudes_and_preserve_signed_ledger(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                original, credit_note = self._reversal(code)

                self._assert_accounting_xml(credit_note)

                stored = Invoice.objects.get(pk=credit_note.pk)
                self.assertEqual(stored.currency_id, code)
                self.assertEqual(stored.total_cents, -original.total_cents)
                self.assertEqual(stored.tax_cents, -original.tax_cents)
                self.assertEqual(stored.exchange_to_ron, original.exchange_to_ron)

    def test_zero_tax_still_emits_ron_accounting_total_for_foreign_currency(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                _original, credit_note = self._reversal(code, zero_tax=True)

                self._assert_accounting_xml(credit_note, expected_tax="0.00")

    def test_current_rates_and_selling_default_do_not_change_a_reversal(self) -> None:
        for code in ("EUR", "USD"):
            currency = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            FXRate.objects.create(
                base_code=currency,
                quote_code=self.ron,
                rate=Decimal("9.0"),
                as_of=timezone.localdate(),
                source="bnr",
                source_reference="current-rate",
                fetched_at=timezone.now(),
            )
        for code in ("EUR", "USD"):
            with self.subTest(currency=code):
                _original, credit_note = self._reversal(code)
                new_default = "USD" if code == "EUR" else "EUR"
                switched = SettingsService.update_setting("billing.default_currency", new_default)
                self.assertTrue(switched.is_ok(), switched)
                self.assertEqual(get_selling_currency_policy().currency_code, new_default)

                with (
                    override_settings(BILLING_DEFAULT_CURRENCY="RON"),
                    patch("apps.billing.exchange_rate_service.ExchangeRateService.resolve") as resolve,
                ):
                    self._assert_accounting_xml(credit_note)

                resolve.assert_not_called()

    def test_credit_note_cannot_change_original_currency(self) -> None:
        for code, other in (("RON", "EUR"), ("EUR", "USD"), ("USD", "RON")):
            with self.subTest(original=code, reversal=other):
                _original, credit_note = self._reversal(code)
                credit_note.currency = Currency.objects.get_or_create(code=other, defaults={"symbol": other})[0]

                with self.assertRaisesRegex(XMLBuilderError, "currency must match the original invoice"):
                    builder_for(credit_note).build()

    def test_credit_note_must_match_all_four_original_exchange_fields(self) -> None:
        changes = {
            "exchange_to_ron": Decimal("9.0"),
            "exchange_rate_as_of": date(2026, 7, 16),
            "exchange_rate_source": "ecb",
            "exchange_rate_source_reference": "different-reference",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                _original, credit_note = self._reversal("EUR")
                setattr(credit_note, field, value)

                with self.assertRaisesRegex(XMLBuilderError, "exchange-rate snapshot must match the original invoice"):
                    builder_for(credit_note).build()

    def test_invalid_original_exchange_evidence_is_refused_without_a_live_rate_lookup(self) -> None:
        cases = (
            ("exchange_to_ron", None, "complete provenanced"),
            ("exchange_rate_as_of", None, "complete provenanced"),
            ("exchange_rate_source", "", "complete provenanced"),
            ("exchange_rate_source_reference", "", "complete provenanced"),
            ("exchange_to_ron", Decimal("0"), "positive"),
            ("exchange_to_ron", Decimal("-1"), "positive"),
            ("exchange_to_ron", Decimal("NaN"), "finite"),
            ("exchange_to_ron", Decimal("Infinity"), "finite"),
            ("exchange_rate_source", "manual", "approved"),
            ("exchange_rate_as_of", date(2026, 7, 21), "after the invoice tax point"),
            ("tax_point_date", None, "complete provenanced"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                original, credit_note = self._reversal("USD")
                setattr(original, field, value)
                if field != "tax_point_date":
                    setattr(credit_note, field, value)

                with (
                    patch("apps.billing.exchange_rate_service.ExchangeRateService.resolve") as resolve,
                    self.assertRaisesRegex(XMLBuilderError, message),
                ):
                    builder_for(credit_note).build()

                resolve.assert_not_called()
