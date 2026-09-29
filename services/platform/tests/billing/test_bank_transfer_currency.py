"""Bank details must identify an account configured for the debt's currency."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from lxml import etree

from apps.billing.bank_transfer import bank_transfer_instructions
from apps.billing.efactura.xml_builder import UBLInvoiceBuilder, XMLBuilderError
from apps.billing.pdf_generators import RomanianDocumentPDFGenerator


@override_settings(
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000", COMPANY_BANK_NAME="Legacy bank", COMPANY_NAME="Legacy seller"
)
class BankTransferCurrencyTests(SimpleTestCase):
    def instructions(self, code, accounts):
        with patch("apps.settings.services.SettingsService.get_setting", return_value=accounts):
            return bank_transfer_instructions(code)

    def test_foreign_debt_never_gets_legacy_ron_account(self) -> None:
        self.assertIsNone(self.instructions("EUR", {}))
        self.assertIsNone(self.instructions("USD", {}))
        self.assertEqual(self.instructions("RON", {})["currency"], "RON")

    def test_each_debt_uses_its_configured_account_despite_other_entries(self) -> None:
        accounts = {
            "RON": {"iban": "RO49AAAA1B31007593840000", "bank_name": "RON bank", "beneficiary": "Seller"},
            "EUR": {"iban": "DE89370400440532013000", "bank_name": "EUR bank", "beneficiary": "Seller"},
        }
        self.assertEqual(self.instructions("EUR", accounts)["iban"], "DE89370400440532013000")
        self.assertEqual(self.instructions("RON", accounts)["bank_name"], "RON bank")

    def test_malformed_explicit_mapping_never_falls_back(self) -> None:
        for accounts in ({"RON": {}}, {"EUR": {"iban": "missing beneficiary"}}, ["RON"], {"USD": None}):
            with self.subTest(accounts=accounts):
                code = next(iter(accounts)) if isinstance(accounts, dict) else "EUR"
                self.assertIsNone(self.instructions(code, accounts))

    def test_unknown_currency_is_unavailable(self) -> None:
        self.assertIsNone(self.instructions("GBP", {}))

    def test_pdf_uses_document_currency_account_even_when_default_is_different(self) -> None:
        document = SimpleNamespace(currency=SimpleNamespace(code="EUR"), currency_id="EUR")
        accounts = {"EUR": {"iban": "DE89370400440532013000", "bank_name": "EUR bank", "beneficiary": "Seller"}}
        with patch("apps.settings.services.SettingsService.get_setting", return_value=accounts):
            info = RomanianDocumentPDFGenerator(document)._get_company_info()
        self.assertEqual(info["bank_account"], "DE89370400440532013000")
        self.assertEqual(info["bank_name"], "EUR bank")

    def test_pdf_and_xml_without_foreign_account_never_render_ron_account(self) -> None:
        document = SimpleNamespace(currency=SimpleNamespace(code="EUR"), currency_id="EUR", due_at=None, number="INV-EUR")
        with patch("apps.settings.services.SettingsService.get_setting", return_value={}):
            generator = RomanianDocumentPDFGenerator(document)
            self.assertEqual(generator._get_company_info()["bank_account"], "")
            builder = UBLInvoiceBuilder(document)
            builder.root = etree.Element("Invoice")
            for payment_code in ("30", "58"):
                with self.subTest(payment_code=payment_code), patch.object(
                    builder, "_get_payment_means_code", return_value=payment_code
                ), self.assertRaisesRegex(XMLBuilderError, "EUR.*bank account"):
                    builder._add_payment_means()
            with patch.object(builder, "_get_payment_means_code", return_value="48"):
                builder.root = etree.Element("Invoice")
                builder._add_payment_means()
                rendered = etree.tostring(builder.root).decode()
                self.assertNotIn("RO49AAAA1B31007593840000", rendered)
                self.assertNotIn("PayeeFinancialAccount", rendered)

    def test_unknown_document_currency_cannot_render_as_ron(self) -> None:
        with self.assertRaises(ValueError):
            RomanianDocumentPDFGenerator(SimpleNamespace(currency=None, currency_id=None))._get_currency_code()
