"""Effect tests for staff-configured e-Factura supplier identity."""

from datetime import UTC, datetime
from decimal import Decimal

from django.test import TestCase, override_settings
from lxml import etree

from apps.billing.efactura.xml_builder import NAMESPACES, UBLInvoiceBuilder, XMLBuilderError
from apps.billing.invoice_models import Invoice
from apps.settings.services import SettingsService
from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory, InvoiceLineFactory


@override_settings(
    COMPANY_NAME="Legacy Supplier SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Legacy Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_EMAIL="legacy@example.com",
    COMPANY_PHONE="+40210000000",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Legacy Bank",
)
class EFacturaIdentitySettingsEffectsTests(TestCase):
    """Persist settings through the staff service and inspect the real UBL output."""

    invoice: Invoice
    supplier_path = "./cac:AccountingSupplierParty/cac:Party"

    def setUp(self) -> None:
        super().setUp()
        self.invoice = InvoiceFactory(
            customer=CustomerFactory(),
            currency=CurrencyFactory(code="RON"),
            number="IDENTITY-2026-001",
            status="issued",
            issued_at=datetime(2026, 9, 1, 9, tzinfo=UTC),
            due_at=datetime(2026, 10, 1, 9, tzinfo=UTC),
            bill_to_name="Identity Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="87654321",
            bill_to_street="Customer Street 2",
            bill_to_city="Cluj-Napoca",
            bill_to_postal_code="400001",
            subtotal_cents=10000,
            tax_total_cents=1900,
            total_cents=11900,
        )
        InvoiceLineFactory(
            invoice=self.invoice,
            description="Hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.1900"),
        )

    def _write(self, key: str, value: str | dict[str, dict[str, str]]) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))
        self.addCleanup(SettingsService._clear_setting_cache, key)

    def test_supplier_lookup_prefers_every_stored_identity_value(self) -> None:
        stored = {
            "name": "Identity Supplier SRL",
            "cui": "87654321",
            "registration_number": "J32/987/2026",
            "street": "Identity Street 27",
            "city": "Sibiu",
            "postal_code": "550001",
            "email": "billing@identity.example",
            "phone": "+40269123456",
        }
        for key, value in stored.items():
            self._write(f"efactura.company.{key}", value)
        supplier = UBLInvoiceBuilder(self.invoice)._get_supplier_info()
        self.assertEqual(
            (
                supplier.name,
                supplier.tax_id,
                supplier.registration_number,
                supplier.street,
                supplier.city,
                supplier.postal_code,
                supplier.email,
                supplier.phone,
            ),
            tuple(stored.values()),
        )

    def _document(self) -> etree._Element:
        return etree.fromstring(UBLInvoiceBuilder(self.invoice).build().encode("utf-8"))

    def _assert_supplier_text(self, path: str, expected: str) -> None:
        document = self._document()
        self.assertEqual(document.findtext(f"{self.supplier_path}/{path}", namespaces=NAMESPACES), expected)
        self.assertEqual(
            document.findtext("./cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:Percent", namespaces=NAMESPACES),
            "19.00",
        )

    def test_bank_account_changes_payment_instructions(self) -> None:
        self._write("efactura.company.bank_account", "RO09BCYP0000001234567890")

        document = self._document()
        self.assertEqual(
            document.findtext("./cac:PaymentMeans/cac:PayeeFinancialAccount/cbc:ID", namespaces=NAMESPACES),
            "RO09BCYP0000001234567890",
        )

        self._write(
            "billing.bank_accounts",
            {"RON": {"iban": "RO49AAAA1B31007593840000", "bank_name": "Currency Bank", "beneficiary": "Supplier"}},
        )
        document = self._document()
        self.assertEqual(
            document.findtext("./cac:PaymentMeans/cac:PayeeFinancialAccount/cbc:ID", namespaces=NAMESPACES),
            "RO49AAAA1B31007593840000",
        )

    @override_settings(EFACTURA_COMPANY_BANK_NAME="Deployment Bank")
    def test_empty_bank_name_uses_deployment_identity_in_xml(self) -> None:
        from apps.billing.efactura.settings import company_identity_setting  # noqa: PLC0415

        self._write("efactura.company.bank_name", "")
        self.assertEqual(company_identity_setting("efactura.company.bank_name", "Legacy Bank"), "Deployment Bank")
        document = self._document()
        self.assertEqual(
            document.findtext(
                "./cac:PaymentMeans/cac:PayeeFinancialAccount/cac:FinancialInstitutionBranch/cbc:Name",
                namespaces=NAMESPACES,
            ),
            "Deployment Bank",
        )
        for key, value in (("efactura.enabled", False), ("efactura.retry.max_retries", 0)):
            with self.subTest(key=key):
                result = SettingsService.update_setting(key, value)
                self.assertTrue(result.is_ok(), str(result))
                self.addCleanup(SettingsService._clear_setting_cache, key)
                self.assertEqual(company_identity_setting(key, "legacy"), str(value))

    def test_bank_name_changes_payment_instructions(self) -> None:
        self._write("efactura.company.bank_name", "Identity Bank")

        document = self._document()
        self.assertEqual(
            document.findtext(
                "./cac:PaymentMeans/cac:PayeeFinancialAccount/cac:FinancialInstitutionBranch/cbc:Name",
                namespaces=NAMESPACES,
            ),
            "Identity Bank",
        )

    def test_city_changes_supplier_postal_address(self) -> None:
        self._write("efactura.company.city", "Sibiu")
        self._assert_supplier_text("cac:PostalAddress/cbc:CityName", "Sibiu")

    def test_country_code_refuses_non_romanian_supplier(self) -> None:
        self._write("efactura.company.country_code", "DE")

        with self.assertRaisesRegex(XMLBuilderError, "Romanian statutory format"):
            UBLInvoiceBuilder(self.invoice).build()

        self._write("efactura.company.country_code", "RO")
        with (
            override_settings(COMPANY_COUNTRY_CODE="DE"),
            self.assertRaisesRegex(XMLBuilderError, "Romanian statutory format"),
        ):
            UBLInvoiceBuilder(self.invoice).build()

    def test_cui_changes_supplier_fiscal_identifiers(self) -> None:
        self._write("efactura.company.cui", "RO87654321")

        document = self._document()
        self.assertEqual(
            document.findtext(f"{self.supplier_path}/cac:PartyIdentification/cbc:ID", namespaces=NAMESPACES),
            "87654321",
        )
        self.assertEqual(
            document.findtext(f"{self.supplier_path}/cac:PartyTaxScheme/cbc:CompanyID", namespaces=NAMESPACES),
            "RO87654321",
        )

    def test_email_changes_supplier_contact(self) -> None:
        self._write("efactura.company.email", "billing@identity.example")
        self._assert_supplier_text("cac:Contact/cbc:ElectronicMail", "billing@identity.example")

    def test_name_changes_supplier_legal_identity(self) -> None:
        self._write("efactura.company.name", "Identity Supplier SRL")

        document = self._document()
        self.assertEqual(
            document.findtext(f"{self.supplier_path}/cac:PartyName/cbc:Name", namespaces=NAMESPACES),
            "Identity Supplier SRL",
        )
        self.assertEqual(
            document.findtext(f"{self.supplier_path}/cac:PartyLegalEntity/cbc:RegistrationName", namespaces=NAMESPACES),
            "Identity Supplier SRL",
        )

    def test_phone_changes_supplier_contact(self) -> None:
        self._write("efactura.company.phone", "+40269123456")
        self._assert_supplier_text("cac:Contact/cbc:Telephone", "+40269123456")

    def test_postal_code_changes_supplier_postal_address(self) -> None:
        self._write("efactura.company.postal_code", "550001")
        self._assert_supplier_text("cac:PostalAddress/cbc:PostalZone", "550001")

    def test_registration_number_changes_supplier_legal_identity(self) -> None:
        self._write("efactura.company.registration_number", "J32/987/2026")
        self._assert_supplier_text("cac:PartyLegalEntity/cbc:CompanyID", "J32/987/2026")

    def test_street_changes_supplier_postal_address(self) -> None:
        self._write("efactura.company.street", "Identity Street 27")
        self._assert_supplier_text("cac:PostalAddress/cbc:StreetName", "Identity Street 27")
