"""Public plan-change documents must pass the real local fiscal export checks.

Only the shared fixture's native transport boundary is doubled. Quote, fiscal
snapshotting, conversion, UBL generation and CIUS-RO arithmetic run unchanged.
This is not Stripe, native quota or ANAF sandbox acceptance.
"""

from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import NAMESPACES, builder_for
from apps.billing.models import Invoice
from apps.billing.plan_change_models import PlanChange
from apps.billing.proforma_service import ProformaPaymentService
from apps.common.cui_validator import CUIValidator
from apps.customers.models import CustomerAddress, CustomerTaxProfile
from apps.settings.services import SettingsService
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


@override_settings(
    COMPANY_NAME="Fiscal Proof Supplier SRL",
    EFACTURA_COMPANY_CUI="12345674",
    COMPANY_REGISTRATION_NUMBER="J12/1234/2020",
    COMPANY_STREET="Strada Furnizorului 10",
    COMPANY_CITY="Cluj-Napoca",
    COMPANY_POSTAL_CODE="400001",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_EMAIL="supplier@example.test",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Fixture Bank",
)
class PlanChangeEFacturaTests(VerifiedPlanChangeCheckoutFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.assertTrue(CUIValidator.validate_strict("12345674").is_valid)
        self.assertTrue(CUIValidator.validate_strict("87654329").is_valid)
        profile = CustomerTaxProfile.objects.get(customer=self.customer)
        profile.cui, profile.vat_number = "87654329", "RO87654329"
        profile.save(update_fields=["cui", "vat_number"])
        CustomerAddress.objects.create(
            customer=self.customer,
            is_billing=True,
            address_line1="Strada Clientului 20",
            city="Cluj-Napoca",
            county="Cluj",
            postal_code="400002",
            country="Romania",
        )
        self.customer.refresh_from_db()
        self.assertTrue(SettingsService.update_setting("efactura.validation.schematron_enabled", True).is_ok())

    def paid_change(self) -> tuple[PlanChange, Invoice]:
        change = self.confirm(self.quote())
        self.assertEqual((change.net_cents, change.tax_cents, change.total_cents), (6000, 1260, 7260))
        self.assertEqual(change.status, "awaiting_payment")
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, change.from_plan_id)
        result = ProformaPaymentService.record_payment_and_convert(str(change.proforma_id), change.total_cents, "bank")
        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        change.refresh_from_db()
        self.assertEqual((invoice.status, change.status), ("paid", "applying_limits"))
        self.assertEqual((invoice.converted_from_proforma_id, change.invoice_id), (change.proforma_id, invoice.pk))
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), (6000, 1260, 7260))
        return change, invoice

    def text(self, document: etree._Element, path: str) -> str:
        element = document.find(path, NAMESPACES)
        if element is None or element.text is None:
            self.fail(f"Missing fiscal export element: {path}")
        return element.text

    def test_public_paid_upgrade_exports_accepted_period_and_fiscal_totals(self) -> None:
        change, invoice = self.paid_change()
        part = change.intervals.get()
        line = invoice.lines.get()
        self.assertEqual(line.service_id, self.service.pk)
        self.assertIsNone(line.billing_cycle_id)
        self.assertEqual(line.quantity, 1)
        expected_start = timezone.localdate(part.slice_start)
        expected_end = timezone.localdate(part.period_end)
        self.assertEqual(
            (line.period_start, line.period_end),
            (expected_start, expected_end),
        )
        self.assertIn(change.quote_snapshot["labels"]["from"], line.description)
        self.assertIn(change.quote_snapshot["labels"]["to"], line.description)

        xml = builder_for(invoice).build()
        validation = CIUSROValidator().validate(xml)
        self.assertTrue(validation.is_valid, validation.to_dict())
        document = etree.fromstring(xml.encode())
        self.assertEqual(self.text(document, "cbc:ID"), invoice.number)
        self.assertEqual(self.text(document, "cbc:DocumentCurrencyCode"), "RON")
        self.assertEqual(
            self.text(document, "cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID"),
            "RO12345674",
        )
        self.assertEqual(
            self.text(document, "cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID"),
            "RO87654329",
        )
        self.assertEqual(self.text(document, "cac:TaxTotal/cbc:TaxAmount"), "12.60")
        totals = "cac:LegalMonetaryTotal/"
        for field, expected in (
            ("LineExtensionAmount", "60.00"),
            ("TaxExclusiveAmount", "60.00"),
            ("TaxInclusiveAmount", "72.60"),
            ("PrepaidAmount", "72.60"),
            ("PayableAmount", "0.00"),
        ):
            with self.subTest(field=field):
                self.assertEqual(self.text(document, totals + "cbc:" + field), expected)
        exported_lines = document.findall("cac:InvoiceLine", NAMESPACES)
        self.assertEqual(len(exported_lines), 1)
        exported = exported_lines[0]
        self.assertEqual(self.text(exported, "cac:InvoicePeriod/cbc:StartDate"), expected_start.isoformat())
        self.assertEqual(self.text(exported, "cac:InvoicePeriod/cbc:EndDate"), expected_end.isoformat())
        self.assertEqual(self.text(exported, "cac:Item/cbc:Description"), line.description)
        item_name = self.text(exported, "cac:Item/cbc:Name")
        self.assertIn(change.quote_snapshot["labels"]["from"], item_name)
        self.assertIn(change.quote_snapshot["labels"]["to"], item_name)
        self.assertEqual(self.text(exported, "cac:Item/cac:ClassifiedTaxCategory/cbc:ID"), "S")
        self.assertEqual(self.text(exported, "cac:Item/cac:ClassifiedTaxCategory/cbc:Percent"), "21.00")
        self.assertEqual(Decimal(self.text(exported, "cbc:LineExtensionAmount")), Decimal("60.00"))

        replay = ProformaPaymentService.record_payment_and_convert(str(change.proforma_id), change.total_cents, "bank")
        self.assertTrue(replay.is_ok(), replay)
        self.assertEqual(replay.unwrap().pk, invoice.pk)
        self.assertEqual(builder_for(replay.unwrap()).build(), xml)

    def test_local_validator_checks_real_paid_document_arithmetic(self) -> None:
        _change, invoice = self.paid_change()
        document = etree.fromstring(builder_for(invoice).build().encode())
        total = document.find("cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount", NAMESPACES)
        if total is None:
            self.fail("The actual paid invoice has no tax-inclusive total")
        total.text = "72.61"
        result = CIUSROValidator().validate(etree.tostring(document, encoding="unicode"))
        self.assertFalse(result.is_valid, "Disabled arithmetic validation must not masquerade as fiscal proof")
        self.assertIn("BR-CO-15", {error.code for error in result.errors})
