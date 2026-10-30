"""A buyer's VAT identifier (BT-48) is stated only for a buyer recorded as VAT-registered.

A Romanian company can hold a CUI without being VAT-registered. bill_to_tax_id carries the VAT
number or, failing that, the bare CUI, so its presence says nothing about VAT registration.
The document's frozen VAT evidence does: its vat_number is the buyer's VAT number as decided at
issuance. `is_business` only means "has a company name".
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from itertools import count

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.billing.efactura.xml_builder import UBLCreditNoteBuilder, UBLInvoiceBuilder
from apps.billing.fiscal_identity import get_customer_fiscal_identity
from apps.billing.issuers.smartbill.mapper import SmartBillAccountConfig, build_invoice_payload
from apps.billing.services import _build_customer_vat_info
from apps.billing.tax_evidence import TaxEvidenceError, capture_vat_evidence, read_vat_evidence
from apps.common.tax_service import TaxService
from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import CustomerMembership, User
from tests.factories.billing_factories import CurrencyFactory, InvoiceFactory, InvoiceLineFactory
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin

NS = {
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
}
BUYER = "./cac:AccountingCustomerParty/cac:Party"
CUI = "14399840"
NUMBERS = count(1)
SMARTBILL = SmartBillAccountConfig(
    invoice_series="TEST", tax_names={"S:21.00": "Normala"}, company_vat_code="RO12345678"
)


def company(*, cui: str = CUI, vat_number: str = "", is_vat_payer: bool = True) -> Customer:
    customer = Customer.objects.create(
        name="Buyer SRL",
        company_name="Buyer SRL",
        customer_type="company",
        primary_email="buyer@example.test",
        status="active",
    )
    # is_vat_payer stays True for the CUI-only case: the model default, and what a staff
    # writer that never sets it leaves. A False flag would hide the bug (TaxService blanks it).
    CustomerTaxProfile.objects.create(customer=customer, cui=cui, vat_number=vat_number, is_vat_payer=is_vat_payer)
    return customer


def issued_invoice(customer: Customer, *, with_evidence: bool = True, bill_to_tax_id: str | None = None):
    """An invoice for `customer` whose evidence comes from the real issuance decision."""
    result = TaxService.calculate_vat_for_document(
        subtotal_cents=10000, customer_info=_build_customer_vat_info(customer, country="RO")
    )
    tax_id = get_customer_fiscal_identity(customer).business_tax_id if bill_to_tax_id is None else bill_to_tax_id
    invoice = InvoiceFactory(
        customer=customer,
        currency=CurrencyFactory(code="RON"),
        number=f"BT48-2026-{next(NUMBERS):03d}",
        status="issued",
        issued_at=datetime(2026, 9, 1, 9, tzinfo=UTC),
        due_at=datetime(2026, 10, 1, 9, tzinfo=UTC),
        bill_to_name="Buyer SRL",
        bill_to_country="RO",
        bill_to_tax_id=tax_id,
        bill_to_street="Str. Exemplu 1",
        bill_to_city="Cluj-Napoca",
        bill_to_postal_code="400001",
        subtotal_cents=result.subtotal_cents,
        tax_total_cents=result.vat_cents,
        total_cents=result.total_cents,
        vat_evidence=capture_vat_evidence(result) if with_evidence else {},
    )
    InvoiceLineFactory(
        invoice=invoice,
        description="Hosting",
        quantity=1,
        unit_price_cents=10000,
        tax_rate=Decimal(result.vat_rate) / 100,
    )
    return invoice


def buyer_party(invoice) -> etree._Element:
    root = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
    return root.find(BUYER, NS)


@override_settings(
    COMPANY_NAME="Supplier SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Supplier Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Supplier Bank",
)
class BuyerVATIdentifierTests(TestCase):
    def test_a_cui_only_company_gets_no_vat_identifier_but_keeps_its_legal_id(self) -> None:
        party = buyer_party(issued_invoice(company()))
        self.assertIsNone(party.find("./cac:PartyTaxScheme", NS))
        self.assertEqual(party.findtext("./cac:PartyLegalEntity/cbc:CompanyID", namespaces=NS), CUI)

    def test_a_vat_registered_company_keeps_its_vat_identifier(self) -> None:
        party = buyer_party(issued_invoice(company(vat_number=f"RO{CUI}")))
        self.assertEqual(party.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), f"RO{CUI}")

    def test_the_vat_identifier_carries_its_country_prefix(self) -> None:
        party = buyer_party(issued_invoice(company(vat_number=CUI)))
        self.assertEqual(party.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), f"RO{CUI}")

    def test_without_evidence_only_a_prefixed_vat_number_is_stated(self) -> None:
        cui_only = buyer_party(issued_invoice(company(), with_evidence=False, bill_to_tax_id=CUI))
        self.assertIsNone(cui_only.find("./cac:PartyTaxScheme", NS))
        vat = buyer_party(issued_invoice(company(), with_evidence=False, bill_to_tax_id=f"RO{CUI}"))
        self.assertEqual(vat.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), f"RO{CUI}")

    def test_smartbill_states_tax_payer_only_for_a_vat_registered_buyer(self) -> None:
        for customer, expected in ((company(), False), (company(vat_number=f"RO{CUI}"), True)):
            with self.subTest(expected=expected):
                result = build_invoice_payload(issued_invoice(customer), SMARTBILL)
                self.assertTrue(result.is_ok(), result)
                self.assertIs(result.unwrap().payload["client"]["isTaxPayer"], expected)


class NewTaxProfileTests(TestCase):
    def test_a_profile_created_with_only_a_cui_is_not_a_vat_payer(self) -> None:
        from apps.customers.profile_service import ProfileService  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        staff = User.objects.create_user(email="profile@example.test", is_staff=True)
        for vat_number, expected in (("", False), (f"RO{CUI}", True)):
            with self.subTest(vat_number=vat_number):
                customer = Customer.objects.create(
                    name=f"Profile {expected} SRL",
                    company_name=f"Profile {expected} SRL",
                    customer_type="company",
                    primary_email="p@example.test",
                    status="active",
                )
                extra = {"vat_number": vat_number} if vat_number else {}
                profile = ProfileService.create_tax_profile(customer, staff, cui=CUI, **extra)
                self.assertIs(profile.is_vat_payer, expected)


class ReverseChargeEvidenceTests(TestCase):
    def test_reverse_charge_evidence_must_name_the_buyer_vat_number(self) -> None:
        cache.clear()
        customer = Customer.objects.create(
            name="Evidence GmbH",
            company_name="Evidence GmbH",
            customer_type="company",
            primary_email="evidence@example.test",
        )
        CustomerTaxProfile.objects.create(
            customer=customer,
            vat_number="DE123456789",
            is_vat_payer=True,
            vies_verification_status="valid",
            reverse_charge_eligible=True,
            vies_verified_at=timezone.now(),
            vies_verified_name="Evidence GmbH",
            vies_consultation_reference="test-reference",
        )
        result = TaxService.calculate_vat_for_document(
            subtotal_cents=10000, customer_info=_build_customer_vat_info(customer, country="DE")
        )
        evidence = capture_vat_evidence(result)
        self.assertEqual(evidence["category"], "AE")
        invoice = InvoiceFactory(vat_evidence={**evidence, "vat_number": ""})
        with self.assertRaises(TaxEvidenceError):
            read_vat_evidence(invoice)


@override_settings(
    COMPANY_NAME="Supplier SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Supplier Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Supplier Bank",
)
class CreditNoteBuyerVATIdentifierTests(TestCase):
    def credit_note_party(self, invoice) -> etree._Element:
        root = etree.fromstring(UBLCreditNoteBuilder(invoice, invoice).build().encode())
        return root.find(BUYER, NS)

    def test_a_credit_note_states_the_vat_identifier_only_for_a_vat_registered_buyer(self) -> None:
        self.assertIsNone(self.credit_note_party(issued_invoice(company())).find("./cac:PartyTaxScheme", NS))
        party = self.credit_note_party(issued_invoice(company(vat_number=f"RO{CUI}")))
        self.assertEqual(party.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), f"RO{CUI}")

    def test_without_evidence_the_stated_number_is_normalised_like_the_evidence(self) -> None:
        party = buyer_party(issued_invoice(company(), with_evidence=False, bill_to_tax_id="GR 123-456.789"))
        self.assertEqual(party.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), "EL123456789")


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    COMPANY_NAME="Supplier SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Supplier Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Supplier Bank",
)
class VATNumberStorageTests(BoundSessionMixin, HMACTestMixin, TestCase):
    """A VAT number is stored with its prefix by every writer, so a document without evidence keeps it."""

    def setUp(self) -> None:
        self.owner = User.objects.create_user(email="vat-owner@example.test")
        self.customer = Customer.objects.create(
            name="Storage SRL", company_name="Storage SRL", customer_type="company", status="active"
        )
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_active=True)

    def post(self, path: str, **data: object) -> None:
        response = self.portal_post(path, {"customer_id": self.customer.pk, "user_id": self.owner.pk, **data})
        self.assertEqual(response.status_code, 200, response.content)

    def test_the_tax_profile_api_stores_the_prefix(self) -> None:
        self.post("/api/customers/tax-profile/", vat_number=CUI, is_vat_payer=True)
        self.assertEqual(CustomerTaxProfile.objects.get(customer=self.customer).vat_number, f"RO{CUI}")

    def test_the_billing_address_api_stores_the_prefix_of_the_billing_country(self) -> None:
        self.post(
            "/api/customers/billing-address/",
            country="DE",
            vat_number="136695976",
            address_line1="Teststrasse 1",
            city="Berlin",
        )
        self.assertEqual(CustomerTaxProfile.objects.get(customer=self.customer).vat_number, "DE136695976")

    def test_a_vat_payer_keeps_the_vat_identifier_on_a_document_without_evidence(self) -> None:
        # Staff proformas record no VAT evidence; their invoices state the stored tax ID.
        self.post("/api/customers/tax-profile/", vat_number=CUI, is_vat_payer=True)
        customer = Customer.objects.get(pk=self.customer.pk)  # As the proforma view loads it
        party = buyer_party(issued_invoice(customer, with_evidence=False))
        self.assertEqual(party.findtext("./cac:PartyTaxScheme/cbc:CompanyID", namespaces=NS), f"RO{CUI}")

    def test_a_profile_the_billing_address_api_creates_with_only_a_cui_is_not_a_vat_payer(self) -> None:
        self.post("/api/customers/billing-address/", fiscal_code=CUI, address_line1="Str. 1", city="Cluj-Napoca")
        self.assertIs(CustomerTaxProfile.objects.get(customer=self.customer).is_vat_payer, False)

    def test_a_profile_the_tax_profile_api_creates_with_only_a_cui_is_not_a_vat_payer(self) -> None:
        self.post("/api/customers/tax-profile/", cui=CUI)
        self.assertIs(CustomerTaxProfile.objects.get(customer=self.customer).is_vat_payer, False)

    def test_the_profile_service_keeps_an_existing_vat_payer_flag(self) -> None:
        from apps.customers.profile_service import ProfileService  # noqa: PLC0415

        CustomerTaxProfile.objects.create(customer=self.customer, vat_number=f"RO{CUI}", is_vat_payer=True)
        profile = ProfileService.create_tax_profile(self.customer, self.owner, cui=CUI)
        self.assertIs(profile.is_vat_payer, True)

    def test_adding_a_vat_number_later_makes_the_profile_a_vat_payer(self) -> None:
        # A CUI-only profile starts as a non-payer; a VAT number given later must not stay ignored.
        for path, first, then in (
            ("/api/customers/billing-address/", {"fiscal_code": CUI}, {"vat_number": f"RO{CUI}"}),
            ("/api/customers/tax-profile/", {"cui": CUI}, {"vat_number": f"RO{CUI}"}),
        ):
            with self.subTest(path=path):
                CustomerTaxProfile.objects.filter(customer=self.customer).delete()
                address = {"address_line1": "Str. 1", "city": "Cluj-Napoca"} if "billing" in path else {}
                self.post(path, **first, **address)
                self.assertIs(CustomerTaxProfile.objects.get(customer=self.customer).is_vat_payer, False)
                self.post(path, **then, **address)
                profile = CustomerTaxProfile.objects.get(customer=self.customer)
                self.assertEqual(profile.vat_number, f"RO{CUI}")
                self.assertIs(profile.is_vat_payer, True)
