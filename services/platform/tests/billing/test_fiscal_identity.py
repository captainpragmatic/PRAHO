"""Fiscal identity snapshot invariants for Romanian billing documents."""

from datetime import timedelta

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.fiscal_identity import billing_country_code, get_customer_fiscal_identity, normalize_country_code
from apps.billing.invoice_models import Invoice
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import CustomerTaxProfile
from tests.factories import CurrencyFactory, CustomerFactory


class FiscalIdentityTests(TestCase):
    def setUp(self) -> None:
        self.currency = CurrencyFactory(code="RON")
        self.customer = CustomerFactory(customer_type="individual", company_name="")

    def test_business_identifier_takes_precedence_over_personal_identifier(self) -> None:
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="RO12345678",
            cnp="1850101123451",
        )

        identity = get_customer_fiscal_identity(self.customer)

        self.assertEqual(identity.business_tax_id, "RO12345678")
        self.assertEqual(identity.cnp, "")

    def test_invalid_personal_identifier_is_not_snapshotted(self) -> None:
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cnp="1850101123456",
        )

        identity = get_customer_fiscal_identity(self.customer)

        self.assertEqual(identity.business_tax_id, "")
        self.assertEqual(identity.cnp, "")

    def test_romanian_country_names_are_normalized_to_iso_code(self) -> None:
        self.assertEqual(normalize_country_code(" România "), "RO")
        self.assertEqual(normalize_country_code("romania"), "RO")

    def test_foreign_country_names_are_normalized_to_iso_code(self) -> None:
        self.assertEqual(normalize_country_code(" Germany "), "DE")
        self.assertEqual(normalize_country_code("Germania"), "DE")

    def test_unknown_country_names_do_not_escape_into_two_character_snapshots(self) -> None:
        self.assertEqual(normalize_country_code("Not a country"), "")
        self.assertEqual(normalize_country_code("XX"), "")

    def test_billing_country_defaults_only_when_the_source_is_blank(self) -> None:
        self.assertEqual(billing_country_code(""), "RO")
        with self.assertRaisesMessage(ValueError, "Unknown billing country"):
            billing_country_code("Not a country")
        with self.assertRaisesMessage(ValueError, "Unknown billing country"):
            billing_country_code("XX")

    def test_invoice_rejects_simultaneous_business_and_personal_identifiers(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number="INV-FISCAL-BOTH",
                bill_to_tax_id="RO12345678",
                bill_to_cnp="1850101123451",
            )

    def test_proforma_rejects_simultaneous_business_and_personal_identifiers(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            ProformaInvoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number="PRO-FISCAL-BOTH",
                valid_until=timezone.now() + timedelta(days=30),
                bill_to_tax_id="RO12345678",
                bill_to_cnp="1850101123451",
            )
