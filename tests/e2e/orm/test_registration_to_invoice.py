"""A customer's fiscal identity, given at registration, reaches their e-Factura invoice.

Before, Platform dropped the CNP the portal sent, and every individual registered through the
portal was invoiced with the placeholder CNP. A company without VAT registration could give no
CUI, and a bare tax ID was stated as a VAT identifier.
"""

import pytest
from django.test import override_settings
from lxml import etree

from apps.billing.efactura.xml_builder import UBLInvoiceBuilder
from apps.orders.services import OrderService
from tests.e2e.orm.test_signup_workflow import RegistrationCase
from tests.e2e.orm.workflow import WorkflowCase

pytestmark = pytest.mark.e2e

CNP = "1900101123457"
CUI = "14399840"
PLACEHOLDER_CNP = "0000000000000"
NS = {
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
}


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
class RegistrationToInvoiceTests(RegistrationCase, WorkflowCase):
    def setUp(self):
        WorkflowCase.setUp(self)
        RegistrationCase.setUp(self)

    def invoice_for(self, customer):
        """Order and pay as the registered customer, with the billing address the order flow builds."""
        self.customer = customer
        self.address = dict(OrderService.build_billing_address_from_customer(customer))
        return self.pay(self.create_order())

    def buyer(self, invoice):
        root = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        return root.find("./cac:AccountingCustomerParty/cac:Party", NS)

    def test_a_romanian_individual_is_invoiced_with_their_cnp(self):
        _user, customer = self.register(individual=True)
        invoice = self.invoice_for(customer)
        self.assertEqual(invoice.bill_to_cnp, CNP)
        party = self.buyer(invoice)
        legal_id = party.findtext("./cac:PartyLegalEntity/cbc:CompanyID", namespaces=NS)
        self.assertEqual(legal_id, CNP)
        self.assertNotIn(PLACEHOLDER_CNP, etree.tostring(party).decode())

    def test_a_company_with_only_a_cui_states_no_vat_identifier(self):
        payload = self.payload()
        payload["customer_data"].update(vat_number="", cui=f"RO{CUI}", registration_number="J40/1234/2020")
        self.payload = lambda **_kwargs: payload  # register() submits this company
        _user, customer = self.register()
        self.assertEqual(customer.tax_profile.cui, CUI)
        self.assertFalse(customer.tax_profile.is_vat_payer)
        party = self.buyer(self.invoice_for(customer))
        self.assertIsNone(party.find("./cac:PartyTaxScheme", NS))
        self.assertEqual(party.findtext("./cac:PartyLegalEntity/cbc:CompanyID", namespaces=NS), CUI)
