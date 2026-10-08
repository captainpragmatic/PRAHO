"""D390 identity remains deployment-only when e-Factura overrides change."""

from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase, override_settings
from lxml import etree

from apps.billing.d390 import render_d390_xml
from apps.billing.ec_sales_service import aggregate_ec_services
from apps.billing.efactura.xml_builder import NAMESPACES, UBLInvoiceBuilder
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.billing.test_d390 import DECLARANT, PERIOD, SUPPLIER, D390FixtureMixin


@override_settings(
    **SUPPLIER,
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Deployment Bank",
)
class D390SupplierPreservationTests(D390FixtureMixin, TestCase):
    def test_efactura_identity_edits_preserve_the_reconciled_d390_export(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.company.").delete()
        invoice = self.make_invoice()
        report = aggregate_ec_services(PERIOD)
        self.assertTrue(report.can_export, report.exceptions)
        before = render_d390_xml(report, DECLARANT)
        stored = {
            "name": "UBL Supplier SRL",
            "cui": "RO18547293",
            "street": "UBL Street 9",
            "city": "Sibiu",
            "postal_code": "550001",
        }
        for key, value in stored.items():
            result = SettingsService.update_setting(f"efactura.company.{key}", value)
            self.assertTrue(result.is_ok(), str(result))
        self.assertEqual(render_d390_xml(report, DECLARANT), before)
        ubl = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        party = "./cac:AccountingSupplierParty/cac:Party/"
        self.assertEqual(
            ubl.findtext(party + "cac:PartyLegalEntity/cbc:RegistrationName", namespaces=NAMESPACES), stored["name"]
        )
        self.assertEqual(ubl.findtext(party + "cac:PartyIdentification/cbc:ID", namespaces=NAMESPACES), "18547293")
