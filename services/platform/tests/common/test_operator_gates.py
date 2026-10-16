"""Romanian operator features follow the operator's country (ADR-0047 addendum).

e-Factura, D390, SmartBill and ROTLD only make sense for an operator established in Romania. One
predicate, `operator_serves()`, gates them all; settings for them are hidden elsewhere. An operator
outside the EU is refused at deploy, because the tax engine assumes an EU supplier.
"""

from __future__ import annotations

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from apps.billing.efactura.settings import efactura_enabled
from apps.billing.fiscal_identity import billing_country_code
from apps.billing.issuers.policy import default_issuer_provider
from apps.billing.vies_evidence import profile_vat_identity
from apps.common.checks import check_operator_clock, check_operator_jurisdiction
from apps.common.localisation_services import get_localisation_defaults
from apps.common.operator import operator_in_eu, operator_is_romanian, operator_serves
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.gateways.base import RegistrarGatewayFactory
from apps.domains.models import TLD, Registrar, TLDRegistrarAssignment
from apps.domains.services import RegistrarService
from apps.orders.services import OrderService
from apps.settings.catalog import ZONE_INTEGRATIONS, groups_in_zone
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user

GERMAN = {"COMPANY_COUNTRY_CODE": "DE"}


class OperatorPredicateTests(SimpleTestCase):
    def test_romania_is_the_reference_operator(self) -> None:
        self.assertTrue(operator_is_romanian())
        self.assertTrue(operator_serves("RO"))
        self.assertTrue(operator_serves(""))

    @override_settings(**GERMAN)
    def test_a_german_operator_is_served_by_no_romanian_feature(self) -> None:
        self.assertFalse(operator_is_romanian())
        self.assertFalse(operator_serves("RO"))
        self.assertTrue(operator_serves(""))
        self.assertTrue(operator_in_eu())

    @override_settings(COMPANY_COUNTRY_CODE="GR")
    def test_greece_counts_as_eu_by_its_iso_code(self) -> None:
        self.assertTrue(operator_in_eu())


@override_settings(DEBUG=False)
class OperatorJurisdictionCheckTests(SimpleTestCase):
    @override_settings(COMPANY_COUNTRY_CODE="US")
    def test_an_operator_outside_the_eu_is_refused(self) -> None:
        self.assertEqual([m.id for m in check_operator_jurisdiction()], ["common.E003"])

    @override_settings(COMPANY_COUNTRY_CODE="XX")
    def test_an_unknown_country_code_is_refused(self) -> None:
        self.assertEqual([m.id for m in check_operator_jurisdiction()], ["common.E003"])

    @override_settings(**GERMAN)
    def test_an_eu_operator_passes(self) -> None:
        self.assertEqual(check_operator_jurisdiction(), [])

    def test_an_operator_in_romania_runs_on_bucharest_time(self) -> None:
        self.assertEqual(check_operator_clock(), [])
        with override_settings(TIME_ZONE="Europe/Berlin"):
            self.assertEqual([m.id for m in check_operator_clock()], ["common.E004"])
        with override_settings(TIME_ZONE="Europe/Berlin", **GERMAN):
            self.assertEqual(check_operator_clock(), [])

    @override_settings(TIME_ZONE="Europe/Atlantis", **GERMAN)
    def test_an_unknown_zone_is_refused(self) -> None:
        self.assertEqual([m.id for m in check_operator_clock()], ["common.E004"])


class RomanianFeatureGateTests(TestCase):
    def setUp(self) -> None:
        cache.clear()

    @override_settings(EFACTURA_ENABLED=True, **GERMAN)
    def test_de_operator_gets_no_efactura_d390_smartbill_rotld_or_ro_settings(self) -> None:
        self.assertFalse(efactura_enabled())

        SystemSetting.objects.update_or_create(
            key="billing.invoice_issuer",
            defaults={"name": "Issuer", "category": "billing", "data_type": "string", "value": "smartbill",
                      "default_value": "builtin"},
        )
        cache.clear()
        self.assertEqual(default_issuer_provider(), "builtin")
        refusal = SettingsService.update_setting("billing.invoice_issuer", "smartbill", reason="test")
        self.assertEqual(refusal.error.code, "unknown_issuer")

        registrar = Registrar(name="rotld", display_name="ROTLD")
        with self.assertRaisesMessage(ValueError, "Romania"):
            RegistrarGatewayFactory.create_gateway(registrar)

        slugs = {group.slug for group in groups_in_zone(ZONE_INTEGRATIONS)}
        self.assertNotIn("efactura", slugs)
        self.assertNotIn("smartbill", slugs)

        self.client.force_login(create_admin_user("gate-admin"))
        self.assertEqual(self.client.get(reverse("settings:group", args=["efactura"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("billing:d390_report")).status_code, 404)
        self.assertNotContains(self.client.get(reverse("billing:reports")), reverse("billing:d390_report"))

    def test_a_dot_ro_domain_skips_rotld_for_a_german_operator(self) -> None:
        tld = TLD.objects.create(
            extension="ro", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        rotld = Registrar.objects.create(name="rotld", display_name="ROTLD", status="active")
        other = Registrar.objects.create(name="other-registrar", display_name="Other", status="active")
        TLDRegistrarAssignment.objects.create(tld=tld, registrar=rotld, is_primary=True, priority=1)
        TLDRegistrarAssignment.objects.create(tld=tld, registrar=other, is_primary=False, priority=2)

        self.assertEqual(RegistrarService.select_best_registrar_for_tld(tld), rotld)
        with override_settings(**GERMAN):
            self.assertEqual(RegistrarService.select_best_registrar_for_tld(tld), other)

    @override_settings(EFACTURA_ENABLED=True)
    def test_ro_operator_keeps_them(self) -> None:
        self.assertTrue(efactura_enabled())
        slugs = {group.slug for group in groups_in_zone(ZONE_INTEGRATIONS)}
        self.assertIn("efactura", slugs)

        self.client.force_login(create_admin_user("gate-admin"))
        self.assertContains(self.client.get(reverse("billing:reports")), reverse("billing:d390_report"))


class CustomerCountryFallbackTests(TestCase):
    """A customer with no billing country is placed in the operator's country, not in Romania."""

    @override_settings(**GERMAN)
    def test_blank_customer_country_falls_back_to_a_german_operator(self) -> None:
        self.assertEqual(billing_country_code(""), "DE")

        customer = Customer.objects.create(customer_type="company", company_name="Kunde GmbH", status="active")
        self.assertEqual(OrderService.build_billing_address_from_customer(customer)["country"], "DE")

        profile = CustomerTaxProfile.objects.create(customer=customer, vat_number="811115368")
        self.assertEqual(profile_vat_identity(profile), ("DE", "811115368"))

    @override_settings(**GERMAN)
    def test_new_customers_start_in_the_operators_country_until_staff_choose_another(self) -> None:
        SystemSetting.objects.filter(key="system.default_country").delete()
        cache.clear()
        self.assertEqual(get_localisation_defaults().default_country, "DE")

        SettingsService.update_setting("system.default_country", "AT", reason="test")
        self.assertEqual(get_localisation_defaults().default_country, "AT")
