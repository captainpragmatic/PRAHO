"""The registration page's company lookup answers from ANAF's register only (ADR-0021).

It reads none of PRAHO's customers, so it says nothing about who is registered with the operator.
It answers `available: false` while the lookup is off (another operator country, the setting, no
connection to ANAF) or ANAF did not answer; each client IP has a budget, and all lookups together a
global one. The portal shows the lookup only while Platform's public defaults offer it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.billing.gateways.anaf_gateway import AnafCompany, AnafLookup
from apps.customers.models import Customer, CustomerTaxProfile
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

CUI = "14399840"
DEFAULTS_URL = "/api/localisation/"
COMPANY = AnafCompany(
    cui=CUI,
    name="DANTE INTERNATIONAL SA",
    registration_number="J2002000372404",
    vat_registered=True,
    street="Şos. Virtuţii 148",
    city="Sector 6 Mun. Bucureşti",
    county="MUNICIPIUL BUCUREŞTI",
    postal_code="60787",
)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    ANAF_TRANSPORT_ENABLED=True,
    COMPANY_COUNTRY_CODE="RO",
)
class CompanyLookupAPITests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def ask(self, cui: str, answer: AnafLookup | None = None) -> Any:
        with patch("apps.billing.gateways.anaf_gateway.AnafGateway.lookup", return_value=answer) as lookup:
            response = self.portal_post("/api/customers/company-lookup/", {"cui": cui})
        return response, lookup

    def test_a_found_company_comes_from_anaf_and_no_customer_is_read(self) -> None:
        with CaptureQueriesContext(connection) as queries:
            response, lookup = self.ask(f"RO{CUI}", AnafLookup(api_available=True, companies={CUI: COMPANY}))
        self.assertEqual(response.status_code, 200, response.content)
        lookup.assert_called_once_with([CUI])
        company = response.json()["company"]
        self.assertEqual(
            (company["name"], company["vat_number"], company["registration_number"], company["postal_code"]),
            ("DANTE INTERNATIONAL SA", f"RO{CUI}", "J2002000372404", "60787"),
        )
        read = " ".join(query["sql"] for query in queries.captured_queries)
        for table in (Customer._meta.db_table, CustomerTaxProfile._meta.db_table):
            self.assertNotIn(table, read)

    def test_not_found_unavailable_and_invalid(self) -> None:
        response, _ = self.ask(CUI, AnafLookup(api_available=True, not_found=frozenset({CUI})))
        self.assertEqual(response.json(), {"success": True, "available": True, "found": False})
        response, _ = self.ask(CUI, AnafLookup(api_available=False))
        self.assertEqual(response.json(), {"success": True, "available": False})
        response, lookup = self.ask("14399841")
        self.assertEqual(response.status_code, 400)
        lookup.assert_not_called()

    def test_off_for_another_operator_country_or_without_anaf(self) -> None:
        for overrides in ({"COMPANY_COUNTRY_CODE": "DE"}, {"ANAF_TRANSPORT_ENABLED": False}):
            with self.subTest(**overrides), override_settings(**overrides):
                response, lookup = self.ask(CUI)
                self.assertEqual(response.json(), {"success": True, "available": False})
                lookup.assert_not_called()

    @override_settings(RATE_LIMITING_ENABLED=True)
    def test_all_lookups_share_a_global_budget(self) -> None:
        found = AnafLookup(api_available=True, companies={CUI: COMPANY})
        with patch("apps.api.customers.views.fixed_window_limited", return_value=(True, 12)):
            response, lookup = self.ask(CUI, found)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "12")
        lookup.assert_not_called()

    def test_the_public_defaults_offer_the_lookup_only_while_it_is_on(self) -> None:
        response = self.portal_post(DEFAULTS_URL, {})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIs(response.json()["features"]["company_lookup"], True)
        with override_settings(COMPANY_COUNTRY_CODE="DE"):
            response = self.portal_post(DEFAULTS_URL, {})
        self.assertIs(response.json()["features"]["company_lookup"], False)
