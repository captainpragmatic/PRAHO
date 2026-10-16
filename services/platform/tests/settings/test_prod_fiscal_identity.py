"""Production must not issue documents under a placeholder seller.

Invoices, PDFs and the VIES requester read the seller's identity from the environment
(``COMPANY_NAME``, ``COMPANY_CUI``), and Romanian-only features follow ``COMPANY_COUNTRY_CODE``.
Base settings default all three to blank so no deployment ever prints a real-looking placeholder
or is silently treated as Romanian; production refuses to start until they are set.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.settings.test_media_storage import _settings_module

_PROD = "config.settings.prod"


class ProdFiscalIdentityTests(SimpleTestCase):
    def test_prod_refuses_blank_company_name_cui_or_country_code(self) -> None:
        for missing in ("COMPANY_NAME", "COMPANY_CUI", "COMPANY_COUNTRY_CODE"):
            with self.subTest(missing=missing), self.assertRaisesMessage(ImproperlyConfigured, missing):
                _settings_module(_PROD, {missing: ""})

    def test_whitespace_only_counts_as_blank(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "COMPANY_NAME"):
            _settings_module(_PROD, {"COMPANY_NAME": "   "})

    def test_configured_identity_is_what_production_uses(self) -> None:
        prod = _settings_module(
            _PROD,
            {
                "COMPANY_NAME": "Acme Hosting SRL",
                "COMPANY_CUI": "DE811115368",
                "COMPANY_COUNTRY_CODE": " DE ",
                "TIME_ZONE": "Europe/Berlin",
            },
        )
        self.assertEqual(prod.COMPANY_NAME, "Acme Hosting SRL")
        self.assertEqual(prod.COMPANY_CUI, "DE811115368")
        self.assertEqual(prod.COMPANY_COUNTRY_CODE, "DE")
