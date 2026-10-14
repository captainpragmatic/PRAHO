"""Production must not issue documents under a placeholder seller.

Invoices, PDFs and the VIES requester read the seller's identity from the environment
(``COMPANY_NAME``, ``COMPANY_CUI``). Base settings default both to blank so no deployment
ever prints a real-looking placeholder; production refuses to start until they are set.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.settings.test_media_storage import _settings_module

_PROD = "config.settings.prod"


class ProdFiscalIdentityTests(SimpleTestCase):
    def test_prod_refuses_blank_company_name_or_cui(self) -> None:
        for missing in ("COMPANY_NAME", "COMPANY_CUI"):
            with self.subTest(missing=missing), self.assertRaisesMessage(ImproperlyConfigured, missing):
                _settings_module(_PROD, {missing: ""})

    def test_whitespace_only_counts_as_blank(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "COMPANY_NAME"):
            _settings_module(_PROD, {"COMPANY_NAME": "   "})

    def test_configured_identity_is_what_production_uses(self) -> None:
        prod = _settings_module(_PROD, {"COMPANY_NAME": "Acme Hosting SRL", "COMPANY_CUI": "RO12345674"})
        self.assertEqual(prod.COMPANY_NAME, "Acme Hosting SRL")
        self.assertEqual(prod.COMPANY_CUI, "RO12345674")
