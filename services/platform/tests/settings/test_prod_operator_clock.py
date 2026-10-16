"""Production runs on the operator's clock (ADR-0041 addendum).

Business dates follow TIME_ZONE. A Romanian operator keeps Europe/Bucharest, because e-Factura
dates and the VAT tax point are Romanian calendar days; any other operator names its own zone,
since a country does not determine one.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.settings.test_media_storage import _settings_module

_PROD = "config.settings.prod"


class ProdOperatorClockTests(SimpleTestCase):
    def test_a_romanian_operator_runs_on_bucharest_time(self) -> None:
        self.assertEqual(_settings_module(_PROD, {"TIME_ZONE": ""}).TIME_ZONE, "Europe/Bucharest")
        with self.assertRaisesMessage(ImproperlyConfigured, "Europe/Bucharest"):
            _settings_module(_PROD, {"TIME_ZONE": "Europe/Berlin"})

    def test_another_operator_names_its_own_zone(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "TIME_ZONE"):
            _settings_module(_PROD, {"COMPANY_COUNTRY_CODE": "DE", "TIME_ZONE": ""})
        prod = _settings_module(_PROD, {"COMPANY_COUNTRY_CODE": "DE", "TIME_ZONE": "Europe/Berlin"})
        self.assertEqual(prod.TIME_ZONE, "Europe/Berlin")
