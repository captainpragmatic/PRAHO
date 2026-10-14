"""The checkout trust signals state facts about the service, never a jurisdiction (ADR-0058)."""

from __future__ import annotations

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import translation


class TrustSignalsTests(SimpleTestCase):
    def test_the_signals_name_no_country_or_data_center(self) -> None:
        with translation.override("en"):
            markup = render_to_string("orders/partials/trust_signals.html")
        self.assertIn("VAT Included", markup)
        self.assertIn("24/7 Support", markup)
        # A deployment may run anywhere: no badge claims where the data lives.
        for claim in ("Romanian", "Data Center"):
            self.assertNotIn(claim, markup)
