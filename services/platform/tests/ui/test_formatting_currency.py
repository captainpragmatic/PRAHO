"""Malformed historical amounts must never acquire a fabricated RON zero."""

from decimal import Decimal

from django.template import Context, Template
from django.test import SimpleTestCase

from apps.billing.models import Currency
from apps.ui.templatetags.formatting import romanian_currency


class CurrencyFormattingTests(SimpleTestCase):
    def test_valid_amounts_keep_the_explicit_currency_and_sign(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                self.assertEqual(romanian_currency(Decimal("1234.56"), code), f"1.234,56 {code}")
                self.assertEqual(romanian_currency(Decimal("-123"), code), f"-123,00 {code}")
                self.assertEqual(romanian_currency(0, code), f"0,00 {code}")

    def test_invalid_values_keep_the_currency_but_mark_the_amount_unavailable(self) -> None:
        for value in (None, "", "invalid", Decimal("NaN"), Decimal("Infinity")):
            with self.subTest(value=value):
                self.assertEqual(romanian_currency(value, "EUR"), "— EUR")

    def test_missing_currency_is_unavailable_without_a_default_relabel(self) -> None:
        for code in (None, "", "unknown"):
            with self.subTest(currency=code):
                self.assertEqual(romanian_currency(Decimal("12.34"), code), "—")

    def test_cents_with_currency_model_render_the_recorded_code(self) -> None:
        template = Template("{% load formatting %}{{ amount|cents_to_currency|romanian_currency:currency }}")
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                currency = Currency(code=code, symbol="symbol")
                self.assertEqual(template.render(Context({"amount": 12100, "currency": currency})), f"121,00 {code}")
