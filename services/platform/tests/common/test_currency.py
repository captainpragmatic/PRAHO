"""
Tests for the CurrencyCode enum.

Regression guard: these tests capture chaos-monkey findings around
unsupported currency acceptance and StrEnum member identity.
"""

from django.test import TestCase

from apps.common.types import CurrencyCode


class TestCurrencyCodeEnum(TestCase):
    """CurrencyCode StrEnum — member values and class methods."""

    def test_ron_member_value(self) -> None:
        self.assertEqual(CurrencyCode.RON, "RON")

    def test_eur_member_value(self) -> None:
        self.assertEqual(CurrencyCode.EUR, "EUR")

    def test_usd_member_value(self) -> None:
        self.assertEqual(CurrencyCode.USD, "USD")

    def test_all_three_currencies_present(self) -> None:
        """RON, EUR, and USD must all be supported — no more, no fewer."""
        members = {c.value for c in CurrencyCode}
        self.assertIn("RON", members)
        self.assertIn("EUR", members)
        self.assertIn("USD", members)

    def test_strenum_member_is_str_instance(self) -> None:
        """StrEnum members must be str instances (Python 3.11+ guarantee)."""
        self.assertIsInstance(CurrencyCode.RON, str)
        self.assertIsInstance(CurrencyCode.EUR, str)
        self.assertIsInstance(CurrencyCode.USD, str)

    def test_member_equals_plain_string(self) -> None:
        """StrEnum members must compare equal to their plain-string equivalents."""
        self.assertEqual(CurrencyCode.RON, "RON")
        self.assertNotEqual(CurrencyCode.RON, "ron")


class TestCurrencyCodeChoices(TestCase):
    """CurrencyCode.choices() — Django-compatible format."""

    def test_choices_returns_list(self) -> None:
        choices = CurrencyCode.choices()
        self.assertIsInstance(choices, list)

    def test_choices_has_three_entries(self) -> None:
        choices = CurrencyCode.choices()
        self.assertEqual(len(choices), 3)

    def test_choices_are_two_tuples(self) -> None:
        for item in CurrencyCode.choices():
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

    def test_choices_contains_ron_tuple(self) -> None:
        self.assertIn(("RON", "RON"), CurrencyCode.choices())

    def test_choices_contains_eur_tuple(self) -> None:
        self.assertIn(("EUR", "EUR"), CurrencyCode.choices())

    def test_choices_contains_usd_tuple(self) -> None:
        self.assertIn(("USD", "USD"), CurrencyCode.choices())


class TestCurrencyCodeIsSupported(TestCase):
    """CurrencyCode.is_supported() — case-insensitive membership check."""

    def test_ron_supported_uppercase(self) -> None:
        self.assertTrue(CurrencyCode.is_supported("RON"))

    def test_eur_supported_uppercase(self) -> None:
        self.assertTrue(CurrencyCode.is_supported("EUR"))

    def test_usd_supported_uppercase(self) -> None:
        self.assertTrue(CurrencyCode.is_supported("USD"))

    def test_ron_supported_lowercase(self) -> None:
        self.assertTrue(CurrencyCode.is_supported("ron"))

    def test_eur_supported_mixed_case(self) -> None:
        self.assertTrue(CurrencyCode.is_supported("Eur"))

    def test_gbp_not_supported(self) -> None:
        self.assertFalse(CurrencyCode.is_supported("GBP"))

    def test_empty_string_not_supported(self) -> None:
        self.assertFalse(CurrencyCode.is_supported(""))

    def test_unknown_code_not_supported(self) -> None:
        self.assertFalse(CurrencyCode.is_supported("XYZ"))
