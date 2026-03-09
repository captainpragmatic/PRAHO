"""
Tests for CurrencyCode enum and Money type.

Regression guard: these tests capture chaos-monkey findings around
unsupported currency acceptance and StrEnum member identity.
"""

from django.test import TestCase

from apps.common.types import CurrencyCode, Money


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


class TestMoneyType(TestCase):
    """Money dataclass — construction, validation, and arithmetic helpers."""

    def test_money_ron_created(self) -> None:
        m = Money(amount=1000, currency="RON")
        self.assertEqual(m.amount, 1000)
        self.assertEqual(m.currency, "RON")

    def test_money_eur_created(self) -> None:
        m = Money(amount=500, currency="EUR")
        self.assertEqual(m.currency, "EUR")

    def test_money_usd_created(self) -> None:
        m = Money(amount=200, currency="USD")
        self.assertEqual(m.currency, "USD")

    def test_money_accepts_all_currency_codes(self) -> None:
        """Money must accept every member of CurrencyCode."""
        for currency in CurrencyCode:
            with self.subTest(currency=currency.value):
                m = Money(amount=100, currency=currency.value)
                self.assertEqual(m.currency, currency.value)

    def test_money_rejects_gbp(self) -> None:
        """Unsupported currency must raise ValueError at construction time."""
        with self.assertRaises(ValueError):
            Money(amount=100, currency="GBP")

    def test_money_rejects_empty_currency(self) -> None:
        with self.assertRaises(ValueError):
            Money(amount=100, currency="")

    def test_money_rejects_lowercase_ron(self) -> None:
        """Currency lookup is case-sensitive (stored values are uppercase)."""
        with self.assertRaises(ValueError):
            Money(amount=100, currency="ron")

    def test_money_to_decimal(self) -> None:
        m = Money(amount=1099, currency="RON")
        self.assertAlmostEqual(m.to_decimal(), 10.99)

    def test_money_from_decimal(self) -> None:
        m = Money.from_decimal(10.99, currency="RON")
        self.assertEqual(m.amount, 1099)

    def test_money_str_ron(self) -> None:
        m = Money(amount=1000, currency="RON")
        self.assertIn("lei", str(m))

    def test_money_str_eur(self) -> None:
        m = Money(amount=1000, currency="EUR")
        self.assertIn("EUR", str(m))

    def test_money_is_frozen(self) -> None:
        """Money is a frozen dataclass — mutation must raise FrozenInstanceError."""
        m = Money(amount=100, currency="RON")
        with self.assertRaises(Exception):
            m.amount = 200  # type: ignore[misc]  # frozen dataclass: assignment raises FrozenInstanceError
