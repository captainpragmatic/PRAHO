"""
Formatting Template Filter Tests

Tests for the as_percentage filter in apps.ui.templatetags.formatting.
No database access — pure filter logic.
"""

import unittest
from decimal import Decimal

from apps.ui.templatetags.formatting import as_percentage


class AsPercentageFilterTestCase(unittest.TestCase):
    """Tests for the as_percentage template filter."""

    def test_standard_vat_rate(self):
        """Decimal('0.21') (21% VAT) should return Decimal('21')."""
        result = as_percentage(Decimal('0.21'))
        self.assertEqual(result, Decimal('21'))

    def test_low_rate(self):
        """Decimal('0.05') should return Decimal('5')."""
        result = as_percentage(Decimal('0.05'))
        self.assertEqual(result, Decimal('5'))

    def test_zero_rate(self):
        """Decimal('0') should return Decimal('0')."""
        result = as_percentage(Decimal('0'))
        self.assertEqual(result, Decimal('0'))

    def test_full_rate(self):
        """Decimal('1.0') should return Decimal('100')."""
        result = as_percentage(Decimal('1.0'))
        self.assertEqual(result, Decimal('100'))

    def test_none_input_returns_zero(self):
        """None input should return Decimal('0') gracefully."""
        result = as_percentage(None)
        self.assertEqual(result, Decimal('0'))

    def test_invalid_string_returns_zero(self):
        """Non-numeric string should return Decimal('0') without raising."""
        result = as_percentage('invalid')  # type: ignore[arg-type]
        self.assertEqual(result, Decimal('0'))

    def test_integer_input(self):
        """Plain integer 0 should be treated as 0%."""
        result = as_percentage(0)
        self.assertEqual(result, Decimal('0'))

    def test_float_input(self):
        """Float 0.19 should convert to Decimal('19')."""
        result = as_percentage(0.19)
        self.assertAlmostEqual(float(result), 19.0, places=5)

    def test_returns_decimal_type(self):
        """Return type should always be Decimal."""
        result = as_percentage(Decimal('0.21'))
        self.assertIsInstance(result, Decimal)

    def test_none_returns_decimal_type(self):
        """Even for None input, return type should be Decimal."""
        result = as_percentage(None)
        self.assertIsInstance(result, Decimal)

    def test_partial_rate(self):
        """Decimal('0.095') (9.5%) should return Decimal('9.5')."""
        result = as_percentage(Decimal('0.095'))
        self.assertEqual(result, Decimal('9.5'))
