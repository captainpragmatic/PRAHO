"""
Formatting Template Filter Tests

Tests for the as_percentage filter in apps.ui.templatetags.formatting.
No database access — pure filter logic.
"""

import unittest
from datetime import UTC, date, datetime
from decimal import Decimal

from django.test import TestCase

from apps.ui.templatetags.formatting import as_percentage, romanian_date


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


class RomanianDateFilterTimezoneTestCase(TestCase):
    """#286: romanian_date must render the Romanian calendar, not the UTC one.

    The formatters read .day/.month/.year off the value directly, which opts out of Django's
    template localization — so an aware (UTC) datetime rendered the UTC day. This filter is used
    on customer-facing billing pages (proforma valid_until, invoice dates).
    """

    def test_aware_datetime_renders_romanian_day_across_utc_midnight(self):
        """2025-12-31 22:30 UTC is 2026-01-01 00:30 in Romania — the wrong YEAR if unconverted."""
        aware = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, 'long'), '1 ianuarie 2026')

    def test_aware_datetime_renders_romanian_clock(self):
        """The datetime format must show the Romanian wall clock, not 22:30 UTC."""
        aware = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, 'datetime'), '1 ian. 2026, 00:30')

    def test_aware_datetime_summer_offset(self):
        """Romania is EEST (UTC+3) in summer; a hardcoded +2 would render 15 iunie."""
        aware = datetime(2026, 6, 15, 21, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, 'short'), '16 iun. 2026')

    def test_plain_date_is_passed_through_untouched(self):
        """A date carries no timezone; converting it would raise. It must render as given."""
        self.assertEqual(romanian_date(date(2026, 1, 15), 'long'), '15 ianuarie 2026')

    def test_naive_datetime_is_passed_through_untouched(self):
        """A naive datetime has no timezone to convert from — render its wall clock as given."""
        self.assertEqual(romanian_date(datetime(2025, 12, 31, 22, 30), 'long'), '31 decembrie 2025')
