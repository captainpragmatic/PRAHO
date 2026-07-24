"""
Tests for the add_years template filter.

Covers #285: the domain renewal template used |add_years but no filter existed,
so the "New expiry" line raised Invalid filter at render time.
"""

from datetime import date, datetime

from django.test import SimpleTestCase

from apps.ui.templatetags.formatting import add_years


class AddYearsFilterTestCase(SimpleTestCase):
    """add_years adds whole years to a date/datetime, with leap-year safety."""

    def test_adds_years_to_date(self) -> None:
        self.assertEqual(add_years(date(2026, 3, 15), 2), date(2028, 3, 15))

    def test_adds_years_to_datetime_preserves_time(self) -> None:
        self.assertEqual(
            add_years(datetime(2026, 3, 15, 8, 30), 1),
            datetime(2027, 3, 15, 8, 30),
        )

    def test_leap_day_rolls_back_to_feb_28_in_non_leap_year(self) -> None:
        self.assertEqual(add_years(date(2024, 2, 29), 1), date(2025, 2, 28))

    def test_leap_day_stays_feb_29_when_target_is_leap(self) -> None:
        self.assertEqual(add_years(date(2024, 2, 29), 4), date(2028, 2, 29))

    def test_string_year_offset_is_coerced(self) -> None:
        # Template variables often arrive as strings.
        self.assertEqual(add_years(date(2026, 1, 1), "3"), date(2029, 1, 1))

    def test_non_date_value_returned_unchanged(self) -> None:
        self.assertEqual(add_years("not a date", 1), "not a date")

    def test_non_numeric_offset_returns_value_unchanged(self) -> None:
        original = date(2026, 1, 1)
        self.assertEqual(add_years(original, "abc"), original)
