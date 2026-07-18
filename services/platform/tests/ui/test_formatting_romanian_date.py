"""
Tests for the romanian_date template filter's timezone handling.
Covers #286: the filter rendered the UTC calendar day instead of the Romanian one.
"""

from datetime import UTC, date, datetime

from django.test import TestCase

from apps.ui.templatetags.formatting import romanian_date


class RomanianDateFilterTimezoneTestCase(TestCase):
    """#286: romanian_date must render the Romanian calendar, not the UTC one.

    The formatters read .day/.month/.year off the value directly, which opts out of Django's
    template localization — so an aware (UTC) datetime rendered the UTC day. Django's own
    {{ value|date }} filter localizes correctly; only this Romanian-branded filter did not.
    """

    def test_aware_datetime_renders_romanian_day_across_utc_midnight(self) -> None:
        """2025-12-31 22:30 UTC is 2026-01-01 00:30 in Romania — the wrong YEAR if unconverted."""
        aware = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, "long"), "1 ianuarie 2026")

    def test_aware_datetime_renders_romanian_clock(self) -> None:
        """The datetime format must show the Romanian wall clock, not 22:30 UTC."""
        aware = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, "datetime"), "1 ian. 2026, 00:30")

    def test_aware_datetime_summer_offset(self) -> None:
        """Romania is EEST (UTC+3) in summer; a hardcoded +2 offset would render 15 iun."""
        aware = datetime(2026, 6, 15, 21, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, "short"), "16 iun. 2026")

    def test_time_only_format_uses_romanian_clock(self) -> None:
        """The time-only format reads .hour/.minute and must also be converted."""
        aware = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)

        self.assertEqual(romanian_date(aware, "time"), "00:30")

    def test_plain_date_is_passed_through_untouched(self) -> None:
        """A date carries no timezone; converting it would raise. It must render as given."""
        self.assertEqual(romanian_date(date(2026, 1, 15), "long"), "15 ianuarie 2026")

    def test_naive_datetime_is_passed_through_untouched(self) -> None:
        """A naive datetime has no timezone to convert from — render its wall clock as given."""
        self.assertEqual(romanian_date(datetime(2025, 12, 31, 22, 30), "long"), "31 decembrie 2025")

    def test_empty_value_returns_empty_string(self) -> None:
        """Non-regression: the falsy short-circuit still precedes any conversion."""
        self.assertEqual(romanian_date(None), "")
