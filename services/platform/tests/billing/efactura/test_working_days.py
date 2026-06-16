"""Tests for Romanian working-day e-Factura deadline arithmetic (OUG 89/2025)."""

from __future__ import annotations

import datetime

import holidays
from django.test import TestCase

from apps.billing.efactura.working_days import add_working_days, submission_deadline_datetime


class WorkingDaysTests(TestCase):
    def setUp(self):
        self.cal = holidays.Romania(years=range(2026, 2028))

    def test_result_is_always_a_working_day(self):
        """Whatever the start date, the deadline lands on a Mon-Fri that is not a RO holiday."""
        start = datetime.date(2026, 1, 1)
        for offset in range(0, 366, 5):
            d = start + datetime.timedelta(days=offset)
            result = add_working_days(d, 5)
            self.assertGreater(result, d)
            self.assertLess(result.weekday(), 5, f"{result} is a weekend")
            self.assertNotIn(result, self.cal, f"{result} is a Romanian public holiday")

    def test_counts_exactly_n_working_days(self):
        """Exactly N working days are counted between start (exclusive) and the result (inclusive),
        including across the Easter / National-Day / Christmas holiday clusters."""
        for start, n in [
            (datetime.date(2026, 6, 1), 5),
            (datetime.date(2026, 4, 9), 3),    # spans Orthodox Good Friday + Easter Monday
            (datetime.date(2026, 11, 26), 5),  # spans St Andrew (Nov 30) + National Day (Dec 1)
            (datetime.date(2026, 12, 23), 5),  # spans Christmas
        ]:
            result = add_working_days(start, n)
            counted = 0
            d = start + datetime.timedelta(days=1)
            while d <= result:
                if d.weekday() < 5 and d not in self.cal:
                    counted += 1
                d += datetime.timedelta(days=1)
            self.assertEqual(counted, n, f"{start}+{n}wd -> {result} counted {counted} working days")

    def test_easter_cluster_2026_hand_computed_golden(self):
        """Hand-computed golden for the Easter 2026 cluster — anchors the algorithm to an
        independently verified expected value, not to its own output.

        Start: Thursday 2026-04-09. Counting 5 working days, day-by-day:
          Fri 2026-04-10  Good Friday (HOLIDAY) — skip
          Sat 2026-04-11  weekend — skip
          Sun 2026-04-12  weekend — skip
          Mon 2026-04-13  Easter Monday (HOLIDAY) — skip
          Tue 2026-04-14  working day  #1
          Wed 2026-04-15  working day  #2
          Thu 2026-04-16  working day  #3
          Fri 2026-04-17  working day  #4
          Sat 2026-04-18  weekend — skip
          Sun 2026-04-19  weekend — skip
          Mon 2026-04-20  working day  #5  ← deadline lands here
        """
        self.assertEqual(add_working_days(datetime.date(2026, 4, 9), 5), datetime.date(2026, 4, 20))

    def test_deadline_datetime_is_end_of_day(self):
        """The submission window ends at the last instant of the deadline day in RO local time
        (consistent with Reg 1182/71 Art. 3: period ends with the last hour of the last day)."""
        issued = datetime.datetime(2026, 6, 1, 9, 0, tzinfo=datetime.UTC)
        deadline = submission_deadline_datetime(issued, 5)
        self.assertEqual(deadline.time(), datetime.time.max)

    def test_skips_orthodox_easter_monday_2026(self):
        """The moveable Orthodox Easter Monday (2026-04-13) is a RO public holiday a working-day
        deadline must never land on."""
        self.assertIn(datetime.date(2026, 4, 13), self.cal)
        result = add_working_days(datetime.date(2026, 4, 9), 2)
        self.assertNotEqual(result, datetime.date(2026, 4, 13))
        self.assertLess(result.weekday(), 5)
        self.assertNotIn(result, self.cal)

    def test_zero_or_negative_returns_start(self):
        d = datetime.date(2026, 6, 15)
        self.assertEqual(add_working_days(d, 0), d)
        self.assertEqual(add_working_days(d, -3), d)

    def test_deadline_datetime_uses_romania_local_date(self):
        """An invoice issued late UTC counts from the next ROMANIAN day, not the UTC day."""
        # 22:30 UTC on 2026-06-15 is 01:30 on 2026-06-16 in Romania (EEST, UTC+3).
        issued = datetime.datetime(2026, 6, 15, 22, 30, tzinfo=datetime.UTC)
        deadline = submission_deadline_datetime(issued, 5)
        self.assertEqual(deadline.date(), add_working_days(datetime.date(2026, 6, 16), 5))
