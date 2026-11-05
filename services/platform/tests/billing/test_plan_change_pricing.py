"""Plan changes charge exact interval slices without rewriting frozen obligations."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from django.test import SimpleTestCase

from apps.billing.plan_change_pricing import CoveredInterval, quote_supplements


class PlanChangePricingTests(SimpleTestCase):
    def setUp(self) -> None:
        self.start = datetime(2028, 2, 1, tzinfo=UTC)
        self.end = datetime(2028, 3, 1, tzinfo=UTC)

    def interval(self, **kwargs: object) -> CoveredInterval:
        values = {
            "evidence_id": "paid-current",
            "start": self.start,
            "end": self.end,
            "base_net_cents": 8000,
            "settled_supplement_cents": 0,
            "paid": True,
        }
        values.update(kwargs)
        return CoveredInterval(**values)

    def quote(self, **kwargs: object):
        values = {
            "intervals": [self.interval()],
            "quoted_at": self.start + (self.end - self.start) / 2,
            "current_period_price_cents": 8000,
            "target_period_price_cents": 20000,
        }
        values.update(kwargs)
        return quote_supplements(**values)

    def test_current_slice_uses_exact_leap_month_span(self) -> None:
        parts = self.quote(quoted_at=self.start + timedelta(days=14))
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].net_cents, 6207)  # 12000 * 15 / 29, half up.
        self.assertEqual(parts[0].start, self.start + timedelta(days=14))
        self.assertEqual(parts[0].end, self.end)
        self.assertEqual(parts[0].evidence_id, "paid-current")

    def test_half_cent_rounds_up_and_tiny_slice_can_be_zero(self) -> None:
        interval = self.interval(end=self.start + timedelta(microseconds=2))
        self.assertEqual(
            self.quote(
                intervals=[interval],
                quoted_at=self.start + timedelta(microseconds=1),
                current_period_price_cents=100,
                target_period_price_cents=101,
            )[0].net_cents,
            1,
        )
        self.assertEqual(
            self.quote(quoted_at=self.end - timedelta(microseconds=1), target_period_price_cents=8001)[0].net_cents,
            0,
        )

    def test_dst_uses_elapsed_time_instead_of_wall_clock_days(self) -> None:
        zone = ZoneInfo("Europe/Bucharest")
        start = datetime(2028, 3, 25, tzinfo=zone)
        end = datetime(2028, 3, 27, tzinfo=zone)
        at = datetime(2028, 3, 26, tzinfo=zone)
        part = self.quote(intervals=[self.interval(start=start, end=end)], quoted_at=at)[0]
        self.assertEqual(part.net_cents, 5872)  # 12000 * 23 / 47 hours.

    def test_early_paid_future_does_not_replace_current_span(self) -> None:
        future = self.interval(evidence_id="prepaid-future", start=self.end, end=datetime(2028, 4, 1, tzinfo=UTC))
        parts = self.quote(intervals=[future, self.interval()])
        self.assertEqual([part.net_cents for part in parts], [6000, 12000])
        self.assertEqual([part.evidence_id for part in parts], ["paid-current", "prepaid-future"])

    def test_repeat_upgrade_deducts_settled_supplements_from_frozen_base(self) -> None:
        future = self.interval(
            evidence_id="frozen-80",
            start=self.end,
            end=datetime(2028, 4, 1, tzinfo=UTC),
            base_net_cents=8000,
            settled_supplement_cents=12000,
        )
        parts = self.quote(
            intervals=[self.interval(), future], current_period_price_cents=20000, target_period_price_cents=30000
        )
        self.assertEqual([part.net_cents for part in parts], [5000, 10000])
        self.assertEqual(future.base_net_cents, 8000)

    def test_issued_unpaid_future_obligation_gets_separate_supplement(self) -> None:
        future = self.interval(
            evidence_id="issued-unpaid", start=self.end, end=datetime(2028, 4, 1, tzinfo=UTC), paid=False
        )
        self.assertEqual(self.quote(intervals=[self.interval(), future])[1].net_cents, 12000)

    def test_zero_or_cheaper_target_never_creates_negative_credit_line(self) -> None:
        self.assertEqual(self.quote(target_period_price_cents=4000)[0].net_cents, 0)
        self.assertEqual(self.quote(target_period_price_cents=8000)[0].net_cents, 0)

    def test_current_interval_requires_paid_coverage(self) -> None:
        with self.assertRaisesRegex(ValueError, "paid"):
            self.quote(intervals=[self.interval(paid=False)])

    def test_half_open_boundary_requires_new_paid_interval(self) -> None:
        with self.assertRaisesRegex(ValueError, "current"):
            self.quote(quoted_at=self.end)

    def test_overlap_gap_and_duplicate_evidence_are_refused(self) -> None:
        for future in (
            self.interval(
                evidence_id="other", start=self.end - timedelta(seconds=1), end=datetime(2028, 4, 1, tzinfo=UTC)
            ),
            self.interval(
                evidence_id="other", start=self.end + timedelta(seconds=1), end=datetime(2028, 4, 1, tzinfo=UTC)
            ),
            self.interval(start=self.end, end=datetime(2028, 4, 1, tzinfo=UTC)),
        ):
            with self.subTest(future=future), self.assertRaises(ValueError):
                self.quote(intervals=[self.interval(), future])

    def test_invalid_money_and_unzoned_evidence_fail_closed(self) -> None:
        for field in ("base_net_cents", "settled_supplement_cents"):
            for invalid in (-1, True, 1.5):
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    self.quote(intervals=[self.interval(**{field: invalid})])
        for field in ("target_period_price_cents", "current_period_price_cents"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.quote(**{field: True})
        with self.assertRaises(ValueError):
            self.quote(quoted_at=datetime(2028, 2, 15))

    def test_past_evidence_is_not_billed_again(self) -> None:
        past = self.interval(evidence_id="past", start=datetime(2028, 1, 1, tzinfo=UTC), end=self.start)
        self.assertEqual([part.evidence_id for part in self.quote(intervals=[past, self.interval()])], ["paid-current"])
