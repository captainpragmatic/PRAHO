from __future__ import annotations

from django.test import SimpleTestCase, override_settings

from apps.common.retry_after import MAX_RETRY_AFTER_SECONDS, coerce_retry_after_seconds


class CoerceRetryAfterSecondsTests(SimpleTestCase):
    def test_none_returns_none(self) -> None:
        self.assertIsNone(coerce_retry_after_seconds(None))

    def test_positive_int(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(5), 5)

    def test_positive_float_ceils(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(0.001), 1)

    def test_string_digit(self) -> None:
        self.assertEqual(coerce_retry_after_seconds("10"), 10)

    def test_large_value_capped_to_max(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(999999), MAX_RETRY_AFTER_SECONDS)

    def test_at_cap_boundary(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(300), 300)

    def test_just_over_cap(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(301), MAX_RETRY_AFTER_SECONDS)

    def test_negative_string_returns_none(self) -> None:
        # "-5" is not all digits, so it falls to date parsing which fails -> None
        self.assertIsNone(coerce_retry_after_seconds("-5"))

    def test_negative_int_returns_one(self) -> None:
        # negative int -> math.ceil(-5) = -5 -> max(1, -5) = 1
        self.assertEqual(coerce_retry_after_seconds(-5), 1)

    def test_unicode_digit_returns_none(self) -> None:
        self.assertIsNone(coerce_retry_after_seconds("\u00b2"))

    def test_extreme_date_no_crash(self) -> None:
        # Should not raise OverflowError or OSError
        result = coerce_retry_after_seconds("Mon, 01 Jan 99999 00:00:00 GMT")
        # Either returns capped value or None, but never crashes
        if result is not None:
            self.assertLessEqual(result, MAX_RETRY_AFTER_SECONDS)

    def test_empty_string_returns_none(self) -> None:
        self.assertIsNone(coerce_retry_after_seconds(""))

    def test_nan_returns_none(self) -> None:
        self.assertIsNone(coerce_retry_after_seconds(float("nan")))

    def test_inf_returns_none(self) -> None:
        self.assertIsNone(coerce_retry_after_seconds(float("inf")))

    @override_settings(RETRY_AFTER_MAX_SECONDS=60)
    def test_custom_cap_from_settings(self) -> None:
        self.assertEqual(coerce_retry_after_seconds(100), 60)
