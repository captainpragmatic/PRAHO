"""Tests for deterministic, provenanced exchange-rate resolution."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.exchange_rate_service import (
    ExchangeRateError,
    ExchangeRateService,
    MissingExchangeRateError,
    UnprovenancedExchangeRateError,
)
from apps.billing.models import Currency, FXRate


class ExchangeRateServiceTest(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(
            code="EUR", defaults={"name": "Euro", "symbol": "EUR", "decimals": 2}
        )
        self.ron, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian leu", "symbol": "lei", "decimals": 2}
        )

    def _rate(self, *, as_of: date, rate: str = "5.01234567", **overrides: object) -> FXRate:
        values: dict[str, object] = {
            "base_code": self.eur,
            "quote_code": self.ron,
            "rate": Decimal(rate),
            "as_of": as_of,
            "source": FXRate.Source.BNR,
            "source_reference": "https://www.bnr.ro/nbrfxrates.xml",
            "fetched_at": timezone.make_aware(datetime(2026, 7, 17, 13, 30)),
        }
        values.update(overrides)
        return FXRate.objects.create(**values)

    def test_resolve_selects_latest_rate_not_after_effective_date(self) -> None:
        self._rate(as_of=date(2026, 7, 16), rate="5.01000000")
        expected = self._rate(as_of=date(2026, 7, 17), rate="5.02000000")
        self._rate(as_of=date(2026, 7, 20), rate="5.03000000")

        snapshot = ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 19))

        self.assertEqual(snapshot.rate, expected.rate)
        self.assertEqual(snapshot.as_of, expected.as_of)
        self.assertEqual(snapshot.source, FXRate.Source.BNR)
        self.assertEqual(snapshot.source_reference, expected.source_reference)

    def test_weekend_lookup_uses_last_published_rate(self) -> None:
        friday = self._rate(as_of=date(2026, 7, 17))

        snapshot = ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 19))

        self.assertEqual(snapshot.as_of, friday.as_of)

    def test_reverse_pair_is_not_silently_inverted(self) -> None:
        self._rate(
            as_of=date(2026, 7, 17),
            base_code=self.ron,
            quote_code=self.eur,
            rate="0.19950000",
        )

        with self.assertRaises(MissingExchangeRateError):
            ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 17))

    def test_missing_rate_has_operator_readable_context(self) -> None:
        with self.assertRaisesRegex(MissingExchangeRateError, "EUR/RON.*2026-07-17"):
            ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 17))

    def test_legacy_rate_is_rejected_as_unprovenanced(self) -> None:
        self._rate(
            as_of=date(2026, 7, 17),
            source=FXRate.Source.LEGACY_UNKNOWN,
            source_reference="",
            fetched_at=None,
        )

        with self.assertRaisesRegex(UnprovenancedExchangeRateError, "legacy_unknown"):
            ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 17))

    def test_unapproved_source_is_rejected_as_unprovenanced(self) -> None:
        self._rate(as_of=date(2026, 7, 17), source="manual")

        with self.assertRaisesRegex(UnprovenancedExchangeRateError, "manual"):
            ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 17))

    def test_missing_reference_is_rejected_as_unprovenanced(self) -> None:
        self._rate(as_of=date(2026, 7, 17), source_reference="")

        with self.assertRaises(UnprovenancedExchangeRateError):
            ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 17))

    def test_stale_but_valid_rate_warns_without_rejecting(self) -> None:
        self._rate(as_of=date(2026, 7, 13))

        with self.assertLogs("apps.billing.exchange_rate_service", level="WARNING") as logs:
            snapshot = ExchangeRateService.resolve("EUR", "RON", date(2026, 7, 20))

        self.assertEqual(snapshot.as_of, date(2026, 7, 13))
        self.assertIn("5 weekdays", logs.output[0])

    def test_conversion_rounds_half_up_in_cents(self) -> None:
        snapshot = self._rate(as_of=date(2026, 7, 17), rate="5.00500000")

        converted = ExchangeRateService.convert_cents(100, snapshot.rate)

        self.assertEqual(converted, 501)

    def test_conversion_handles_exact_subunit_midpoint(self) -> None:
        self.assertEqual(ExchangeRateService.convert_cents(1, Decimal("4.50000000")), 5)

    def test_conversion_rejects_non_finite_rates(self) -> None:
        for rate in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
            with self.subTest(rate=rate), self.assertRaisesRegex(ExchangeRateError, "finite and positive"):
                ExchangeRateService.convert_cents(100, rate)
