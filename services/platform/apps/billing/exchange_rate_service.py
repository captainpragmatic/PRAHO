"""Deterministic exchange-rate lookup for fiscal document issuance."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal

from .currency_models import FXRate

logger = logging.getLogger(__name__)

WEEKDAYS_PER_WEEK = 5


class ExchangeRateError(ValueError):
    """Base error for exchange-rate resolution failures."""


class MissingExchangeRateError(ExchangeRateError):
    """Raised when no exact-direction rate exists by the effective date."""


class UnprovenancedExchangeRateError(ExchangeRateError):
    """Raised when a historical rate lacks enough evidence for new issuance."""


@dataclass(frozen=True, slots=True)
class ExchangeRateSnapshot:
    """Immutable fiscal subset copied from an approved FX-rate row."""

    rate: Decimal
    as_of: date
    source: str
    source_reference: str


class ExchangeRateService:
    """Resolve exact-direction, provenanced rates without network I/O."""

    STALE_WEEKDAYS = 3
    APPROVED_SOURCES = frozenset(
        {
            FXRate.Source.BNR,
            FXRate.Source.ECB,
            FXRate.Source.BANK,
        }
    )

    @classmethod
    def resolve(cls, base_code: str, quote_code: str, effective_date: date) -> ExchangeRateSnapshot:
        base = base_code.strip().upper()
        quote = quote_code.strip().upper()
        fx_rate = (
            FXRate.objects.filter(base_code_id=base, quote_code_id=quote, as_of__lte=effective_date)
            .order_by("-as_of", "-pk")
            .first()
        )
        if fx_rate is None:
            raise MissingExchangeRateError(f"No {base}/{quote} exchange rate exists on or before {effective_date}")

        if (
            fx_rate.source not in cls.APPROVED_SOURCES
            or not fx_rate.source_reference.strip()
            or fx_rate.fetched_at is None
        ):
            raise UnprovenancedExchangeRateError(
                f"{base}/{quote} exchange rate for {fx_rate.as_of} has incomplete provenance (source={fx_rate.source})"
            )

        weekdays = cls._weekdays_after(fx_rate.as_of, effective_date)
        if weekdays > cls.STALE_WEEKDAYS:
            logger.warning(
                "Using %s/%s exchange rate dated %s for %s after %d weekdays without a publication",
                base,
                quote,
                fx_rate.as_of,
                effective_date,
                weekdays,
            )

        return ExchangeRateSnapshot(
            rate=fx_rate.rate,
            as_of=fx_rate.as_of,
            source=fx_rate.source,
            source_reference=fx_rate.source_reference,
        )

    @staticmethod
    def convert_cents(amount_cents: int, rate: Decimal) -> int:
        """Convert minor units with exact decimal, half-up rounding."""
        if not rate.is_finite() or rate <= 0:
            raise ExchangeRateError("Exchange rate must be finite and positive")
        return int((Decimal(amount_cents) * rate).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    @staticmethod
    def _weekdays_after(start: date, end: date) -> int:
        """Count Monday-Friday dates in ``(start, end]``.

        Publication-specific holidays are intentionally not guessed. A stale
        warning is operational telemetry, while rate validity is determined by
        selecting the latest published row on or before the tax point.
        """
        if end <= start:
            return 0
        current = start + timedelta(days=1)
        count = 0
        while current <= end:
            if current.weekday() < WEEKDAYS_PER_WEEK:
                count += 1
            current += timedelta(days=1)
        return count
