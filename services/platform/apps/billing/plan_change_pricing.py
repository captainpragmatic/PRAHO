"""Pure integer pricing over independently proven, half-open coverage intervals.

Callers supply immutable document/settlement evidence, never subscription period
pointers. Taxes are calculated later by TaxService on these quantity-one NET lines.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, localcontext


@dataclass(frozen=True)
class CoveredInterval:
    evidence_id: str
    start: datetime
    end: datetime
    base_net_cents: int
    settled_supplement_cents: int
    paid: bool


@dataclass(frozen=True)
class PlanSupplement:
    evidence_id: str
    start: datetime
    end: datetime
    net_cents: int
    current_slice: bool


def _money(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("Coverage amounts must be nonnegative integer cents")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Coverage dates require an explicit timezone")
    return value.astimezone(UTC)


def _microseconds(delta: timedelta) -> int:
    return ((delta.days * 86400) + delta.seconds) * 1000000 + delta.microseconds


def quote_supplements(
    *,
    intervals: Sequence[CoveredInterval],
    quoted_at: datetime,
    current_period_price_cents: int,
    target_period_price_cents: int,
) -> tuple[PlanSupplement, ...]:
    """Price the current paid slice and every subsequent committed obligation.

    An issued but unpaid future base remains an obligation: only its additional
    price is collected here. Settled supplements cover that base independently.
    Gaps, overlap and ambiguous current evidence require review, not guessed money.
    """
    _money(current_period_price_cents)
    _money(target_period_price_cents)
    at = _utc(quoted_at)
    evidence_ids: set[str] = set()
    ordered = sorted(intervals, key=lambda item: _utc(item.start))
    previous_end: datetime | None = None
    for item in ordered:
        start, end = _utc(item.start), _utc(item.end)
        _money(item.base_net_cents)
        _money(item.settled_supplement_cents)
        if not item.evidence_id or item.evidence_id in evidence_ids:
            raise ValueError("Coverage evidence must identify each interval exactly once")
        if type(item.paid) is not bool or start >= end:
            raise ValueError("Invalid coverage interval")
        if previous_end is not None and start < previous_end:
            raise ValueError("Overlapping coverage intervals require review")
        evidence_ids.add(item.evidence_id)
        previous_end = end
    relevant = [item for item in ordered if _utc(item.end) > at]
    if not relevant or not _utc(relevant[0].start) <= at < _utc(relevant[0].end):
        raise ValueError("No proven current interval contains the quote instant")
    if not relevant[0].paid:
        raise ValueError("The current interval requires paid coverage")
    results: list[PlanSupplement] = []
    previous_end = None
    for index, item in enumerate(relevant):
        start, end = _utc(item.start), _utc(item.end)
        if previous_end is not None and start != previous_end:
            raise ValueError("A gap in committed future coverage requires review")
        if index == 0:
            difference = max(0, target_period_price_cents - current_period_price_cents)
            with localcontext() as context:
                context.prec = 60  # Preserve half-cent boundaries for bigint amounts and datetime spans.
                amount = (Decimal(difference) * _microseconds(end - at) / _microseconds(end - start)).quantize(
                    Decimal("1"), rounding=ROUND_HALF_UP
                )
            results.append(PlanSupplement(item.evidence_id, at, end, int(amount), True))
        else:
            covered = item.base_net_cents + item.settled_supplement_cents
            results.append(
                PlanSupplement(item.evidence_id, start, end, max(0, target_period_price_cents - covered), False)
            )
        previous_end = end
    return tuple(results)
