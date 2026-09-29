"""Deterministic promotion arithmetic. Prices and eligibility come from Platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

PERIOD_MONTHS = {"monthly": 1, "quarterly": 3, "semiannual": 6, "annual": 12, "biennial": 24, "triennial": 36}


def cents(value: Decimal) -> int:
    return int(value.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def allocate(amount: int, weights: dict[str, int]) -> dict[str, int]:
    """Largest-remainder allocation with stable ties and no lost or invented cents."""
    weights = {key: value for key, value in weights.items() if value > 0}
    total = sum(weights.values())
    amount = min(max(0, amount), total)
    if not total or not amount:
        return {}
    result = {key: amount * value // total for key, value in weights.items()}
    remainder = amount - sum(result.values())
    for key in sorted(weights, key=lambda key: (-(amount * weights[key] % total), key))[:remainder]:
        result[key] += 1
    return {key: value for key, value in result.items() if value}


@dataclass(frozen=True)
class PriceLine:
    key: str
    quantity: int
    unit_cents: int
    setup_cents: int
    period: str

    def __post_init__(self) -> None:
        if self.quantity < 1 or min(self.unit_cents, self.setup_cents) < 0:
            raise ValueError("Promotion prices and quantities must be nonnegative, with at least one unit")

    @property
    def subtotal(self) -> int:
        return self.quantity * self.unit_cents + self.setup_cents


@dataclass(frozen=True)
class Offer:
    key: str
    kind: str
    percent: Decimal = Decimal(0)
    amount_cents: int = 0
    months: int = 0
    tiers: tuple[dict[str, Any], ...] = ()
    eligible_ids: frozenset[str] | None = None
    stackable: bool = False
    exclusive: bool = False
    priority: int = 100
    entered: bool = False
    max_cents: int | None = None
    budget_key: str = ""
    budget_available_cents: int | None = None


@dataclass
class AppliedOffer:
    key: str
    allocations: dict[str, int]
    renewals: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def discount_cents(self) -> int:
        return sum(self.allocations.values())

    @property
    def committed_cents(self) -> int:
        return self.discount_cents + sum(int(value["remaining_cents"]) for value in self.renewals.values())


@dataclass
class Evaluation:
    offers: list[AppliedOffer] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)

    @property
    def discount_cents(self) -> int:
        return sum(offer.discount_cents for offer in self.offers)


def _tier_discount(offer: Offer, lines: list[PriceLine], base: int) -> int:
    quantity = sum(line.quantity for line in lines)
    for tier in sorted(offer.tiers, key=lambda tier: tier["threshold"], reverse=True):
        measure = quantity if tier["threshold_type"] == "quantity" else sum(line.subtotal for line in lines)
        if measure >= tier["threshold"]:
            if "percent" in tier:
                return cents(Decimal(base) * Decimal(str(tier["percent"])) / 100)
            return int(tier["amount_cents"])
    return 0


def _calculate(offer: Offer, lines: list[PriceLine], service: dict[str, int], setup: dict[str, int]) -> AppliedOffer:
    weights = {line.key: service[line.key] + setup[line.key] for line in lines}
    base = sum(weights.values())
    renewals: dict[str, dict[str, Any]] = {}
    if offer.kind == "percent":
        amount = cents(Decimal(base) * offer.percent / 100)
    elif offer.kind == "fixed":
        amount = offer.amount_cents
    elif offer.kind in {"tiered", "tiered_percent", "tiered_fixed"}:
        amount = _tier_discount(offer, lines, base)
    elif offer.kind == "free_setup":
        weights = {line.key: setup[line.key] for line in lines}
        amount = sum(weights.values())
    elif offer.kind == "bogo":
        free_units = sum(line.quantity for line in lines) // 2
        weights = {}
        for line in sorted(lines, key=lambda line: (Decimal(service[line.key]) / line.quantity, line.key)):
            units = min(line.quantity, free_units)
            weights[line.key] = cents(Decimal(service[line.key]) * units / line.quantity)
            free_units -= units
        amount = sum(weights.values())
    elif offer.kind == "free_months":
        weights = {}
        for line in lines:
            period = PERIOD_MONTHS.get(line.period)
            if period is None:
                continue
            monthly = Decimal(line.quantity * line.unit_cents) / period
            weights[line.key] = min(service[line.key], cents(monthly * min(period, offer.months)))
            future_months = max(0, offer.months - period)
            if future_months:
                renewals[line.key] = {
                    "remaining_cents": cents(monthly * future_months),
                    "monthly_cents": str(monthly),
                    "months": future_months,
                }
        amount = sum(weights.values())
    else:
        raise ValueError(f"Unsupported promotion discount: {offer.kind}")

    if offer.max_cents is not None:
        amount = min(amount, offer.max_cents)
        future = allocate(
            max(0, offer.max_cents - amount), {key: value["remaining_cents"] for key, value in renewals.items()}
        )
        renewals = {key: {**renewals[key], "remaining_cents": value} for key, value in future.items()}
    return AppliedOffer(offer.key, allocate(amount, weights), renewals)


def evaluate_offers(lines: list[PriceLine], offers: list[Offer]) -> Evaluation:  # noqa: PLR0912  # Explicit offer compatibility and budget rules
    """Select compatible offers and apply them in priority order to remaining prices."""
    if len({line.key for line in lines}) != len(lines):
        raise ValueError("Each cart line requires a unique stable key")
    ordered = sorted(offers, key=lambda offer: (offer.priority, offer.key))
    entered = [offer for offer in ordered if offer.entered]
    if entered:
        if any(offer.exclusive or not offer.stackable for offer in entered):
            ordered = entered[:1]
        else:
            ordered = [offer for offer in ordered if offer.entered or (offer.stackable and not offer.exclusive)]

    result = Evaluation()
    service = {line.key: line.quantity * line.unit_cents for line in lines}
    setup = {line.key: line.setup_cents for line in lines}
    budgets: dict[str, int] = {}
    previous: Offer | None = None
    for offer in ordered:
        if previous and (previous.exclusive or offer.exclusive or not previous.stackable or not offer.stackable):
            continue
        eligible = [line for line in lines if offer.eligible_ids is None or line.key in offer.eligible_ids]
        applied = _calculate(offer, eligible, service, setup)
        budget_key = offer.budget_key or offer.key
        if offer.budget_available_cents is not None:
            available = budgets.setdefault(budget_key, max(0, offer.budget_available_cents))
            if applied.committed_cents > available:
                result.unavailable.append(offer.key)
                continue
            budgets[budget_key] -= applied.committed_cents
        if not applied.committed_cents:
            continue
        for key, discount in applied.allocations.items():
            if offer.kind == "free_setup":
                setup[key] -= discount
            elif offer.kind in {"bogo", "free_months"}:
                service[key] -= discount
            else:
                parts = allocate(discount, {"service": service[key], "setup": setup[key]})
                service[key] -= parts.get("service", 0)
                setup[key] -= parts.get("setup", 0)
        result.offers.append(applied)
        previous = offer
    return result
