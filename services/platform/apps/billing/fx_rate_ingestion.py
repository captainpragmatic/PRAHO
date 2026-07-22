"""Controlled, audited promotion of migrated exchange-rate evidence."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from apps.audit.services import AuditService
from apps.billing.currency_models import Currency, FXRate


class LegacyRatePromotionError(ValueError):
    """Raised when a legacy FX row cannot be safely promoted."""


@transaction.atomic
def promote_legacy_rate(  # noqa: PLR0913
    base: Currency,
    quote: Currency,
    as_of: date,
    rate_value: Decimal,
    source: str,
    reference: str,
    recorded_by: str,
) -> str:
    """Attach evidence to a locked legacy row without changing its historical rate."""
    fx_rate = FXRate.objects.select_for_update().filter(base_code=base, quote_code=quote, as_of=as_of).first()
    pair = f"{base.code}/{quote.code} for {as_of}"
    if fx_rate is None:
        raise LegacyRatePromotionError(f"No legacy {pair} exchange-rate row exists to promote")
    if (
        fx_rate.rate == rate_value
        and fx_rate.source == source
        and fx_rate.source_reference == reference
        and fx_rate.fetched_at is not None
    ):
        return f"Exchange rate {pair} already recorded"
    if fx_rate.source != FXRate.Source.LEGACY_UNKNOWN:
        raise LegacyRatePromotionError(f"{pair} already exists with different rate or provenance")
    if fx_rate.rate != rate_value:
        message = f"{pair} has a different rate; promotion cannot alter the historical amount"
        raise LegacyRatePromotionError(message)

    old_values = {
        "rate": str(fx_rate.rate),
        "source": fx_rate.source,
        "source_reference": fx_rate.source_reference,
        "fetched_at": fx_rate.fetched_at.isoformat() if fx_rate.fetched_at else None,
    }
    captured_at = timezone.now()
    fx_rate.source, fx_rate.source_reference, fx_rate.fetched_at = source, reference, captured_at
    fx_rate.full_clean()
    fx_rate.save(update_fields=["source", "source_reference", "fetched_at"])
    AuditService.log_simple_event(
        "fx_rate_provenance_promoted",
        content_object=fx_rate,
        description=f"Promoted legacy {pair} exchange-rate provenance",
        old_values=old_values,
        new_values={
            "rate": str(rate_value),
            "source": source,
            "source_reference": reference,
            "fetched_at": captured_at.isoformat(),
        },
        metadata={"recorded_by": recorded_by, "as_of": as_of.isoformat()},
        actor_type="system",
    )
    return f"Promoted legacy {base.code}/{quote.code}={rate_value} for {as_of}"
