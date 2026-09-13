"""Controlled, audited promotion of migrated exchange-rate evidence."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

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


class FXRateConflictError(ValueError):
    """An existing exchange-rate row differs from the supplied evidence."""


class FXRatePromotionRequiredError(FXRateConflictError):
    """A matching legacy amount requires explicit provenance promotion."""


@transaction.atomic
def record_fx_rate(  # noqa: PLR0913
    base: Currency,
    quote: Currency,
    as_of: date,
    rate_value: Decimal,
    source: str,
    reference: str,
    recorded_by: str,
) -> tuple[FXRate, bool]:
    """Record immutable exchange-rate evidence, returning (row, created).

    Shared by the manual ``record_exchange_rate`` command and the automated BNR
    fetcher (#103). Exact replays leave both the row and its ``fetched_at`` unchanged
    and emit no audit event; a differing rate/provenance is a hard conflict (never an
    overwrite); a same-amount ``legacy_unknown`` row requires explicit promotion.
    Creation and its audit event commit or roll back together.
    """
    if source not in (FXRate.Source.BNR, FXRate.Source.ECB, FXRate.Source.BANK):
        raise ValidationError(_("Exchange-rate source must be bnr, ecb, or bank"))
    if not reference.strip():
        raise ValidationError(_("Source reference must not be empty"))
    if not recorded_by.strip():
        raise ValidationError(_("Recorded-by identity must not be empty"))

    candidate = FXRate(
        base_code=base,
        quote_code=quote,
        as_of=as_of,
        rate=rate_value,
        source=source,
        source_reference=reference,
        fetched_at=timezone.now(),
    )
    # Validate before INSERT (decimal precision + model constraints); the unique key
    # is enforced by get_or_create() below, safe under concurrent inserts.
    candidate.full_clean(validate_unique=False)

    fx_rate, created = FXRate.objects.get_or_create(
        base_code=base,
        quote_code=quote,
        as_of=as_of,
        defaults={
            "rate": candidate.rate,
            "source": candidate.source,
            "source_reference": candidate.source_reference,
            "fetched_at": candidate.fetched_at,
        },
    )
    if not created:
        if (
            fx_rate.rate == rate_value
            and fx_rate.source == source
            and fx_rate.source_reference == reference
            and fx_rate.fetched_at is not None
        ):
            return fx_rate, False

        pair = f"{base.code}/{quote.code} for {as_of}"
        if fx_rate.source == FXRate.Source.LEGACY_UNKNOWN and fx_rate.rate == rate_value:
            raise FXRatePromotionRequiredError(f"{pair} lacks approved provenance; rerun with --promote-legacy")
        raise FXRateConflictError(f"{pair} already exists with different rate or provenance")

    AuditService.log_simple_event(
        "fx_rate_recorded",
        content_object=fx_rate,
        description=f"Recorded {base.code}/{quote.code} exchange rate for {as_of}",
        new_values={
            "rate": str(rate_value),
            "source": source,
            "source_reference": reference,
        },
        metadata={"recorded_by": recorded_by, "as_of": as_of.isoformat()},
        actor_type="system",
    )
    return fx_rate, True
