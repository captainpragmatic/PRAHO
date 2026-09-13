"""Record or promote a provenanced exchange rate for offline fiscal issuance."""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.billing.currency_models import MAX_FX_RATE
from apps.billing.fx_rate_ingestion import (
    FXRateConflictError,
    LegacyRatePromotionError,
    promote_legacy_rate,
    record_fx_rate,
)
from apps.billing.models import Currency, FXRate


def _validate_rate(rate_value: Decimal) -> None:
    """Reject values that cannot be represented safely by the FXRate model."""
    if not rate_value.is_finite() or rate_value <= 0:
        raise CommandError("Exchange rate must be finite and positive")
    if rate_value > MAX_FX_RATE:
        raise CommandError(f"Exchange rate must not exceed {MAX_FX_RATE}")


class Command(BaseCommand):
    help = "Record an approved, provenanced exchange rate without network access"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--base", required=True, help="Base ISO 4217 code, e.g. EUR")
        parser.add_argument("--quote", required=True, help="Quote ISO 4217 code, e.g. RON")
        parser.add_argument("--rate", required=True, help="Quote units for one base unit")
        parser.add_argument(
            "--as-of",
            required=True,
            dest="as_of",
            help=(
                "Date the rate is legally valid for VAT (YYYY-MM-DD). A BNR rate "
                "communicated on day D applies from the next banking day — enter "
                "the validity date, not the publication date (art. 290(2) norms)."
            ),
        )
        parser.add_argument(
            "--source",
            required=True,
            choices=[FXRate.Source.BNR, FXRate.Source.ECB, FXRate.Source.BANK],
        )
        parser.add_argument("--reference", required=True, help="Publication URL or auditable document reference")
        parser.add_argument(
            "--recorded-by", required=True, dest="recorded_by", help="Operator identity for the audit trail"
        )
        parser.add_argument(
            "--promote-legacy",
            action="store_true",
            help="Attach verified provenance to an existing matching legacy row",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        base_code = str(options["base"]).strip().upper()
        quote_code = str(options["quote"]).strip().upper()
        source = str(options["source"])
        reference = str(options["reference"]).strip()
        recorded_by = str(options["recorded_by"]).strip()

        try:
            rate_value = Decimal(str(options["rate"]))
            as_of = date.fromisoformat(str(options["as_of"]))
        except (InvalidOperation, ValueError) as exc:
            raise CommandError(f"Invalid exchange-rate value or date: {exc}") from exc

        _validate_rate(rate_value)
        if base_code == quote_code:
            raise CommandError("Base and quote currencies must differ")
        if not reference:
            raise CommandError("Source reference must not be empty")
        if not recorded_by:
            raise CommandError("Recorded-by identity must not be empty")

        try:
            base = Currency.objects.get(pk=base_code)
            quote = Currency.objects.get(pk=quote_code)
        except Currency.DoesNotExist as exc:
            raise CommandError(f"Both currencies must exist before recording {base_code}/{quote_code}") from exc

        if options["promote_legacy"]:
            try:
                message = promote_legacy_rate(base, quote, as_of, rate_value, source, reference, recorded_by)
            except LegacyRatePromotionError as exc:
                raise CommandError(str(exc)) from exc
            self.stdout.write(self.style.SUCCESS(message))
            return

        try:
            _, created = record_fx_rate(base, quote, as_of, rate_value, source, reference, recorded_by)
        except (FXRateConflictError, ValidationError) as exc:
            raise CommandError(str(exc)) from exc

        if not created:
            self.stdout.write(
                self.style.SUCCESS(f"Exchange rate {base_code}/{quote_code} for {as_of} already recorded")
            )
            return

        self.stdout.write(self.style.SUCCESS(f"Recorded {base_code}/{quote_code}={rate_value} for {as_of}"))
