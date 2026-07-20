"""Record a provenanced exchange rate for offline fiscal issuance."""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction
from django.utils import timezone

from apps.audit.services import AuditService
from apps.billing.models import Currency, FXRate


class Command(BaseCommand):
    help = "Record an approved, provenanced exchange rate without network access"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--base", required=True, help="Base ISO 4217 code, e.g. EUR")
        parser.add_argument("--quote", required=True, help="Quote ISO 4217 code, e.g. RON")
        parser.add_argument("--rate", required=True, help="Quote units for one base unit")
        parser.add_argument("--as-of", required=True, dest="as_of", help="Published rate date (YYYY-MM-DD)")
        parser.add_argument(
            "--source",
            required=True,
            choices=[FXRate.Source.BNR, FXRate.Source.ECB, FXRate.Source.BANK],
        )
        parser.add_argument("--reference", required=True, help="Publication URL or auditable document reference")
        parser.add_argument(
            "--recorded-by", required=True, dest="recorded_by", help="Operator identity for the audit trail"
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

        if not rate_value.is_finite() or rate_value <= 0:
            raise CommandError("Exchange rate must be finite and positive")
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

        with transaction.atomic():
            fx_rate, created = FXRate.objects.get_or_create(
                base_code=base,
                quote_code=quote,
                as_of=as_of,
                defaults={
                    "rate": rate_value,
                    "source": source,
                    "source_reference": reference,
                    "fetched_at": timezone.now(),
                },
            )
            if not created:
                if (
                    fx_rate.rate == rate_value
                    and fx_rate.source == source
                    and fx_rate.source_reference == reference
                    and fx_rate.fetched_at is not None
                ):
                    self.stdout.write(
                        self.style.SUCCESS(f"Exchange rate {base_code}/{quote_code} for {as_of} already recorded")
                    )
                    return
                raise CommandError(
                    f"{base_code}/{quote_code} for {as_of} already exists with different rate or provenance"
                )
            AuditService.log_simple_event(
                "fx_rate_recorded",
                content_object=fx_rate,
                description=f"Recorded {base_code}/{quote_code} exchange rate for {as_of}",
                new_values={
                    "rate": str(rate_value),
                    "source": source,
                    "source_reference": reference,
                },
                metadata={"recorded_by": recorded_by, "as_of": as_of.isoformat()},
                actor_type="system",
            )

        self.stdout.write(self.style.SUCCESS(f"Recorded {base_code}/{quote_code}={rate_value} for {as_of}"))
