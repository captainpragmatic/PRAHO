"""Create the operator's home-currency row: every exchange rate quotes against it (ADR-0041)."""

from typing import Any

from django.core.management.base import BaseCommand

from apps.billing.currency_service import ensure_home_currency_row


class Command(BaseCommand):
    help = "Ensure the operator's home currency exists (idempotent, safe for every deploy)"

    def handle(self, *args: Any, **options: Any) -> None:
        currency = ensure_home_currency_row()
        self.stdout.write(self.style.SUCCESS(f"Home currency: {currency.code}"))
