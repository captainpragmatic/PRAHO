"""Atomic invoice-number resolution."""

from __future__ import annotations

from django.db import IntegrityError, transaction

from .invoice_models import InvoiceSequence


class InvoiceNumberingService:
    """Resolve and lock the active sequence before consuming a number."""

    @staticmethod
    @transaction.atomic
    def get_next_number(*, scope: str = "default") -> str:
        """Return the next number from the currently active scope."""
        try:
            sequence = InvoiceSequence.objects.select_for_update().get(scope=scope)
        except InvoiceSequence.DoesNotExist:
            try:
                with transaction.atomic():
                    sequence = InvoiceSequence.objects.create(
                        scope=scope,
                        prefix="SUB" if scope == "subscription" else "INV",
                    )
            except IntegrityError:
                sequence = InvoiceSequence.objects.select_for_update().get(scope=scope)
        return sequence.get_next_number()
